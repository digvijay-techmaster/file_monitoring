"""Detection rules. Each rule looks at one event and may produce an alert.

Every alert carries a MITRE ATT&CK technique id, so you can say which attack it maps to.
"""
import os
import stat
from collections import deque
from datetime import datetime

from .common import match_any


class RuleEngine:
    def __init__(self, cfg):
        r = cfg.get("rules", {})
        crit = r.get("critical_files", {})
        self.crit_sev = crit.get("severity", "high")
        self.crit_items = crit.get("items", [])
        self.log_patterns = r.get("log_patterns", ["*.log"])
        mc = r.get("mass_change", {})
        self.mc_n = mc.get("threshold", 50)
        self.mc_window = mc.get("window_sec", 10)
        self.mc_cool = mc.get("cooldown_sec", 60)
        self.odd = r.get("odd_hours", {})
        self.self_paths = cfg.get("_self_paths", [])
        self.window = deque()          # (time, path) of recent events, for the mass-change rule
        self.last_mass = 0.0

    # ---------- helpers ----------
    def critical_item(self, path):
        for item in self.crit_items:
            if match_any(path, [item["pattern"]]):
                return item
        return None

    def is_self(self, path):
        return any(path == s or path.startswith(s + os.sep) for s in self.self_paths)

    # ---------- the rules ----------
    def evaluate(self, ev):
        out = []
        p, act = ev["path"], ev["action"]

        def add(rule, sev, mitre, msg):
            out.append({
                "ts": ev["ts"], "rule": rule, "severity": sev, "mitre": mitre,
                "path": p, "message": msg, "action": act,
                "user": ev.get("user"), "exe": ev.get("exe"),
            })

        # 1. Someone touched the monitor itself
        if self.is_self(p):
            add("monitor_tampering", "critical", "T1562.001", f"Monitor file {act}: {p}")

        # 2. A critical file changed (passwd, shadow, sudoers, ssh keys, cron ...)
        item = self.critical_item(p)
        if item:
            add("critical_file_change", self.crit_sev, item.get("mitre"), f"Critical file {act}: {p}")

        # 3. Content differs from the baseline, or a baseline file disappeared
        if act == "modified" and ev.get("old_hash") and ev.get("new_hash") != ev["old_hash"]:
            add("baseline_mismatch", "medium", "T1565.001", f"File content differs from baseline: {p}")
        if act in ("deleted", "moved_from") and ev.get("in_baseline"):
            add("baseline_file_removed", "medium", "T1070.004", f"Baseline file {act}: {p}")

        # 4. Dangerous permissions
        mode, old = ev.get("mode"), ev.get("old_mode") or 0
        if mode is not None and act in ("created", "modified", "attrib", "moved_to"):
            if mode & (stat.S_ISUID | stat.S_ISGID) and not old & (stat.S_ISUID | stat.S_ISGID):
                add("suid_sgid_set", "high", "T1548.001", f"SUID/SGID bit set ({ev.get('mode_oct')}): {p}")
            elif mode & stat.S_IWOTH and not old & stat.S_IWOTH:
                add("world_writable", "medium", "T1222.002", f"File became world-writable ({ev.get('mode_oct')}): {p}")

        # 5. Log files deleted or cut shorter
        if match_any(p, self.log_patterns):
            if act in ("deleted", "moved_from"):
                add("log_deleted", "high", "T1070.002", f"Log file {act}: {p}")
            elif act == "modified" and ev.get("old_size") is not None and ev.get("size") is not None \
                    and ev["size"] < ev["old_size"]:
                add("log_truncated", "high", "T1070.002", f"Log file got smaller ({ev['old_size']} -> {ev['size']} bytes): {p}")

        # 6. Many files change very fast (ransomware behaviour)
        now = ev["ts_epoch"]
        self.window.append((now, p))
        while self.window and now - self.window[0][0] > self.mc_window:
            self.window.popleft()
        distinct = len({x[1] for x in self.window})
        if distinct >= self.mc_n and now - self.last_mass > self.mc_cool:
            self.last_mass = now
            add("mass_change", "critical", "T1486", f"{distinct} files changed within {self.mc_window}s - possible ransomware")

        # 7. Activity at night
        if self.odd.get("enabled"):
            h = datetime.fromtimestamp(now).hour
            s, e = self.odd.get("start", 22), self.odd.get("end", 5)
            night = (h >= s or h < e) if s > e else (s <= h < e)
            if night:
                add("odd_hours", "low", "T1078", f"Change outside normal hours ({h:02d}:00): {p}")
        return out
