"""Real-time part: watchdog -> queue -> debounce -> enrich (hash, who) -> rules -> store -> alerts.

Also runs a periodic full scan (the 'source of truth') and a heartbeat.
"""
import os
import queue
import threading
import time
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .alerts import AlertManager
from .audit import AuditIndex
from .baseline import build_baseline, compare, file_info
from .common import SEV, match_any, now_iso
from .rules import RuleEngine


class Collector(FileSystemEventHandler):
    """Receives raw kernel events from watchdog and puts them in a queue. Does nothing else (stay fast)."""

    def __init__(self, q, ignore, only=None):
        self.q, self.ignore, self.only = q, ignore, only

    def _put(self, path, kind, other=None):
        if self.only is not None and path not in self.only:    # watching a single file: ignore its neighbours
            return
        if match_any(path, self.ignore):
            return
        self.q.put((path, kind, {"other": other} if other else {}))

    def on_any_event(self, event):
        if event.is_directory:
            return
        t, src = event.event_type, os.fsdecode(event.src_path)
        if t == "moved":
            dest = os.fsdecode(event.dest_path)
            self._put(src, "moved_from", dest)
            self._put(dest, "moved_to", src)
        elif t in ("created", "modified", "deleted"):
            self._put(src, t)


class Pipeline(threading.Thread):
    """One save in an editor makes many kernel events. We wait until a file is quiet (debounce),
    then look at it once, hash it, find out who did it, and run the rules."""

    def __init__(self, cfg, q, store, rules, alerts, baseline, audit_idx, seen):
        super().__init__(daemon=True)
        self.q, self.store, self.rules, self.alerts = q, store, rules, alerts
        self.baseline, self.audit, self.seen = baseline, audit_idx, seen
        self.debounce = cfg.get("debounce_sec", 0.7)
        self.max_hash_mb = cfg.get("max_hash_mb", 200)
        self.pending = {}          # path -> what we saw
        self.session = {}          # path -> last state we reported (to ignore repeats)
        self.stop_flag = threading.Event()

    def run(self):
        while not self.stop_flag.is_set():
            try:
                path, kind, extra = self.q.get(timeout=0.2)
                now = time.time()
                p = self.pending.setdefault(path, {"first": now, "last": now, "kinds": set(), "extra": {}})
                p["last"] = now
                p["kinds"].add(kind)
                p["extra"].update(extra)
            except queue.Empty:
                pass
            self.flush()

    def stop(self):
        self.stop_flag.set()
        self.join(3)
        self.flush(force=True)

    def flush(self, force=False):
        now = time.time()
        due = [p for p, v in self.pending.items() if force or now - v["last"] >= self.debounce]
        for path in due:
            v = self.pending.pop(path)
            try:
                ev = self.build_event(path, v)
                if ev:
                    self.handle(ev)
            except Exception as e:                      # one bad file must never stop the monitor
                print(f"[pipeline] error on {path}: {e!r}")

    def build_event(self, path, v):
        kinds = v["kinds"]
        base = self.baseline.get(path)
        info = file_info(path, self.max_hash_mb)
        last = self.session[path] if path in self.session else base    # what we knew before this event

        if info is None:                                # file is gone
            if last is None:
                return None                             # a temp file that came and went
            action = "moved_from" if "moved_from" in kinds else "deleted"
        elif last is None:
            action = "moved_to" if "moved_to" in kinds else "created"
        elif info["sha256"] == last["sha256"]:
            if (info["mode"], info["uid"], info["gid"]) == (last["mode"], last["uid"], last["gid"]):
                return None                             # nothing really changed (e.g. only 'touch')
            action = "attrib"                           # permissions or owner changed
        else:
            action = "modified"

        ref = base or last                              # what to compare against in the report
        self.session[path] = info
        ts = v["first"]
        ev = {
            "ts": now_iso(ts), "ts_epoch": round(ts, 3), "path": path, "action": action,
            "in_baseline": base is not None,
            "old_hash": ref["sha256"] if ref else None, "new_hash": info["sha256"] if info else None,
            "old_mode": ref["mode"] if ref else None, "mode": info["mode"] if info else None,
            "mode_oct": info["mode_oct"] if info else None,
            "old_size": ref["size"] if ref else None, "size": info["size"] if info else None,
            "owner": (info or ref or {}).get("owner"),
            "inode": info["inode"] if info else None,
        }
        if v["extra"].get("other"):
            ev["other_path"] = v["extra"]["other"]

        who = self.audit.lookup(path, ts) if self.audit else None
        ev.update(who or {"user": None, "exe": None})
        ev["who_source"] = "auditd" if who else "none"
        return ev

    def handle(self, ev):
        alerts = self.rules.evaluate(ev)
        ev["severity"] = max((a["severity"] for a in alerts), key=SEV.get, default="info")
        ev["rules"] = [a["rule"] for a in alerts]
        self.store.add_event(ev)
        for a in alerts:
            self.store.add_alert(a)
            self.alerts.notify(a)
        self.seen.add((ev["path"], ev["new_hash"]))     # so the periodic scan does not report it again
        self.show(ev)

    @staticmethod
    def show(ev):
        t = datetime.fromtimestamp(ev["ts_epoch"]).strftime("%H:%M:%S")
        who = f"  by {ev['user']} ({ev['exe']})" if ev.get("user") else ""
        sev = f"  [{ev['severity']}]" if ev["severity"] != "info" else ""
        print(f"{t} {ev['action'].upper():<10} {ev['path']}{who}{sev}", flush=True)


def run_scan(cfg, store, alerts, rules, baseline, seen):
    """Hash everything again and compare with the baseline. Slow but cannot be fooled."""
    current = build_baseline(cfg["watch_paths"] + cfg["_self_paths"], cfg["ignore_patterns"], cfg.get("max_hash_mb", 200))
    diffs = compare(baseline, current)
    new_alerts = []
    for d in diffs:
        new_hash = d["new"]["sha256"] if d["new"] else None
        if (d["path"], new_hash) in seen:               # the real-time watcher already reported this exact state
            continue
        seen.add((d["path"], new_hash))
        item = rules.critical_item(d["path"])
        if rules.is_self(d["path"]):
            sev, mitre = "critical", "T1562.001"
        elif item:
            sev, mitre = "high", item.get("mitre")
        else:
            sev, mitre = ("low" if d["change"] == "added" else "medium"), None
        a = {"ts": now_iso(), "rule": "scan_" + d["change"], "severity": sev, "mitre": mitre,
             "path": d["path"], "message": f"Baseline scan: file {d['change']}: {d['path']}",
             "action": d["change"], "user": None, "exe": None}
        store.add_alert(a)
        alerts.notify(a)
        new_alerts.append(a)
    return diffs, new_alerts


class Monitor:
    def __init__(self, cfg, store, baseline):
        self.cfg, self.store, self.baseline = cfg, store, baseline
        self.alerts = AlertManager(cfg)
        self.rules = RuleEngine(cfg)
        self.seen = set()
        self.stop = threading.Event()

    def _audit_index(self):
        a = self.cfg.get("audit", {})
        if not a.get("enabled", True):
            return None
        log = a.get("log_file", "/var/log/audit/audit.log")
        if os.access(log, os.R_OK):
            idx = AuditIndex(log, a.get("key", "fam"))
            idx.refresh()
            return idx
        print(f"[audit] cannot read {log} -> 'who did it' is OFF. Install auditd and run with sudo (see README).")
        return None

    def _scan_loop(self):
        interval = self.cfg.get("scan_interval_sec", 600)
        while not self.stop.is_set():
            try:
                diffs, new = run_scan(self.cfg, self.store, self.alerts, self.rules, self.baseline, self.seen)
                if new:
                    print(f"[scan] {len(new)} difference(s) from the baseline")
            except Exception as e:
                print(f"[scan] error: {e!r}")
            self.stop.wait(interval)

    def _heartbeat_loop(self):
        while not self.stop.is_set():
            self.store.beat()
            self.stop.wait(30)

    def run(self):
        cfg = self.cfg
        q = queue.Queue()
        observer = Observer()
        dirs, files = [], {}
        for p in cfg["watch_paths"] + cfg["_self_paths"]:
            if os.path.isdir(p):
                dirs.append(p)
            elif os.path.exists(p):
                files.setdefault(os.path.dirname(p), set()).add(p)
            else:
                print(f"[watch] skipping {p}: it does not exist")
        if not (dirs or files):
            print("Nothing to watch. Check watch_paths in config.yaml")
            return 1
        for d in dirs:
            observer.schedule(Collector(q, cfg["ignore_patterns"]), d, recursive=True)
        for parent, only in files.items():
            observer.schedule(Collector(q, cfg["ignore_patterns"], only), parent, recursive=False)

        audit_idx = self._audit_index()
        pipe = Pipeline(cfg, q, self.store, self.rules, self.alerts, self.baseline, audit_idx, self.seen)
        try:
            observer.start()
        except OSError as e:
            print(f"Could not start watching: {e}")
            print("If this says 'watch limit reached':  sudo sysctl fs.inotify.max_user_watches=524288")
            return 1
        pipe.start()
        threading.Thread(target=self._scan_loop, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        print(f"Watching {len(dirs)} folder(s) and {sum(len(s) for s in files.values())} file(s) | "
              f"storage: {self.store.mode} | who-did-it (auditd): {'ON' if audit_idx else 'OFF'}")
        print("Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            self.stop.set()
            observer.stop()
            observer.join()
            pipe.stop()
        return 0
