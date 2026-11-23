"""Who did it? Reads the Linux auditd log and matches its records to our file events.

watchdog/inotify tells us WHAT changed.  auditd tells us WHO (user, program, PID).
"""
import os
import pwd
import re
from collections import defaultdict, deque

UNSET = 4294967295                      # auid value that means "no login user"
HEADER = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
KV = re.compile(r'(\w+)=("[^"]*"|\S*)')
HEXKEYS = {"name", "exe", "comm", "cwd", "proctitle"}   # auditd hex-encodes these when they hold odd characters
KEEP = ("pid", "ppid", "auid", "uid", "euid", "comm", "exe", "key", "syscall", "success", "tty", "ses")


def setup_commands(paths, key="fam"):
    """The auditctl commands that tell the kernel to log changes to our paths."""
    cmds = []
    for p in paths:
        if os.path.isdir(p):
            cmds.append(f"sudo auditctl -a always,exit -F dir={p} -F perm=wa -F key={key}")
        else:
            cmds.append(f"sudo auditctl -w {p} -p wa -k {key}")
    return cmds


def parse_line(line):
    """'type=SYSCALL msg=audit(1700000000.1:42): pid=1 ...' -> (type, time, event_id, {fields})"""
    m = HEADER.search(line)
    if not m:
        return None
    rtype = line.split(" ", 1)[0].removeprefix("type=")
    body = line.split("): ", 1)[1] if "): " in line else ""
    fields = {}
    for k, v in KV.findall(body):
        if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        elif k in HEXKEYS and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
            v = bytes.fromhex(v).decode("utf-8", "replace")
        fields[k] = v
    return rtype, float(m.group(1)), m.group(2), fields


def _name(uid):
    try:
        u = int(uid)
        return "unset" if u == UNSET else pwd.getpwuid(u).pw_name
    except (TypeError, ValueError, KeyError):
        return str(uid)


def who(ev):
    """auid = the user who LOGGED IN (stays the same after sudo). uid = the user the program ran as."""
    return {
        "user": _name(ev.get("auid")),
        "run_as": _name(ev.get("uid")),
        "pid": int(ev["pid"]) if str(ev.get("pid", "")).isdigit() else None,
        "exe": ev.get("exe"),
        "comm": ev.get("comm"),
    }


class AuditIndex:
    """Keeps the recent audit records, indexed by file path."""

    def __init__(self, log_file, key="fam"):
        self.log_file, self.key = log_file, key
        self.offset = None
        self.inode = None
        self.partial = {}                              # records of events that are not finished yet
        self.by_path = defaultdict(lambda: deque(maxlen=50))

    def refresh(self):
        """Read only the lines added to the log since the last call."""
        try:
            st = os.stat(self.log_file)
        except OSError:
            return
        if self.offset is None:                        # first call: start at the end, old history is not our business
            self.offset, self.inode = st.st_size, st.st_ino
        elif st.st_ino != self.inode or st.st_size < self.offset:   # log was rotated or cut
            self.offset, self.inode = 0, st.st_ino
        with open(self.log_file, "rb") as f:
            f.seek(self.offset)
            data = f.read()
        cut = data.rfind(b"\n")
        if cut < 0:
            return
        self.offset += cut + 1                         # only whole lines
        for line in data[:cut].decode("utf-8", "replace").splitlines():
            self.feed(line)

    def feed(self, line):
        p = parse_line(line)
        if not p:
            return
        rtype, ts, eid, f = p
        ev = self.partial.setdefault(eid, {"ts": ts, "paths": [], "cwd": None})
        if rtype == "SYSCALL":
            ev.update({k: f.get(k) for k in KEEP})
        elif rtype == "CWD":
            ev["cwd"] = f.get("cwd")
        elif rtype == "PATH":
            ev["paths"].append(f.get("name"))
        elif rtype == "EOE":                           # End Of Event
            self._finish(eid)
        while len(self.partial) > 2000:                # never grow forever
            self.partial.pop(next(iter(self.partial)))

    def _finish(self, eid):
        ev = self.partial.pop(eid, None)
        if not ev or (self.key and ev.get("key") != self.key):
            return
        for name in ev["paths"]:
            if not name or name == "(null)":
                continue
            full = name if name.startswith("/") else os.path.join(ev.get("cwd") or "/", name)
            self.by_path[os.path.normpath(full)].append(ev)

    def lookup(self, path, ts, window=5.0):
        """Best matching audit record for this file near this time, or None."""
        self.refresh()
        best = None
        for ev in self.by_path.get(os.path.normpath(path), ()):
            gap = abs(ev["ts"] - ts)
            if gap <= window and (best is None or gap < abs(best["ts"] - ts)):
                best = ev
        return who(best) if best else None
