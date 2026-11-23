import json
import os
import time

import pytest

from fam.audit import AuditIndex, parse_line, setup_commands
from fam.baseline import BaselineTampered, build_baseline, compare, load_baseline, save_baseline, sha256_file
from fam.rules import RuleEngine
from fam.store import Store

RULES = {
    "rules": {
        "critical_files": {"severity": "high", "items": [{"pattern": "*/passwd", "mitre": "T1136.001"}]},
        "log_patterns": ["*.log"],
        "mass_change": {"threshold": 5, "window_sec": 10, "cooldown_sec": 60},
    },
    "_self_paths": ["/opt/fam/config.yaml"],
}


def ev(path, action="modified", **kw):
    base = {"ts": "2026-11-22T10:00:00.000+00:00", "ts_epoch": time.time(), "path": path, "action": action,
            "old_hash": None, "new_hash": "x", "old_mode": 0o644, "mode": 0o644, "mode_oct": "0644",
            "old_size": 10, "size": 10, "in_baseline": True}
    base.update(kw)
    return base


# ---------- baseline ----------
def test_baseline_detects_changes(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.txt").write_text("world")
    base = build_baseline([str(tmp_path)])
    assert len(base) == 2
    (tmp_path / "a.txt").write_text("HELLO")          # content change
    os.chmod(tmp_path / "b.txt", 0o777)               # permission change
    (tmp_path / "c.txt").write_text("new")            # new file
    now = build_baseline([str(tmp_path)])
    kinds = {os.path.basename(d["path"]): d["change"] for d in compare(base, now)}
    assert kinds == {"a.txt": "modified", "b.txt": "attrib", "c.txt": "added"}
    os.remove(tmp_path / "a.txt")
    kinds = {os.path.basename(d["path"]): d["change"] for d in compare(base, build_baseline([str(tmp_path)]))}
    assert kinds["a.txt"] == "removed"


def test_sha256_matches_known_value(tmp_path):
    p = tmp_path / "f"
    p.write_text("abc")
    assert sha256_file(str(p)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_baseline_signature_detects_edit(tmp_path):
    data = str(tmp_path / "data")
    os.makedirs(data)
    save_baseline({"/x": {"sha256": "aa"}}, data)
    assert load_baseline(data) == {"/x": {"sha256": "aa"}}
    path = os.path.join(data, "baseline.json")
    doc = json.load(open(path))
    doc["files"]["/x"]["sha256"] = "bb"                # attacker edits the baseline
    json.dump(doc, open(path, "w"))
    with pytest.raises(BaselineTampered):
        load_baseline(data)


# ---------- store / hash chain ----------
def make_store(tmp_path):
    return Store({"data_dir": str(tmp_path), "storage": {"use_mongo": False}})


def test_chain_ok_and_detects_edit_and_delete(tmp_path):
    s = make_store(tmp_path)
    for i in range(5):
        s.add_event({"ts": "2026-11-22T10:00:00.000+00:00", "path": f"/f{i}", "action": "modified"})
    assert s.verify("events")[0] is True
    p = tmp_path / "events.jsonl"
    lines = p.read_text().splitlines()

    edited = json.loads(lines[2])
    edited["path"] = "/evil"
    bad = lines[:2] + [json.dumps(edited)] + lines[3:]
    p.write_text("\n".join(bad) + "\n")
    ok, seq, msg = s.verify("events")
    assert not ok and seq == 3 and "edited" in msg

    p.write_text("\n".join(lines[:2] + lines[3:]) + "\n")      # delete the 3rd entry
    ok, seq, msg = s.verify("events")
    assert not ok and "missing" in msg


def test_two_writers_keep_one_chain(tmp_path):
    a, b = make_store(tmp_path), make_store(tmp_path)   # like `watch` and `check` running together
    for i in range(10):
        (a if i % 2 else b).add_alert({"ts": "2026-11-22T10:00:00.000+00:00", "rule": "r", "path": str(i)})
    assert a.verify("alerts") == (True, 10, "ok")


# ---------- rules ----------
def names(alerts):
    return {a["rule"] for a in alerts}


def test_critical_file_and_baseline_mismatch():
    r = RuleEngine(RULES)
    out = r.evaluate(ev("/etc/passwd", old_hash="a", new_hash="b"))
    assert {"critical_file_change", "baseline_mismatch"} <= names(out)
    assert next(a for a in out if a["rule"] == "critical_file_change")["mitre"] == "T1136.001"


def test_permissions_rules():
    r = RuleEngine(RULES)
    assert "world_writable" in names(r.evaluate(ev("/x/tool.sh", "attrib", mode=0o777, mode_oct="0777")))
    assert "suid_sgid_set" in names(r.evaluate(ev("/x/tool.sh", "attrib", mode=0o4755, mode_oct="4755")))
    assert not names(r.evaluate(ev("/x/ok.txt", "attrib", mode=0o600, mode_oct="0600")))


def test_log_rules():
    r = RuleEngine(RULES)
    assert "log_deleted" in names(r.evaluate(ev("/x/app.log", "deleted")))
    assert "log_truncated" in names(r.evaluate(ev("/x/app.log", "modified", old_size=100, size=0)))


def test_mass_change_fires_once():
    r = RuleEngine(RULES)
    hits = [a for i in range(20) for a in r.evaluate(ev(f"/docs/f{i}", "created", in_baseline=False))
            if a["rule"] == "mass_change"]
    assert len(hits) == 1 and hits[0]["severity"] == "critical"


def test_monitor_tampering():
    r = RuleEngine(RULES)
    assert "monitor_tampering" in names(r.evaluate(ev("/opt/fam/config.yaml")))


# ---------- auditd parser ----------
AUDIT = """\
type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=257 success=yes exit=3 items=2 ppid=900 pid=2000 auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=3 comm="vim" exe="/usr/bin/vim" key="fam"
type=CWD msg=audit(1700000000.123:456): cwd="/home/ravi"
type=PATH msg=audit(1700000000.123:456): item=0 name="/etc/" inode=1 nametype=PARENT
type=PATH msg=audit(1700000000.123:456): item=1 name="passwd" inode=2 nametype=NORMAL
type=EOE msg=audit(1700000000.123:456):
type=SYSCALL msg=audit(1700000001.000:457): arch=c000003e syscall=87 success=yes pid=2100 auid=4294967295 uid=0 comm="rm" exe="/usr/bin/rm" key="other"
type=PATH msg=audit(1700000001.000:457): item=0 name="/etc/hosts" nametype=DELETE
type=EOE msg=audit(1700000001.000:457):
"""


def test_parse_line():
    rtype, ts, eid, f = parse_line(AUDIT.splitlines()[0])
    assert (rtype, eid, f["pid"], f["exe"], f["key"]) == ("SYSCALL", "456", "2000", "/usr/bin/vim", "fam")
    assert parse_line("garbage") is None
    # hex-encoded file name (auditd does this for names with spaces)
    _, _, _, f = parse_line('type=PATH msg=audit(1.0:9): item=0 name=2F746D702F612062 nametype=NORMAL')
    assert f["name"] == "/tmp/a b"


def test_audit_index_lookup(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")
    idx = AuditIndex(str(log), "fam")
    idx.refresh()                                   # starts at the end of the file
    log.write_text(AUDIT)                           # new lines appear in the log
    # 'passwd' is a relative name, so it is joined with the process's cwd (/home/ravi)
    w = idx.lookup("/home/ravi/passwd", 1700000000.5)
    assert w and w["exe"] == "/usr/bin/vim" and w["pid"] == 2000 and w["user"] != ""
    assert idx.lookup("/home/ravi/passwd", 1700000100.0) is None   # too far away in time
    assert idx.lookup("/etc/hosts", 1700000001.0) is None          # other audit key -> ignored


def test_setup_commands(tmp_path):
    cmds = setup_commands([str(tmp_path), "/etc/passwd"], "fam")
    assert "-F dir=" in cmds[0] and cmds[1] == "sudo auditctl -w /etc/passwd -p wa -k fam"
