#!/usr/bin/env python3
"""File Access Monitor - command line.

  python main.py init            make the signed baseline ("known good" state)
  python main.py check           compare now vs baseline (one-time scan)
  python main.py watch           real-time monitoring (use sudo for auditd 'who did it')
  python main.py report          summary of events and alerts
  python main.py verify-logs     check that nobody edited the logs (hash chain)
  python main.py anomaly         machine-learning check for strange activity spikes
  python main.py audit-setup     print the auditctl commands for 'who did it'
  python main.py api             dashboard at http://127.0.0.1:8000
  python main.py status          is the monitor alive? (exit code 2 = heartbeat too old)
"""
import argparse
import os
import sys

from fam.alerts import AlertManager
from fam.audit import setup_commands
from fam.baseline import BaselineTampered, build_baseline, load_baseline, save_baseline
from fam.common import load_config, now_iso
from fam.rules import RuleEngine
from fam.store import Store


def get_baseline(cfg, store):
    try:
        return load_baseline(cfg["data_dir"])
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    except BaselineTampered as e:
        print(f"\n!!! CRITICAL: {e}")
        store.add_alert({"ts": now_iso(), "rule": "baseline_tampered", "severity": "critical", "mitre": "T1565.001",
                         "path": os.path.join(cfg["data_dir"], "baseline.json"), "message": str(e),
                         "action": "tamper", "user": None, "exe": None})
        sys.exit(3)


def cmd_init(cfg, store, args):
    for p in cfg["watch_paths"]:
        if not os.path.exists(p):
            print(f"warning: {p} does not exist (run: python demo.py prepare)")
    files = build_baseline(cfg["watch_paths"] + cfg["_self_paths"], cfg["ignore_patterns"], cfg.get("max_hash_mb", 200))
    path = save_baseline(files, cfg["data_dir"])
    print(f"Baseline saved: {len(files)} files -> {path}")
    unreadable = [p for p, i in files.items() if i["sha256"] is None and "cannot read" in i.get("note", "")]
    if unreadable:
        print(f"{len(unreadable)} file(s) could not be read (try sudo), e.g. {unreadable[0]}")


def cmd_check(cfg, store, args):
    from fam.monitor import run_scan
    base = get_baseline(cfg, store)
    diffs, new = run_scan(cfg, store, AlertManager(cfg), RuleEngine(cfg), base, set())
    if not diffs:
        print("OK: every file matches the baseline.")
        return 0
    print(f"{len(diffs)} difference(s):")
    for d in diffs:
        print(f"  {d['change'].upper():<9} {d['path']}")
    return 1


def cmd_watch(cfg, store, args):
    from fam.monitor import Monitor
    base = get_baseline(cfg, store)
    return Monitor(cfg, store, base).run()


def cmd_report(cfg, store, args):
    s = store.summary()
    print(f"Storage: {s['storage']}   Events: {s['events']}   Alerts: {s['alerts']}")
    print("Alerts by severity:", s["alerts_by_severity"] or "none")
    print("\nMost changed files:")
    for p, n in s["top_paths"]:
        print(f"  {n:>5}  {p}")
    print("\nMost active users:")
    for u, n in s["top_users"]:
        print(f"  {n:>5}  {u}")
    print("\nLatest alerts:")
    for a in store.recent("alerts", 10):
        who = f" by {a['user']}" if a.get("user") else ""
        print(f"  {a['ts'][:19]}  {a['severity']:<8} {a['rule']:<22} {a['path']}{who}  {a.get('mitre') or ''}")


def cmd_verify(cfg, store, args):
    bad = False
    for c in ("events", "alerts"):
        ok, n, msg = store.verify(c)
        print(f"{c:<7} {'OK' if ok else 'BROKEN'}: {n} entries checked - {msg}" + ("" if ok else f" (entry #{n})"))
        bad = bad or not ok
    return 2 if bad else 0


def cmd_anomaly(cfg, store, args):
    from fam.anomaly import analyze
    table, msg = analyze(store)
    if table is None or "anomaly" not in table:
        print(msg)
        return 0
    odd = table[table["anomaly"]]
    print(f"{len(table)} minutes analysed, {len(odd)} strange.")
    if len(odd):
        print(odd[["events", "files", "deletes", "score"]].to_string())
    return 0


def cmd_audit_setup(cfg, store, args):
    key = cfg.get("audit", {}).get("key", "fam")
    print("Run these once to make Linux auditd log changes to your paths:\n")
    for c in setup_commands(cfg["watch_paths"] + cfg["_self_paths"], key):
        print("  " + c)
    print(f"\nCheck it works:  sudo ausearch -k {key} | tail")


def cmd_api(cfg, store, args):
    import uvicorn
    from fam.api import create_app
    print("Dashboard: http://127.0.0.1:8000   (only this computer can open it)")
    uvicorn.run(create_app(store), host="127.0.0.1", port=8000, log_level="warning")


def cmd_status(cfg, store, args):
    age = store.heartbeat_age()
    if age is None:
        print("Monitor has never run.")
        return 2
    print(f"Last heartbeat {age}s ago.")
    if age > 120:
        print("ALERT: the monitor looks dead or was switched off!")
        return 2
    return 0


COMMANDS = {"init": cmd_init, "check": cmd_check, "watch": cmd_watch, "report": cmd_report,
            "verify-logs": cmd_verify, "anomaly": cmd_anomaly, "audit-setup": cmd_audit_setup,
            "api": cmd_api, "status": cmd_status}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="File Access Monitor")
    ap.add_argument("-c", "--config", default=os.path.join(here, "config.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in COMMANDS:
        sub.add_parser(name)
    args = ap.parse_args()
    cfg = load_config(args.config)
    store = Store(cfg)
    sys.exit(COMMANDS[args.cmd](cfg, store, args) or 0)


if __name__ == "__main__":
    main()
