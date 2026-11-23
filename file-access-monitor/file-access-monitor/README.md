# File Access Monitor (FAM)

Watches files on Linux and answers two questions:

- **What changed?** (integrity monitoring: hashes, permissions, deletes, renames)
- **Who did it?** (access monitoring: user, program, PID, from Linux `auditd`)

## How it works

```
watchdog (inotify) -> queue -> debounce -> hash + who (auditd) -> rules -> store -> alerts
                                                                          |         |
periodic full scan (source of truth) ------------------------------------+         +-> console / Telegram / e-mail
                                                                          v
                                                          MongoDB (or files) -> dashboard + anomaly check
```

| Piece | File | What it does |
|---|---|---|
| Baseline | `fam/baseline.py` | SHA-256 + permissions of every file, signed with HMAC |
| Watcher + pipeline | `fam/monitor.py` | Real-time events, debounce, periodic scan, heartbeat |
| Who did it | `fam/audit.py` | Reads `/var/log/audit/audit.log`, matches records to file events |
| Rules | `fam/rules.py` | 7 rules, each mapped to a MITRE ATT&CK technique |
| Storage | `fam/store.py` | MongoDB (TTL + indexes) or JSON files; hash-chained logs |
| Alerts | `fam/alerts.py` | Console, Telegram, e-mail, cooldown against spam |
| Dashboard | `fam/api.py` | FastAPI + one HTML page |
| Anomaly check | `fam/anomaly.py` | pandas + Isolation Forest on events per minute |
| CLI | `main.py` | `init`, `check`, `watch`, `report`, `verify-logs`, `anomaly`, `audit-setup`, `api`, `status` |
| Safe demo | `demo.py` | Fake sensitive files + a simulated attack (stays inside `./watched`) |

## Quick start (10 minutes)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python demo.py prepare        # fake passwd, sudoers, ssh key, logs, documents in ./watched
python main.py init           # make the signed baseline
python main.py watch          # terminal 1: real-time monitoring

python demo.py attack         # terminal 2: simulated attacker
python main.py report         # summary
python main.py verify-logs    # proves nobody edited the logs
python main.py api            # dashboard: http://127.0.0.1:8000
```

The demo attack does 5 things; FAM should alert on each:
1. adds a user to `passwd` -> `critical_file_change` (T1136.001)
2. adds an SSH key -> `critical_file_change` (T1098.004)
3. `chmod 777` and SUID -> `world_writable`, `suid_sgid_set`
4. truncates and deletes a log -> `log_truncated`, `log_deleted`
5. rewrites 20 documents and creates 300 files in a second -> `mass_change` (T1486)

`python demo.py attack --tamper-self` also edits `config.yaml` -> `monitor_tampering`.

## Turn on "who did it" (auditd)

Without auditd the `user` column shows `unknown`. Everything else works.

```bash
sudo apt install auditd
python main.py audit-setup          # prints the auditctl commands, run them
sudo ausearch -k fam | tail         # after editing a watched file, you should see records
sudo venv/bin/python main.py watch  # root is needed to read the audit log
```

`user` is the login user (auid, stays the same after `sudo`). `run_as` is the user the program ran as.
To keep the rules after reboot, put the same lines in `/etc/audit/rules.d/fam.rules`
(without the word `sudo auditctl`, e.g. `-a always,exit -F dir=/etc -F perm=wa -F key=fam`).

## Use it on real files

Edit `watch_paths` in `config.yaml`, for example:

```yaml
watch_paths: [/etc/passwd, /etc/sudoers, /etc/ssh, /home/you/.ssh]
```

Run `sudo venv/bin/python main.py init` and `sudo venv/bin/python main.py watch`.
After a change you approve, run `init` again to accept the new state as "known good".
While you are editing FAM's own code, set `self_protect: false` (otherwise every edit raises `monitor_tampering`).
Run as a service: edit paths in `fam.service`, copy it to `/etc/systemd/system/`, then `sudo systemctl enable --now fam`.
Add a cron job running `python main.py status` to notice a dead monitor (exit code 2).

## MongoDB

`sudo apt install mongodb` or run the official Docker image. If MongoDB is not running, FAM
uses `data/events.jsonl` and `data/alerts.jsonl` automatically and tells you at start-up.
Collections: `events`, `alerts`. Indexes: `path + time`, `severity + time`, unique `seq`, TTL on old events.
The baseline is a signed file (`data/baseline.json`), because it needs the HMAC signature.

## How the monitor protects itself

- The baseline is signed (HMAC-SHA256). An edited baseline stops the monitor with a critical alert.
- Logs are hash-chained: each entry holds the hash of the one before. `verify-logs` finds edited or deleted entries.
- FAM watches its own code and config (`monitor_tampering`).
- `status` + a heartbeat file reveal a monitor that was switched off.
- The dashboard only uses `textContent`, so a file named `<script>...` cannot attack you.

Known limits (good things to write about in your report):
- Deleting the **last** log lines cannot be found by the chain alone. Ship logs to another machine (syslog) for that.
- An attacker with root can stop FAM or read the HMAC key. Run FAM as a root-owned service and forward alerts off the machine.
- Hash scans of very large files are slow (`max_hash_mb` skips huge files).
- `watchdog` can lose events if the kernel queue overflows. That is why the periodic scan exists.

## Tests

```bash
python -m pytest -q
```

Covers baseline compare, HMAC tamper detection, hash chain (edit, delete, two writers), all rules, and the auditd parser.

## Ideas to extend

`fanotify` (gives the PID directly, no auditd), eBPF with `bcc`, per-user baselines of normal behaviour,
a Grafana board on MongoDB, Docker image, Sigma-style rule files.
