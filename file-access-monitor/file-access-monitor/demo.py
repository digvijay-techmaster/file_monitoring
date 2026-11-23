#!/usr/bin/env python3
"""Safe demo. Everything happens INSIDE the watched folder (default ./watched). Nothing real is touched.

  python demo.py prepare          create fake sensitive files (passwd, sudoers, ssh key, logs, documents)
  python demo.py attack           simulate an attacker, step by step
  python demo.py attack --tamper-self    also touch the monitor's own config file (comment line, harmless)
"""
import argparse
import os
import random
import time

from fam.common import load_config


def prepare(root):
    files = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nravi:x:1000:1000::/home/ravi:/bin/bash\n",
        "etc/shadow": "root:*:19000:0:99999:7:::\nravi:*:19000:0:99999:7:::\n",
        "etc/sudoers": "root ALL=(ALL:ALL) ALL\n",
        "home/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample ravi@laptop\n",
        "bin/tool.sh": "#!/bin/sh\necho hello\n",
        "var/log/app.log": "".join(f"2026-11-22 10:00:{i:02d} INFO app started step {i}\n" for i in range(30)),
    }
    for i in range(20):
        files[f"docs/doc_{i:02d}.txt"] = f"Important document number {i}\n" * 20
    for rel, text in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
    os.chmod(os.path.join(root, "etc/shadow"), 0o600)
    print(f"Created {len(files)} files in {root}\nNext: python main.py init")


def attack(root, cfg, tamper_self):
    def step(msg):
        print(f"\n>>> {msg}", flush=True)

    def pause():
        time.sleep(1.5)       # let the monitor finish one step before the next starts

    step("1. Attacker adds a backdoor user to passwd")
    with open(os.path.join(root, "etc/passwd"), "a") as f:
        f.write("hacker:x:0:0::/root:/bin/bash\n")
    pause()

    step("2. Attacker adds his own SSH key")
    with open(os.path.join(root, "home/.ssh/authorized_keys"), "a") as f:
        f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIattacker evil@remote\n")
    pause()

    step("3. Attacker makes a script world-writable and sets the SUID bit")
    os.chmod(os.path.join(root, "bin/tool.sh"), 0o777)
    pause()
    os.chmod(os.path.join(root, "docs/doc_00.txt"), 0o4755)
    pause()

    step("4. Attacker cleans the logs (truncate), then deletes them")
    with open(os.path.join(root, "var/log/app.log"), "w") as f:
        f.write("")
    pause()
    os.remove(os.path.join(root, "var/log/app.log"))
    pause()

    step("5. Fake ransomware: rewrite every document and create 300 '.locked' files very fast")
    for i in range(20):
        with open(os.path.join(root, f"docs/doc_{i:02d}.txt"), "wb") as f:
            f.write(random.randbytes(200))        # pretend this is encrypted data
    os.makedirs(os.path.join(root, "locked"), exist_ok=True)
    for i in range(300):
        with open(os.path.join(root, f"locked/file_{i:03d}.locked"), "wb") as f:
            f.write(random.randbytes(64))
    pause()

    if tamper_self:
        step("6. Attacker edits the monitor's own config to switch rules off")
        with open(cfg["_config_path"], "a") as f:
            f.write("\n# edited by demo attack\n")
        pause()

    print("\nDone. Look at the monitor window, then run:  python main.py report")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["prepare", "attack"])
    ap.add_argument("--tamper-self", action="store_true")
    ap.add_argument("-c", "--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"))
    a = ap.parse_args()
    cfg = load_config(a.config)
    root = cfg["watch_paths"][0]
    if a.what == "prepare":
        prepare(root)
    else:
        attack(root, cfg, a.tamper_self)
