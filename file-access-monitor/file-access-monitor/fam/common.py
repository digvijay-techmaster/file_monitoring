"""Small helpers shared by every module."""
import fnmatch
import os
import time
from datetime import datetime, timezone

import yaml

# Severity order. Higher number = more serious.
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now_iso(ts=None):
    """UTC time as text, e.g. 2026-11-22T13:04:05.123+00:00"""
    ts = time.time() if ts is None else ts
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def match_any(path, patterns):
    """True if the path matches any glob pattern. '*' also matches '/'."""
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def load_config(path="config.yaml"):
    """Read config.yaml and turn every path into an absolute path."""
    path = os.path.abspath(path)
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    root = os.path.dirname(path)

    def absp(p):
        return os.path.abspath(os.path.join(root, os.path.expanduser(p)))

    cfg["_config_path"] = path
    cfg["_root"] = root
    cfg["watch_paths"] = [absp(p) for p in cfg.get("watch_paths", [])]
    cfg["data_dir"] = absp(cfg.get("data_dir", "data"))
    os.makedirs(cfg["data_dir"], exist_ok=True)

    # Never watch our own data folder: we write to it all the time (infinite loop).
    cfg["ignore_patterns"] = list(cfg.get("ignore_patterns", [])) + [cfg["data_dir"] + "/*"]

    # The monitor's own code and config (so we can detect tampering with the monitor).
    if cfg.get("self_protect", True):
        cfg["_self_paths"] = [absp("main.py"), cfg["_config_path"], absp("fam")]
    else:
        cfg["_self_paths"] = []
    return cfg
