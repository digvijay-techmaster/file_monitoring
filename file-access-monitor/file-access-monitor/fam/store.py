"""Storage for events and alerts.

Uses MongoDB when it is running, and plain JSON-lines files when it is not.
Every entry carries the hash of the previous entry (a hash chain), so a deleted
or edited entry is detected by `python main.py verify-logs`.
"""
import fcntl
import hashlib
import json
import os
import threading
import time
from collections import Counter
from datetime import datetime

GENESIS = "0" * 64
SKIP = {"_id", "ts_dt", "seq", "prev_hash", "entry_hash"}   # fields that are not part of the hash


def _digest(prev, seq, doc):
    body = json.dumps({k: v for k, v in doc.items() if k not in SKIP}, sort_keys=True, default=str)
    return hashlib.sha256(f"{prev}|{seq}|{body}".encode()).hexdigest()


class Store:
    COLLECTIONS = ("events", "alerts")

    def __init__(self, cfg):
        sc = cfg.get("storage", {})
        self.dir = cfg["data_dir"]
        self.lock = threading.RLock()
        self.mode = "files"
        self.db = None
        if sc.get("use_mongo", True):
            try:
                from pymongo import MongoClient
                client = MongoClient(sc.get("mongo_uri", "mongodb://localhost:27017"), serverSelectionTimeoutMS=2000)
                client.admin.command("ping")
                db = client[sc.get("db_name", "fam")]
                days = int(sc.get("retention_days", 30))
                db.events.create_index([("path", 1), ("ts_dt", -1)])
                db.events.create_index("ts_dt", expireAfterSeconds=days * 86400)   # old events delete themselves
                db.events.create_index("seq", unique=True)
                db.alerts.create_index([("severity", 1), ("ts_dt", -1)])
                db.alerts.create_index("seq", unique=True)
                self.db, self.mode = db, "mongo"
            except Exception as e:
                print(f"[store] MongoDB not available ({e.__class__.__name__}) -> using files in {self.dir}")

    # ---------- writing ----------
    def add_event(self, doc):
        return self._add("events", doc)

    def add_alert(self, doc):
        return self._add("alerts", doc)

    def _file(self, c):
        return os.path.join(self.dir, f"{c}.jsonl")

    def _last_doc(self, c):
        if self.mode == "mongo":
            return self.db[c].find_one({}, {"_id": 0}, sort=[("seq", -1)])
        p = self._file(c)
        if not os.path.exists(p):
            return None
        size = os.path.getsize(p)
        with open(p, "rb") as f:
            f.seek(max(0, size - 65536))
            tail = f.read()
        for line in reversed(tail.splitlines()):
            try:
                d = json.loads(line)
                if "seq" in d:
                    return d
            except ValueError:
                continue
        return None

    def _seal(self, c, doc):
        last = self._last_doc(c)
        seq = last["seq"] + 1 if last else 1
        prev = last["entry_hash"] if last else GENESIS
        d = dict(doc, seq=seq, prev_hash=prev)
        d["entry_hash"] = _digest(prev, seq, d)
        return d

    def _add(self, c, doc):
        with self.lock:
            if self.mode == "mongo":
                from pymongo.errors import DuplicateKeyError
                for _ in range(5):
                    d = self._seal(c, doc)
                    try:
                        self.db[c].insert_one(dict(d, ts_dt=datetime.fromisoformat(d["ts"])))
                        return d
                    except DuplicateKeyError:      # another process wrote at the same moment: try again
                        continue
                raise RuntimeError("could not write to MongoDB")
            with open(self._file(c) + ".lock", "a") as lk:
                fcntl.flock(lk, fcntl.LOCK_EX)     # two programs (watch + check) never write together
                d = self._seal(c, doc)
                with open(self._file(c), "a") as f:
                    f.write(json.dumps(d, default=str) + "\n")
                return d

    # ---------- reading ----------
    def _iter_file(self, c):
        p = self._file(c)
        if not os.path.exists(p):
            return
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except ValueError:
                        yield {"_corrupt": line[:80]}

    def recent(self, c, limit=100):
        """Newest first."""
        if self.mode == "mongo":
            return list(self.db[c].find({}, {"_id": 0, "ts_dt": 0}).sort("seq", -1).limit(limit))
        rows = [d for d in self._iter_file(c) if "_corrupt" not in d]
        return rows[-limit:][::-1]

    def summary(self, limit=5000):
        ev, al = self.recent("events", limit), self.recent("alerts", limit)
        return {
            "storage": self.mode,
            "events": len(ev), "alerts": len(al),
            "alerts_by_severity": dict(Counter(a["severity"] for a in al)),
            "top_paths": Counter(e["path"] for e in ev).most_common(10),
            "top_users": Counter((e.get("user") or "unknown") for e in ev).most_common(10),
            "heartbeat_age_sec": self.heartbeat_age(),
        }

    # ---------- integrity ----------
    def verify(self, c):
        """Check the hash chain. Returns (ok, entries_checked, message)."""
        if self.mode == "mongo":
            docs = self.db[c].find({}, {"_id": 0}).sort("seq", 1)
        else:
            docs = self._iter_file(c)
        prev_hash = prev_seq = None
        n = 0
        for d in docs:
            n += 1
            if "_corrupt" in d:
                return False, n, "a line is damaged"
            if prev_seq is not None:
                if d["seq"] != prev_seq + 1:
                    return False, d["seq"], "entries are missing before this one"
                if d["prev_hash"] != prev_hash:
                    return False, d["seq"], "chain link is broken"
            if _digest(d["prev_hash"], d["seq"], d) != d["entry_hash"]:
                return False, d["seq"], "this entry was edited"
            prev_hash, prev_seq = d["entry_hash"], d["seq"]
        return True, n, "ok"

    # ---------- heartbeat (to notice if the monitor was switched off) ----------
    def beat(self):
        with open(os.path.join(self.dir, "heartbeat"), "w") as f:
            f.write(str(time.time()))

    def heartbeat_age(self):
        try:
            with open(os.path.join(self.dir, "heartbeat")) as f:
                return round(time.time() - float(f.read()), 1)
        except (OSError, ValueError):
            return None
