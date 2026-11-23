"""Baseline = the 'known good' fingerprint of every file. Signed with HMAC so it cannot be edited quietly."""
import hashlib
import hmac
import json
import os
import pwd
import stat

from .common import match_any, now_iso


class BaselineTampered(Exception):
    pass


def sha256_file(path, chunk=1024 * 1024):
    """Hash a file in 1 MB pieces, so big files do not fill the memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def _owner(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def file_info(path, max_hash_mb=200):
    """Everything we remember about one file. Returns None if the file does not exist."""
    try:
        st = os.lstat(path)           # lstat: do not follow symlinks
    except OSError:
        return None
    perm = stat.S_IMODE(st.st_mode)
    info = {
        "path": path, "size": st.st_size,
        "mode": perm, "mode_oct": format(perm, "04o"),
        "uid": st.st_uid, "gid": st.st_gid, "owner": _owner(st.st_uid),
        "mtime": st.st_mtime, "ctime": st.st_ctime, "inode": st.st_ino,
        "sha256": None,
    }
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = ""
        info["note"] = "symlink -> " + target
        info["sha256"] = hashlib.sha256(target.encode()).hexdigest()   # a changed target = a change
    elif stat.S_ISREG(st.st_mode):
        if st.st_size > max_hash_mb * 1024 * 1024:
            info["note"] = "too large to hash"
        else:
            try:
                info["sha256"] = sha256_file(path)
            except OSError as e:
                info["note"] = f"cannot read: {e.strerror}"
    else:
        info["note"] = "not a regular file"
    return info


def iter_files(paths, ignore=()):
    """Yield every file under the given folders/files, skipping ignored ones."""
    for root in paths:
        if os.path.isfile(root) or os.path.islink(root):
            if not match_any(root, ignore):
                yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # prune ignored folders (the trailing '/' lets patterns like '*/.git/*' match)
            dirnames[:] = [d for d in dirnames if not match_any(os.path.join(dirpath, d) + "/", ignore)]
            for name in filenames:
                p = os.path.join(dirpath, name)
                if not match_any(p, ignore):
                    yield p


def build_baseline(paths, ignore=(), max_hash_mb=200):
    files = {}
    for p in iter_files(paths, ignore):
        info = file_info(p, max_hash_mb)
        if info:
            files[p] = info
    return files


def compare(base, current):
    """Return the differences between the baseline and the current state."""
    diffs = []
    for p, old in base.items():
        new = current.get(p)
        if new is None:
            diffs.append({"path": p, "change": "removed", "old": old, "new": None})
        elif new["sha256"] != old["sha256"]:
            diffs.append({"path": p, "change": "modified", "old": old, "new": new})
        elif (new["mode"], new["uid"], new["gid"]) != (old["mode"], old["uid"], old["gid"]):
            diffs.append({"path": p, "change": "attrib", "old": old, "new": new})
    for p, new in current.items():
        if p not in base:
            diffs.append({"path": p, "change": "added", "old": None, "new": new})
    return diffs


# ---------- signing (HMAC) ----------

def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _key_path(data_dir):
    return os.path.join(data_dir, ".fam.key")


def _get_key(data_dir, create=False):
    kp = _key_path(data_dir)
    if not os.path.exists(kp):
        if not create:
            raise BaselineTampered("HMAC key file is missing")
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # only the owner can read it
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    with open(kp, "rb") as f:
        return f.read()


def baseline_path(data_dir):
    return os.path.join(data_dir, "baseline.json")


def save_baseline(files, data_dir):
    key = _get_key(data_dir, create=True)
    doc = {"created": now_iso(), "files": files}
    doc["hmac"] = hmac.new(key, _canon({"created": doc["created"], "files": files}), hashlib.sha256).hexdigest()
    path = baseline_path(data_dir)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f)
    os.replace(tmp, path)         # atomic: never a half-written baseline
    return path


def load_baseline(data_dir):
    path = baseline_path(data_dir)
    if not os.path.exists(path):
        raise FileNotFoundError("No baseline yet. Run:  python main.py init")
    with open(path) as f:
        doc = json.load(f)
    key = _get_key(data_dir)
    want = hmac.new(key, _canon({"created": doc.get("created"), "files": doc.get("files")}), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(doc.get("hmac", ""))):
        raise BaselineTampered("baseline.json does not match its signature - it was edited!")
    return doc["files"]
