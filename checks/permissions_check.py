# checks/permissions_check.py

import os
import stat
import glob

# Critical files with their expected permissions and owner
# Format: "path": {"expected_mode": octal, "expected_uid": int, "expected_gid": int}
CRITICAL_FILES = {
    # passwd & shadow
    "/etc/passwd": {
        "expected_mode": 0o644,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "User account database",
    },
    "/etc/shadow": {
        "expected_mode": 0o640,
        "expected_uid":  0,
        "expected_gid":  42,   # group 'shadow' on most distros
        "description":   "Encrypted password database",
    },
    "/etc/gshadow": {
        "expected_mode": 0o640,
        "expected_uid":  0,
        "expected_gid":  42,
        "description":   "Encrypted group password database",
    },
    "/etc/group": {
        "expected_mode": 0o644,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Group account database",
    },

    # sudoers
    "/etc/sudoers": {
        "expected_mode": 0o440,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Sudo privilege configuration",
    },

    # SSH config
    "/etc/ssh/sshd_config": {
        "expected_mode": 0o600,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "SSH daemon configuration",
    },
}

# Directories to audit recursively
CRITICAL_DIRS = {
    "/etc/sudoers.d": {
        "expected_mode": 0o440,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Sudoers drop-in directory",
    },
    "/etc/cron.d": {
        "expected_mode": 0o644,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Cron job definitions",
    },
    "/etc/cron.daily": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Daily cron scripts",
    },
    "/etc/cron.weekly": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Weekly cron scripts",
    },
    "/etc/cron.monthly": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Monthly cron scripts",
    },
    "/usr/bin": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "User binaries directory",
    },
    "/usr/sbin": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "System binaries directory",
    },
    "/bin": {
        "expected_mode": 0o755,
        "expected_uid":  0,
        "expected_gid":  0,
        "description":   "Essential binaries directory",
    },
}

# Permission masks
WORLD_WRITABLE = 0o002   # -------w-
WORLD_READABLE = 0o004   # ------r--


def get_octal_mode(filepath: str) -> int | None:
    """Return the permission bits of a file as an octal integer"""
    try:
        return stat.S_IMODE(os.stat(filepath).st_mode)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_owner(filepath: str) -> tuple[int, int] | None:
    """Return (uid, gid) of a file owner"""
    try:
        s = os.stat(filepath)
        return s.st_uid, s.st_gid
    except (PermissionError, FileNotFoundError, OSError):
        return None


def is_world_writable(mode: int) -> bool:
    """Return True if the file is writable by others"""
    return bool(mode & WORLD_WRITABLE)


def is_world_readable(mode: int) -> bool:
    """Return True if the file is readable by others"""
    return bool(mode & WORLD_READABLE)


def audit_file(filepath: str, expected: dict) -> dict:
    """
    Audit a single file against its expected permissions and owner.
    Returns a dict describing the file status and any issues found.
    """
    issues = []

    mode = get_octal_mode(filepath)
    owner = get_owner(filepath)

    if mode is None or owner is None:
        return {
            "path":        filepath,
            "description": expected.get("description", ""),
            "status":      "unreadable",
            "issues":      ["Could not read file metadata"],
            "mode":        None,
            "uid":         None,
            "gid":         None,
        }

    uid, gid = owner

    # Check permissions
    if mode != expected["expected_mode"]:
        issues.append(
            f"Incorrect permissions: {oct(mode)} "
            f"(expected {oct(expected['expected_mode'])})"
        )

    # Check owner UID
    if uid != expected["expected_uid"]:
        issues.append(
            f"Incorrect owner UID: {uid} "
            f"(expected {expected['expected_uid']})"
        )

    # Check owner GID
    if gid != expected["expected_gid"]:
        issues.append(
            f"Incorrect owner GID: {gid} "
            f"(expected {expected['expected_gid']})"
        )

    # Check world-writable
    if is_world_writable(mode):
        issues.append("World-writable: any user can modify this file")

    # Check world-readable on sensitive files
    if is_world_readable(mode) and expected["expected_mode"] in {0o640, 0o440, 0o600}:
        issues.append("World-readable: sensitive file exposed to all users")

    return {
        "path":        filepath,
        "description": expected.get("description", ""),
        "status":      "ok" if not issues else "issues_found",
        "issues":      issues,
        "mode":        oct(mode),
        "uid":         uid,
        "gid":         gid,
    }


def collect_dir_files(dirpath: str, expected: dict) -> list[dict]:
    """Audit all files inside a directory (non-recursive)"""
    results = []

    if not os.path.isdir(dirpath):
        return results

    try:
        for filename in os.listdir(dirpath):
            filepath = os.path.join(dirpath, filename)
            if os.path.isfile(filepath):
                results.append(audit_file(filepath, expected))
    except PermissionError:
        pass

    return results


def permissions_audit() -> dict:
    result = {
        "files":            [],
        "total_checked":    0,
        "total_issues":     0,
        "world_writable":   [],
        "world_readable":   [],
        "wrong_owner":      [],
        "wrong_mode":       [],
        "audit_score":     0,
        "error":            None,
    }

    audited = []

    # Audit individual critical files
    for filepath, expected in CRITICAL_FILES.items():
        if os.path.exists(filepath):
            audited.append(audit_file(filepath, expected))

    # Audit files inside critical directories
    for dirpath, expected in CRITICAL_DIRS.items():
        audited.extend(collect_dir_files(dirpath, expected))

    # Aggregate results
    for entry in audited:
        for issue in entry["issues"]:
            if "World-writable" in issue:
                result["world_writable"].append(entry["path"])
            if "World-readable" in issue:
                result["world_readable"].append(entry["path"])
            if "owner UID" in issue or "owner GID" in issue:
                result["wrong_owner"].append(entry["path"])
            if "Incorrect permissions" in issue:
                result["wrong_mode"].append(entry["path"])

    files_with_issues = [f for f in audited if f["status"] == "issues_found"]

    result["files"]         = audited
    result["total_checked"] = len(audited)
    result["total_issues"]  = len(files_with_issues)

    # Score:
    # -15 per world-writable file (critical risk)
    # -10 per wrong owner
    # -5  per wrong mode
    # -5  per world-readable sensitive file
    # Capped at -60
    penalty = (
        len(result["world_writable"]) * 15 +
        len(result["wrong_owner"])    * 10 +
        len(result["wrong_mode"])     *  5 +
        len(result["world_readable"]) *  5
    )
    result["audit_score"] = -min(penalty, 60)
    
    return result
