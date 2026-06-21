# check/suid_check.py
import subprocess
import os
import stat
from utils.logger import logger

# Legitimate SUID binaries present on most Linux systems
SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/sbin/unix_chkpwd",
    "/bin/su",
    "/bin/mount",
    "/bin/umount",
    "/sbin/unix_chkpwd",
}

# Directories to exclude from the scan (virtual/system filesystems)
EXCLUDED_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
}


def is_excluded(path: str) -> bool:
    """Check if a path belongs to an excluded directory"""
    for excluded in EXCLUDED_DIRS:
        if path.startswith(excluded):
            return True
    return False


def has_suid_bit(filepath: str) -> bool:
    """Return True if the file has the SUID bit set"""
    try:
        file_stat = os.stat(filepath)
        return bool(file_stat.st_mode & stat.S_ISUID)
    except (PermissionError, FileNotFoundError, OSError):
        return False


def scan_suid_files(root: str = "/") -> list[dict]:
    """
    Walk the filesystem from root and collect all SUID files.
    Returns a list of dicts with path, whitelisted, and owner info.
    """
    suid_files = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):

        # Skip excluded directories in-place (modifying dirnames
        # prevents os.walk from descending into them)
        dirnames[:] = [
            d for d in dirnames
            if not is_excluded(os.path.join(dirpath, d))
        ]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)

            if is_excluded(filepath):
                continue

            if not has_suid_bit(filepath):
                continue

            # Retrieve file owner
            try:
                file_stat = os.stat(filepath)
                owner_uid = file_stat.st_uid
            except OSError:
                owner_uid = -1

            whitelisted = filepath in SUID_WHITELIST

            suid_files.append({
                               "path":        filepath,
                               "owner_uid":   owner_uid,
                               "whitelisted": whitelisted,
                               "suspicious":  not whitelisted,
                             })

    return suid_files


def suid_audit(root: str = "/") -> dict:
    result = {
        "suid_files":       [],
        "suspicious_files": [],
        "total_suid":       0,
        "total_suspicious": 0,
        "audit_score":      0,
        "error":            None,
    }

    try:
        suid_files = scan_suid_files(root)
    except PermissionError as e:
        logger.error("Permission denied during scan.")
        result["error"] = f"Permission denied during scan: {e}"
        return result

    suspicious = [f for f in suid_files if f["suspicious"]]

    result["suid_files"]       = suid_files
    result["suspicious_files"] = suspicious
    result["total_suid"]       = len(suid_files)
    result["total_suspicious"] = len(suspicious)

    logger.info(f"suid_check - suspicious files : {len(suspicious)}")
    
    # Score: -20 per suspicious SUID file, capped at -60
    penalty = min(len(suspicious) * 20, 60)
    result["audit_score"] = -penalty
    
 
    return result
