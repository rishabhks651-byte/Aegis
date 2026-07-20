"""Backup and restore of the Aegis data directory."""

from __future__ import annotations

import datetime
import glob
import json
import os
import shutil
import tempfile
import time
import zipfile

BACKUP_DIR_NAME = "backups"


def _backup_dir(data_dir: str) -> str:
    return os.path.join(data_dir, BACKUP_DIR_NAME)


def create_backup(data_dir: str) -> str:
    """Create a timestamped zip backup of *data_dir* (excluding backups dir)."""
    backup_root = _backup_dir(data_dir)
    os.makedirs(backup_root, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"aegis_backup_{timestamp}.zip"
    backup_path = os.path.join(backup_root, backup_name)

    with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(data_dir):
            rel = os.path.relpath(root, data_dir)
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.join(rel, fname) if rel != "." else fname
                zf.write(fpath, arcname)

    return backup_path


def list_backups(data_dir: str) -> list[dict]:
    """Return metadata for all available backups, newest first."""
    backup_root = _backup_dir(data_dir)
    if not os.path.isdir(backup_root):
        return []

    results = []
    for fname in sorted(os.listdir(backup_root), reverse=True):
        if fname.startswith("aegis_backup_") and fname.endswith(".zip"):
            fpath = os.path.join(backup_root, fname)
            stat = os.stat(fpath)
            results.append({
                "name": fname,
                "path": fpath,
                "size_bytes": stat.st_size,
                "created": datetime.datetime.fromtimestamp(
                    stat.st_mtime, tz=datetime.timezone.utc
                ).isoformat(),
            })
    return results


def restore_backup(data_dir: str, backup_path: str) -> str:
    """Restore *backup_path* zip into *data_dir*, clearing existing data first."""
    if not os.path.isfile(backup_path):
        raise FileNotFoundError(f"Backup not found: {backup_path}")

    if not backup_path.endswith(".zip"):
        raise ValueError(f"Not a zip file: {backup_path}")

    # Clear existing data (but keep the backup dir itself)
    backup_root = _backup_dir(data_dir)
    for item in os.listdir(data_dir):
        if item == BACKUP_DIR_NAME:
            continue
        item_path = os.path.join(data_dir, item)
        if os.path.isdir(item_path):
            shutil.rmtree(item_path)
        else:
            os.remove(item_path)

    # Extract backup
    with zipfile.ZipFile(backup_path, "r") as zf:
        zf.extractall(data_dir)

    summary = _summarise_backup(data_dir, backup_path)
    return json.dumps(summary, indent=2)


def _summarise_backup(data_dir: str, backup_path: str) -> dict:
    """Return a summary dict of the backup contents."""
    sizes = {}
    for root, dirs, files in os.walk(data_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            sizes[fname] = os.path.getsize(fpath)
    return {
        "restored_from": backup_path,
        "files_restored": len(sizes),
        "total_size_bytes": sum(sizes.values()),
    }
