"""One-time migration: rename MD5-prefixed uploads to SHA256-prefixed.

Run this ONCE before deploying the SHA256 fix. Reads file_info.json
from each Results directory to get the SHA256 hash, then renames both
the Uploads file and Results directory.

Usage:
    python scripts/migrate_hashes.py
    python scripts/migrate_hashes.py --dry-run  # preview only
"""

import json
import os
import sys
import argparse


def migrate(upload_dir: str = "Uploads", result_dir: str = "Results", dry_run: bool = False) -> None:
    if not os.path.isdir(result_dir):
        print(f"Results directory not found: {result_dir}")
        return

    migrated = 0
    skipped = 0
    errors = 0

    for dirname in os.listdir(result_dir):
        result_path = os.path.join(result_dir, dirname)
        if not os.path.isdir(result_path):
            continue

        # Read file_info.json to get SHA256
        info_path = os.path.join(result_path, "file_info.json")
        if not os.path.exists(info_path):
            print(f"  SKIP (no file_info.json): {dirname}")
            skipped += 1
            continue

        try:
            with open(info_path) as f:
                info = json.load(f)
        except Exception as e:
            print(f"  ERROR reading {info_path}: {e}")
            errors += 1
            continue

        sha256 = info.get("sha256", "")
        if not sha256:
            print(f"  SKIP (no sha256 in file_info): {dirname}")
            skipped += 1
            continue

        # Check if already SHA256-prefixed
        if dirname.startswith(sha256):
            skipped += 1
            continue

        # Extract original filename from current dirname: {md5}_{original}
        parts = dirname.split("_", 1)
        if len(parts) < 2:
            print(f"  SKIP (unexpected format): {dirname}")
            skipped += 1
            continue

        original_name = parts[1]
        new_dirname = f"{sha256}_{original_name}"

        print(f"  {dirname}")
        print(f"  → {new_dirname}")

        if not dry_run:
            # Rename Results directory
            new_result_path = os.path.join(result_dir, new_dirname)
            if not os.path.exists(new_result_path):
                os.rename(result_path, new_result_path)

            # Rename Uploads file
            old_upload = os.path.join(upload_dir, dirname)
            new_upload = os.path.join(upload_dir, new_dirname)
            if os.path.exists(old_upload) and not os.path.exists(new_upload):
                os.rename(old_upload, new_upload)

        migrated += 1

    print(f"\n{'DRY RUN — ' if dry_run else ''}Migration complete: {migrated} migrated, {skipped} skipped, {errors} errors")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate MD5-prefixed uploads to SHA256-prefixed")
    parser.add_argument("--dry-run", action="store_true", help="Preview without making changes")
    parser.add_argument("--upload-dir", default="Uploads", help="Upload directory path")
    parser.add_argument("--result-dir", default="Results", help="Results directory path")
    args = parser.parse_args()

    migrate(args.upload_dir, args.result_dir, args.dry_run)
