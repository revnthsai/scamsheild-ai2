#!/usr/bin/env python3
"""
ScamShield AI — Project Zipper

Walks the repository and produces `scamshield-ai.zip` alongside this
script, skipping anything that shouldn't ship (caches, virtual envs,
secrets, previous zips). Run it from anywhere; paths are resolved
relative to this file, not the current working directory.

Usage:
    python build_project_zip.py [output_name.zip]
"""

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT_NAME = ROOT.name

EXCLUDED_DIR_NAMES = {
    "__pycache__", ".git", ".venv", "venv", "env", "node_modules",
    ".vercel", ".pytest_cache", ".mypy_cache", ".idea", ".vscode",
}
EXCLUDED_FILE_SUFFIXES = {".pyc", ".pyo", ".zip"}
EXCLUDED_FILE_NAMES = {".env", ".DS_Store", "Thumbs.db"}


def should_skip(path: Path) -> bool:
    if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
        return True
    if path.name in EXCLUDED_FILE_NAMES:
        return True
    if path.suffix in EXCLUDED_FILE_SUFFIXES:
        return True
    return False


def build_zip(output_name: str) -> Path:
    output_path = ROOT / output_name
    if output_path.exists():
        output_path.unlink()

    file_count = 0
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(ROOT.rglob("*")):
            if path.is_dir():
                continue
            if should_skip(path.relative_to(ROOT)):
                continue
            arcname = Path(PROJECT_NAME) / path.relative_to(ROOT)
            zf.write(path, arcname)
            file_count += 1

    print(f"Wrote {file_count} files to {output_path}")
    return output_path


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "scamshield-ai.zip"
    if not name.endswith(".zip"):
        name += ".zip"
    build_zip(name)
