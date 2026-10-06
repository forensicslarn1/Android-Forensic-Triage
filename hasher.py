"""
4nsicsLarn - Evidence Hashing & Integrity Module
Calculates cryptographic hashes (SHA-256, MD5) for chain of custody and forensic data integrity.
"""

import os
import hashlib
from typing import Dict, Any

def compute_file_hashes(file_path: str, chunk_size: int = 65536) -> Dict[str, Any]:
    """
    Computes SHA-256 and MD5 hashes of a file using chunked reading to handle large evidence files.
    Returns a dictionary with hashes, file size, and timestamps.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)

    stat_info = os.stat(file_path)

    return {
        "file_name": os.path.basename(file_path),
        "file_path": os.path.abspath(file_path),
        "file_size_bytes": stat_info.st_size,
        "file_size_formatted": format_size(stat_info.st_size),
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
        "modified_time": stat_info.st_mtime,
    }

def format_size(size_bytes: int) -> str:
    """Formats file size into human-readable units (B, KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}" if unit != 'B' else f"{size_bytes} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
