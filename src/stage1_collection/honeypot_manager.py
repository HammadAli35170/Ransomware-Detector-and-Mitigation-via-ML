# src/stage1_collection/honeypot_manager.py
# FULL PRODUCTION VERSION – Sysmon-Compatible (Dec 2025)

import os
import json
import hashlib
import ctypes
import random
from pathlib import Path
from typing import Callable, Set, Dict, Optional


class HoneypotManager:
    """
    Deploys safe honeypot files into controlled directories and checks for ANY access.
    Compatible with SYSMon Stage-1 normalized event stream.
    """

    FILE_ATTRIBUTE_HIDDEN = 0x02
    FILE_ATTRIBUTE_SYSTEM = 0x04
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000

    SAFE_ROOTS = [
        r"C:\Honeypots",
        r"C:\Users\Public\Honeypots"
    ]

    def __init__(self, alert_callback: Callable[[dict], None]):
        self.alert_callback = alert_callback

        # For O(1) lookup performance
        self.deployed_paths: Set[str] = set()

        # Shadow integrity protection
        self.checksums: Dict[str, str] = {}
        self.entropy_map: Dict[str, float] = {}

        # Folder-level prefix accelerator
        self.honeypot_dirs: Set[str] = set()

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    @staticmethod
    def _win_set_attributes(filepath: str) -> None:
        """Apply hidden+system+non-indexed attributes. Safe, ignores failures."""
        try:
            attrs = (
                HoneypotManager.FILE_ATTRIBUTE_HIDDEN |
                HoneypotManager.FILE_ATTRIBUTE_SYSTEM |
                HoneypotManager.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
            )
            ctypes.windll.kernel32.SetFileAttributesW(str(filepath), attrs)
        except Exception:
            pass

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Calculate Shannon entropy 0–8."""
        if not data:
            return 0.0
        import math
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        length = len(data)
        for c in freq:
            if c == 0:
                continue
            p = c / length
            entropy -= p * math.log2(p)
        return entropy

    def _checksum(self, path: str) -> Optional[str]:
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    # ---------------------------------------------------------
    # Deployment
    # ---------------------------------------------------------

    def deploy(self, count_per_dir: int = 10) -> None:
        """Deploy honeypots in safe sandbox directories."""
        patterns = [
            "Financial_Report_2025.docx",
            "Crypto_Keys_Backup.dat",
            "Vacation_Photos.zip",
            "Medical_Bills_2024.pdf",
            "Password_Export.kdbx",
        ]

        for safe_root in self.SAFE_ROOTS:
            os.makedirs(safe_root, exist_ok=True)
            self.honeypot_dirs.add(safe_root.lower())

            for i in range(count_per_dir):
                base = random.choice(patterns)
                ext = random.choice(["docx", "xlsx", "txt", "pdf", "zip", "dat"])
                name_hash = hashlib.md5(f"{safe_root}-{i}".encode()).hexdigest()[:10]
                full_path = os.path.join(safe_root, f"{base}_{name_hash}.{ext}")

                try:
                    # Write deterministic honeypot content
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write("=== HONEYPOT FILE ===\n" * 40)
                        f.write("ACCESS = ENCRYPTION ATTEMPT\n")

                    os.chmod(full_path, 0o444)
                    self._win_set_attributes(full_path)

                    norm = full_path.lower()
                    self.deployed_paths.add(norm)

                    # Store checksum + entropy
                    c = self._checksum(full_path)
                    if c:
                        self.checksums[norm] = c
                    with open(full_path, "rb") as f:
                        self.entropy_map[norm] = self._entropy(f.read())

                except Exception:
                    continue

        print(f"[+] HoneypotManager: Deployed {len(self.deployed_paths)} honeypots.")

    # ---------------------------------------------------------
    # Utilities
    # ---------------------------------------------------------

    def _log(self, data: dict):
        try:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            with open(log_dir / "honeypot_alerts.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except Exception:
            pass

    def _is_honeypot(self, path: str) -> bool:
        p = path.lower()
        if p in self.deployed_paths:
            return True

        # Folder-level prefix rule
        for d in self.honeypot_dirs:
            if p.startswith(d):
                return True

        return False

    # ---------------------------------------------------------
    # Event Handler — Called by file_monitor.py
    # ---------------------------------------------------------

    def handle_file_event(self, evt: dict) -> None:
        """
        evt = {
            "type": "FILE_WRITE",
            "path": "C:\\Honeypots\\Financial...docx",
            "pid": 1120,
            "process_name": "evil.exe",
            "operation": "WriteFile"
        }
        """
        path = evt.get("path")
        if not path or not self._is_honeypot(path):
            return

        # Honeypot touched — verify integrity
        integrity_state = "OK"
        norm = path.lower()

        try:
            # Checksum delta
            old = self.checksums.get(norm)
            new = self._checksum(path)
            if old and new and old != new:
                integrity_state = "CHECKSUM_CHANGED"

            # Entropy change
            with open(path, "rb") as f:
                new_ent = self._entropy(f.read())
            old_ent = self.entropy_map.get(norm, new_ent)
            if abs(old_ent - new_ent) > 0.6:
                integrity_state = "ENTROPY_CHANGED"

        except Exception:
            integrity_state = "INACCESSIBLE"

        alert = {
            "type": "HONEYPOT_TRIGGER",
            "file_path": path,
            "process_id": evt.get("pid"),
            "process_name": evt.get("process_name"),
            "operation": evt.get("operation", "UNKNOWN"),
            "integrity_status": integrity_state,
            "severity": "CRITICAL"
        }

        print(f"\n[!!!] HONEYPOT ACCESSED by PID {evt.get('pid')} ({evt.get('process_name')})\n")

        self._log(alert)
        self.alert_callback(alert)
