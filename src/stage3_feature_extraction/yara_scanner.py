"""
YARA Scanner for Stage 3

Fast YARA pattern matching for on-disk PE files and memory regions.
Designed to be lightweight (<2ms, <5MB) and integrated into Stage 3 ML pipeline.
"""

import logging
import os
import sys
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

logger = logging.getLogger("stage3_yara_scanner")

# YARA import
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("Yara not available. Install with: pip install yara-python")

# Windows-specific imports for memory scanning
try:
    import ctypes
    from ctypes import wintypes
    WINDOWS_AVAILABLE = sys.platform == 'win32'
except ImportError:
    WINDOWS_AVAILABLE = False

if WINDOWS_AVAILABLE:
    # Windows API constants
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    
    # Windows API functions
    kernel32 = ctypes.windll.kernel32
    OpenProcess = kernel32.OpenProcess
    CloseHandle = kernel32.CloseHandle
    ReadProcessMemory = kernel32.ReadProcessMemory
    VirtualQueryEx = kernel32.VirtualQueryEx


class YaraScanner:
    """
    Fast YARA scanner for Stage 3.
    
    Scans:
    - On-disk PE files (primary)
    - Memory regions (if available, Windows only)
    
    Designed to run in <2ms and add <5MB memory overhead.
    """

    # Contexts for YARA matches (used to down-weight low-trust matches and reduce false positives)
    YARA_CONTEXTS = {
        "MEMORY",
        "EXECUTABLE_FILE",
        "SCRIPT_FILE",
        "DOCUMENT_FILE",
        "ADS_METADATA",
        "UNKNOWN",
    }

    # Context weights (higher = more trustworthy signal)
    CONTEXT_WEIGHTS: Dict[str, float] = {
        "MEMORY": 1.0,
        "EXECUTABLE_FILE": 0.9,
        "SCRIPT_FILE": 0.6,
        "DOCUMENT_FILE": 0.3,
        "ADS_METADATA": 0.05,
        "UNKNOWN": 0.1,
    }
    
    def __init__(self, yara_rules_path: Optional[str] = None):
        """
        Initialize YARA scanner.
        
        Args:
            yara_rules_path: Path to YARA rules file or directory (300-400 curated rules)
        """
        self.yara_rules = None
        self.rules_loaded = False
        self.rules_source: Optional[str] = None
        self.rules_file_count: int = 0
        
        if not YARA_AVAILABLE:
            logger.warning("YARA not available. YARA scanning will be disabled.")
            return
        
        # If no explicit rules path is provided, auto-discover the bundled rules directory
        # (avoids absolute paths; works in production packaging).
        if not yara_rules_path:
            default_rules_dir = Path(__file__).parent / "rules"
            if default_rules_dir.exists() and default_rules_dir.is_dir():
                yara_rules_path = str(default_rules_dir)
                logger.info(f"No YARA rules path provided; using bundled rules dir: {default_rules_dir}")
            else:
                logger.info("No YARA rules path provided and no bundled rules dir found. YARA scanning disabled.")
                return

        # Load rules from file or directory
        try:
            p = Path(yara_rules_path)
            if p.is_dir():
                # Compile all .yar/.yara files in directory. yara.compile(filepath=...) expects a single file,
                # so we must build filepaths mapping for directories.
                rule_files = sorted([*p.glob("*.yar"), *p.glob("*.yara")])
                if not rule_files:
                    logger.warning(f"YARA rules directory has no .yar/.yara files: {p}")
                    return

                # Use stable, unique keys for each file.
                filepaths = {f"{idx:03d}_{rf.name}": str(rf) for idx, rf in enumerate(rule_files, start=1)}
                self.yara_rules = yara.compile(filepaths=filepaths)
                self.rules_source = str(p)
                self.rules_file_count = len(rule_files)
                logger.info(f"Loaded {len(rule_files)} YARA rule files from directory: {p}")

            elif p.is_file():
                self.yara_rules = yara.compile(filepath=str(p))
                self.rules_source = str(p)
                self.rules_file_count = 1
                logger.info(f"Loaded YARA rules from file: {p}")

            else:
                logger.warning(f"YARA rules path does not exist: {p}")
                return

            self.rules_loaded = True
            logger.info("YARA scanner initialized successfully")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None
            self.rules_loaded = False
            self.rules_source = None
            self.rules_file_count = 0
    
    def scan_file(self, file_path: str) -> Tuple[bool, List[str], float]:
        """
        Scan on-disk PE file with YARA.
        
        Args:
            file_path: Path to executable file
            
        Returns:
            Tuple of (matched: bool, matched_rules: List[str], confidence: float)
            confidence is 0.0-1.0 based on rule priority/tags
        """
        if not self.rules_loaded or not self.yara_rules:
            return False, [], 0.0

    @staticmethod
    def classify_yara_context(file_path: Optional[str]) -> str:
        """
        Classify the scan context for a file path.

        This is used to apply context-aware YARA weighting:
        - ADS metadata (Zone.Identifier) is low-trust and should not elevate risk alone.
        """
        if not file_path:
            return "UNKNOWN"

        p = str(file_path)
        low = p.lower()

        # ADS / metadata streams (e.g., :Zone.Identifier)
        # Note: Windows paths include "C:\", so we specifically look for a second ':' after drive letter.
        if ":zone.identifier" in low or (len(p) > 2 and ":" in p[2:] and "zone.identifier" in low):
            return "ADS_METADATA"

        # Extension-based classification
        try:
            suffix = Path(p).suffix.lower()
        except Exception:
            suffix = ""

        if suffix in {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".com"}:
            return "EXECUTABLE_FILE"

        if suffix in {".ps1", ".psm1", ".vbs", ".js", ".jse", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".py", ".sh"}:
            return "SCRIPT_FILE"

        if suffix in {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam", ".rtf"}:
            return "DOCUMENT_FILE"

        return "UNKNOWN"

    def get_context_weight(self, context: str) -> float:
        """Get weighting for a YARA context."""
        return float(self.CONTEXT_WEIGHTS.get(context, 0.1))
        
        if not file_path or not os.path.exists(file_path):
            return False, [], 0.0
        
        try:
            matches = self.yara_rules.match(file_path, timeout=10)
            
            if not matches:
                return False, [], 0.0
            
            matched_rules = [match.rule for match in matches]
            
            # Calculate confidence based on rule tags/priority
            # Known ransomware families get higher confidence
            confidence = 0.0
            for match in matches:
                tags = match.tags or []
                rule_name_lower = match.rule.lower()
                
                # High confidence for known ransomware families
                if any(tag in ['ransomware', 'lockbit', 'akira', 'ransomhub', 'blackcat', 'conti'] for tag in tags):
                    confidence = max(confidence, 0.95)
                elif 'ransomware' in rule_name_lower or 'crypto' in rule_name_lower:
                    confidence = max(confidence, 0.90)
                elif any(tag in ['malware', 'trojan'] for tag in tags):
                    confidence = max(confidence, 0.85)
                else:
                    confidence = max(confidence, 0.75)
            
            return True, matched_rules, min(confidence, 1.0)
            
        except yara.TimeoutError:
            logger.debug(f"YARA scan timeout for {file_path}")
            return False, [], 0.0
        except Exception as e:
            logger.debug(f"YARA scan error for {file_path}: {e}")
            return False, [], 0.0
    
    def scan_process_memory(self, pid: int, max_regions: int = 50) -> Tuple[bool, List[str], float]:
        """
        Scan process memory regions with YARA (Windows only).
        
        Args:
            pid: Process ID
            max_regions: Maximum memory regions to scan (for performance)
            
        Returns:
            Tuple of (matched: bool, matched_rules: List[str], confidence: float)
        """
        if not self.rules_loaded or not self.yara_rules:
            return False, [], 0.0
        
        if not WINDOWS_AVAILABLE:
            return False, [], 0.0
        
        try:
            # Open process handle
            h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_process:
                return False, [], 0.0
            
            try:
                matched_rules = []
                confidence = 0.0
                regions_scanned = 0
                
                # Query memory regions
                mbi = ctypes.create_string_buffer(48)  # MEMORY_BASIC_INFORMATION
                address = 0
                
                while regions_scanned < max_regions:
                    result = VirtualQueryEx(h_process, address, mbi, 48)
                    if result == 0:
                        break
                    
                    # Extract memory info
                    base_address = ctypes.c_void_p.from_buffer(mbi, 0).value
                    region_size = ctypes.c_size_t.from_buffer(mbi, 24).value
                    protect = ctypes.c_ulong.from_buffer(mbi, 32).value
                    state = ctypes.c_ulong.from_buffer(mbi, 40).value
                    
                    # Only scan committed, readable regions
                    if (state == MEM_COMMIT and 
                        protect in [PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]):
                        
                        # Read memory region (limit to 1MB per region for performance)
                        read_size = min(region_size, 1024 * 1024)
                        buffer = ctypes.create_string_buffer(read_size)
                        bytes_read = ctypes.c_size_t(0)
                        
                        if ReadProcessMemory(h_process, base_address, buffer, read_size, ctypes.byref(bytes_read)):
                            try:
                                # Scan with YARA
                                matches = self.yara_rules.match(data=buffer.raw[:bytes_read.value], timeout=5)
                                for match in matches:
                                    if match.rule not in matched_rules:
                                        matched_rules.append(match.rule)
                                        
                                        # Calculate confidence
                                        tags = match.tags or []
                                        if any(tag in ['ransomware', 'lockbit', 'akira'] for tag in tags):
                                            confidence = max(confidence, 0.95)
                                        else:
                                            confidence = max(confidence, 0.80)
                            except Exception:
                                pass  # Skip region on error
                    
                    address = base_address + region_size
                    regions_scanned += 1
                
                if matched_rules:
                    return True, matched_rules, min(confidence, 1.0)
                else:
                    return False, [], 0.0
                    
            finally:
                CloseHandle(h_process)
                
        except Exception as e:
            logger.debug(f"Memory scan error for PID {pid}: {e}")
            return False, [], 0.0
    
    def scan_process(self, pid: int, image_path: Optional[str] = None, scan_memory: bool = True) -> Tuple[bool, List[str], float]:
        """
        Scan both on-disk PE and memory regions for a process.
        
        Args:
            pid: Process ID
            image_path: Path to executable file (optional, will try to resolve if not provided)
            scan_memory: Whether to scan memory regions (default True, Windows only)
            
        Returns:
            Tuple of (matched: bool, matched_rules: List[str], confidence: float)
        """
        file_matched = False
        memory_matched = False
        all_matched_rules = []
        max_confidence = 0.0
        
        # Scan on-disk PE file
        if image_path:
            file_matched, file_rules, file_confidence = self.scan_file(image_path)
            if file_matched:
                all_matched_rules.extend(file_rules)
                max_confidence = max(max_confidence, file_confidence)
        
        # Scan memory regions (Windows only, optional)
        if scan_memory and WINDOWS_AVAILABLE:
            memory_matched, memory_rules, memory_confidence = self.scan_process_memory(pid)
            if memory_matched:
                all_matched_rules.extend([r for r in memory_rules if r not in all_matched_rules])
                max_confidence = max(max_confidence, memory_confidence)
        
        # Return combined result
        matched = file_matched or memory_matched
        return matched, all_matched_rules, max_confidence

    def scan_process_detailed(
        self,
        pid: int,
        image_path: Optional[str] = None,
        scan_memory: bool = True
    ) -> Dict[str, Any]:
        """
        Scan process with context-aware results.

        Returns:
            dict with:
              - matched: bool
              - matched_rules: list[str]
              - raw_confidence: float (0-1)
              - contexts: dict[str,bool]
              - confidence_by_context: dict[str,float]
              - rules_by_context: dict[str,list[str]]
              - primary_context: str
              - context_weight: float
              - weighted_confidence: float (raw_confidence * context_weight for primary context)
        """
        contexts = {c: False for c in self.YARA_CONTEXTS}
        confidence_by_context = {c: 0.0 for c in self.YARA_CONTEXTS}
        rules_by_context: Dict[str, List[str]] = {c: [] for c in self.YARA_CONTEXTS}

        matched_rules: List[str] = []
        raw_confidence = 0.0

        # File scan context
        file_context = self.classify_yara_context(image_path)
        if image_path:
            file_matched, file_rules, file_conf = self.scan_file(image_path)
            if file_matched:
                contexts[file_context] = True
                confidence_by_context[file_context] = max(confidence_by_context[file_context], float(file_conf))
                rules_by_context[file_context].extend(file_rules)
                for r in file_rules:
                    if r not in matched_rules:
                        matched_rules.append(r)
                raw_confidence = max(raw_confidence, float(file_conf))

        # Memory scan context
        if scan_memory and WINDOWS_AVAILABLE:
            mem_matched, mem_rules, mem_conf = self.scan_process_memory(pid)
            if mem_matched:
                contexts["MEMORY"] = True
                confidence_by_context["MEMORY"] = max(confidence_by_context["MEMORY"], float(mem_conf))
                rules_by_context["MEMORY"].extend(mem_rules)
                for r in mem_rules:
                    if r not in matched_rules:
                        matched_rules.append(r)
                raw_confidence = max(raw_confidence, float(mem_conf))

        matched = bool(matched_rules)

        # Decide primary context by highest weighted confidence
        primary_context = "UNKNOWN"
        primary_weight = self.get_context_weight(primary_context)
        weighted_confidence = 0.0
        if matched:
            best_ctx = "UNKNOWN"
            best_weighted = 0.0
            for ctx, did_match in contexts.items():
                if not did_match:
                    continue
                conf = float(confidence_by_context.get(ctx, 0.0))
                w = self.get_context_weight(ctx)
                wc = conf * w
                if wc > best_weighted:
                    best_weighted = wc
                    best_ctx = ctx
            primary_context = best_ctx
            primary_weight = self.get_context_weight(primary_context)
            weighted_confidence = best_weighted

        return {
            "matched": matched,
            "matched_rules": matched_rules,
            "raw_confidence": raw_confidence,
            "contexts": contexts,
            "confidence_by_context": confidence_by_context,
            "rules_by_context": rules_by_context,
            "primary_context": primary_context,
            "context_weight": primary_weight,
            "weighted_confidence": weighted_confidence,
        }
    
    def is_available(self) -> bool:
        """Check if YARA scanner is available and loaded"""
        return self.rules_loaded and self.yara_rules is not None

