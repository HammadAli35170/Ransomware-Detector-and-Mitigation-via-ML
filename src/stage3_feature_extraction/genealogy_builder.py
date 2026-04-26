"""
Process Genealogy Builder for Stage 3

Lightweight process genealogy builder for visualization purposes only.
NOT used for ML scoring - keeps Stage 3 fast and focused.

Updated to handle missing parents explicitly using ProcessGuid as primary identifier.
"""

import logging
import time
import threading
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger("stage3_genealogy")


class MissingParentReason(Enum):
    """Reason codes for why a parent process is missing"""
    PARENT_EXITED_BEFORE_COLLECTION = "parent_exited_before_collection"
    AGENT_STARTUP_GAP = "agent_startup_gap"
    TELEMETRY_FILTERED = "telemetry_filtered"
    PID_REUSE_RISK = "pid_reuse_risk"
    UNKNOWN = "unknown"


@dataclass
class ProcessNode:
    """Represents an observed process in the genealogy tree"""
    process_guid: str  # Primary identifier
    pid: int
    image_path: str = ""
    command_line: str = ""
    parent_pid: Optional[int] = None
    parent_guid: Optional[str] = None  # If parent is observed
    parent_image: str = ""
    children: Set[str] = field(default_factory=set)  # Set of child process_guids
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class ReferencedOnlyParent:
    """Represents a parent process that was referenced but never observed"""
    pid: int
    first_seen_time: float
    child_process_guids: Set[str] = field(default_factory=set)
    resolved: bool = False  # True if we later observed this process
    reason: MissingParentReason = MissingParentReason.UNKNOWN


@dataclass
class UnobservedParentNode:
    """Placeholder node for an unobserved parent in the genealogy tree"""
    pid: int
    reason: MissingParentReason
    first_referenced: float
    child_count: int


@dataclass
class GenealogyTree:
    """Process genealogy tree for a specific PID/ProcessGuid"""
    root_pid: int
    root_process_guid: Optional[str]
    tree_depth: int
    tree_width: int
    total_descendants: int
    observed_ancestors: int
    unobserved_ancestors: int
    ancestors: List[Dict[str, Any]]  # List of {pid, image, command_line, process_guid, is_unobserved, reason} going up
    descendants: List[Dict[str, Any]]  # List of {pid, image, command_line, process_guid, depth} going down
    full_tree: Dict[str, Any]  # Complete tree structure for visualization


class ProcessGenealogy:
    """
    Lightweight process genealogy builder for Stage 3.
    
    Purpose: Build process genealogy for dashboard visualization only.
    NOT used for ML scoring - Stage 3 ML remains unchanged.
    
    Key Features:
    - Uses ProcessGuid as primary identifier (handles PID reuse safely)
    - Tracks observed processes vs referenced-only parents
    - Preserves parent-child relationships even when parent is missing
    - Includes unobserved parent placeholders in genealogy trees
    """
    
    def __init__(self, window_sec: int = 3600, cleanup_sec: int = 7200):
        """
        Initialize Process Genealogy Builder.
        
        Args:
            window_sec: Time window for genealogy tracking (default 1 hour)
            cleanup_sec: Cleanup processes older than this (default 2 hours)
        """
        self.window_sec = window_sec
        self.cleanup_sec = cleanup_sec
        
        # Observed Process Table: process_guid -> ProcessNode
        self.processes: Dict[str, ProcessNode] = {}
        
        # PID to ProcessGuid mapping (for display/fallback correlation)
        # Note: PID can be reused, so this is best-effort
        self.pid_to_guid: Dict[int, str] = {}
        
        # Referenced-Only Parent Table: pid -> ReferencedOnlyParent
        self.referenced_parents: Dict[int, ReferencedOnlyParent] = {}
        
        # GUID to ProcessNode reverse lookup (for fast access)
        self.guid_to_node: Dict[str, ProcessNode] = {}
        
        self._lock = threading.RLock()
        
        logger.info("ProcessGenealogy initialized (ProcessGuid-based, handles missing parents)")
    
    def _generate_guid(self, pid: int, timestamp: float) -> str:
        """Generate a synthetic ProcessGuid if one is not provided"""
        return f"SYNTHETIC-{pid}-{int(timestamp * 1000)}"
    
    def _determine_missing_parent_reason(self, parent_pid: int, child_time: float) -> MissingParentReason:
        """
        Determine why a parent process is missing.
        
        Args:
            parent_pid: The missing parent's PID
            child_time: When the child process was created
            
        Returns:
            MissingParentReason enum value
        """
        # Check if this PID was ever seen (PID reuse scenario)
        if parent_pid in self.pid_to_guid:
            # Check if the GUID we have is still active
            guid = self.pid_to_guid[parent_pid]
            if guid in self.processes:
                node = self.processes[guid]
                # If parent was seen but ended before child started, it exited
                if node.end_time and node.end_time < child_time:
                    return MissingParentReason.PARENT_EXITED_BEFORE_COLLECTION
                # Otherwise might be PID reuse
                return MissingParentReason.PID_REUSE_RISK
        
        # Check if we're in early startup window (first 60 seconds)
        if child_time - self._get_startup_time() < 60:
            return MissingParentReason.AGENT_STARTUP_GAP
        
        # Default to telemetry filtered (most common case)
        return MissingParentReason.TELEMETRY_FILTERED
    
    def _get_startup_time(self) -> float:
        """Get the time when genealogy tracking started"""
        if not hasattr(self, '_startup_time'):
            self._startup_time = time.time()
        return self._startup_time
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """
        Add an event to build genealogy.
        
        This is called for visualization purposes only - does not affect ML scoring.
        """
        try:
            # Extract PID
            pid = None
            for k in ("ProcessID", "ProcessId", "process_id", "pid"):
                if k in event:
                    try:
                        pid = int(event[k])
                        break
                    except (ValueError, TypeError):
                        continue
            
            if not pid:
                return
            
            # Extract ProcessGuid (preferred) or generate synthetic one
            process_guid = (
                event.get("ProcessGuid") or 
                event.get("process_guid") or 
                self._generate_guid(pid, time.time())
            )
            
            with self._lock:
                current_time = time.time()
                
                # Get or create process node (keyed by ProcessGuid)
                if process_guid not in self.processes:
                    # New process - create node
                    node = ProcessNode(
                        process_guid=process_guid,
                        pid=pid,
                        image_path=event.get("Image") or event.get("image") or "",
                        command_line=event.get("CommandLine") or event.get("command_line") or "",
                        start_time=current_time,
                        first_seen=current_time,
                        last_seen=current_time
                    )
                    
                    # Extract parent information
                    parent_pid = None
                    parent_guid = None
                    
                    # Try ParentProcessGuid first (most reliable)
                    parent_guid = event.get("ParentProcessGuid") or event.get("parent_process_guid")
                    if parent_guid:
                        # Check if parent is observed
                        if parent_guid in self.processes:
                            parent_node = self.processes[parent_guid]
                            parent_pid = parent_node.pid
                            node.parent_guid = parent_guid
                            node.parent_pid = parent_pid
                            node.parent_image = parent_node.image_path
                            # Link child to parent
                            parent_node.children.add(process_guid)
                        else:
                            # Parent referenced but not observed - will handle below
                            pass
                    
                    # Fallback to ParentProcessId if ParentProcessGuid not available
                    if not parent_pid:
                        parent_pid_raw = event.get("ParentProcessId") or event.get("parent_process_id") or event.get("ParentPID")
                        if parent_pid_raw:
                            try:
                                parent_pid = int(parent_pid_raw)
                                # Try to find parent by PID (best-effort, handles PID reuse)
                                if parent_pid in self.pid_to_guid:
                                    potential_parent_guid = self.pid_to_guid[parent_pid]
                                    if potential_parent_guid in self.processes:
                                        parent_node = self.processes[potential_parent_guid]
                                        # Verify this is still the same process (not PID reuse)
                                        if not parent_node.end_time or (current_time - parent_node.end_time) < 5:
                                            node.parent_guid = potential_parent_guid
                                            node.parent_pid = parent_pid
                                            node.parent_image = parent_node.image_path
                                            parent_node.children.add(process_guid)
                                        else:
                                            # PID was reused, parent is missing
                                            parent_pid = None
                                    else:
                                        # GUID mapping exists but process is gone
                                        parent_pid = None
                                else:
                                    # Parent PID not in our observed processes
                                    pass
                            except (ValueError, TypeError):
                                parent_pid = None
                    
                    # If we have a parent_pid but couldn't link to observed process
                    if parent_pid and not node.parent_guid:
                        # Check if this parent was already referenced
                        if parent_pid in self.referenced_parents:
                            ref_parent = self.referenced_parents[parent_pid]
                            ref_parent.child_process_guids.add(process_guid)
                        else:
                            # Register as referenced-only parent
                            reason = self._determine_missing_parent_reason(parent_pid, current_time)
                            self.referenced_parents[parent_pid] = ReferencedOnlyParent(
                                pid=parent_pid,
                                first_seen_time=current_time,
                                child_process_guids={process_guid},
                                reason=reason
                            )
                            logger.debug(f"Registered referenced-only parent PID {parent_pid} for child {process_guid} (reason: {reason.value})")
                        
                        # Store parent_pid reference even though parent is unobserved
                        node.parent_pid = parent_pid
                    
                    # Register the process
                    self.processes[process_guid] = node
                    self.guid_to_node[process_guid] = node
                    self.pid_to_guid[pid] = process_guid  # Best-effort mapping
                    
                    # Check if this process resolves a previously referenced parent
                    if pid in self.referenced_parents:
                        ref_parent = self.referenced_parents[pid]
                        if not ref_parent.resolved:
                            ref_parent.resolved = True
                            logger.debug(f"Process {process_guid} (PID {pid}) resolved previously referenced parent")
                
                else:
                    # Update existing process node
                    node = self.processes[process_guid]
                    node.last_seen = current_time
                    if not node.image_path:
                        node.image_path = event.get("Image") or event.get("image") or ""
                    if not node.command_line:
                        node.command_line = event.get("CommandLine") or event.get("command_line") or ""
                    
                    # Update PID mapping if PID changed (shouldn't happen, but handle it)
                    if node.pid != pid:
                        logger.warning(f"ProcessGuid {process_guid} PID changed from {node.pid} to {pid}")
                        node.pid = pid
                        self.pid_to_guid[pid] = process_guid
                
        except Exception as e:
            logger.debug(f"Error adding event to genealogy: {event.get('EventID', 'unknown')}: {e}")
    
    def build_genealogy(self, pid: int, max_depth: int = 10) -> Optional[GenealogyTree]:
        """
        Build genealogy tree for a specific PID.
        
        Args:
            pid: Process ID to build genealogy for
            max_depth: Maximum depth to traverse (default 10)
            
        Returns:
            GenealogyTree with ancestors (including unobserved), descendants, and full tree structure
        """
        with self._lock:
            # Find process by PID (best-effort, handles PID reuse)
            process_guid = None
            if pid in self.pid_to_guid:
                potential_guid = self.pid_to_guid[pid]
                if potential_guid in self.processes:
                    process_guid = potential_guid
            
            if not process_guid:
                # Try to find by searching (fallback)
                for guid, node in self.processes.items():
                    if node.pid == pid and not node.end_time:
                        process_guid = guid
                        break
            
            if not process_guid or process_guid not in self.processes:
                return None
            
            root_node = self.processes[process_guid]
            
            # Build ancestor chain (going up) - includes unobserved parents
            ancestors = []
            observed_ancestors = 0
            unobserved_ancestors = 0
            
            current_guid = root_node.parent_guid
            current_pid = root_node.parent_pid
            depth = 0
            
            while (current_guid or current_pid) and depth < max_depth:
                if current_guid and current_guid in self.processes:
                    # Observed parent
                    parent_node = self.processes[current_guid]
                    ancestors.append({
                        "pid": parent_node.pid,
                        "image": parent_node.image_path,
                        "command_line": parent_node.command_line,
                        "process_guid": parent_node.process_guid,
                        "is_unobserved": False
                    })
                    observed_ancestors += 1
                    current_guid = parent_node.parent_guid
                    current_pid = parent_node.parent_pid
                elif current_pid and current_pid in self.referenced_parents:
                    # Unobserved parent (referenced-only)
                    ref_parent = self.referenced_parents[current_pid]
                    ancestors.append({
                        "pid": current_pid,
                        "image": "[Unobserved Parent]",
                        "command_line": "",
                        "process_guid": None,
                        "is_unobserved": True,
                        "reason": ref_parent.reason.value,
                        "first_referenced": ref_parent.first_seen_time
                    })
                    unobserved_ancestors += 1
                    # Try to continue up the chain if we have more info
                    # (unobserved parents don't have parent_guid, so we stop here)
                    break
                elif current_pid:
                    # Parent PID known but not in referenced_parents (edge case)
                    ancestors.append({
                        "pid": current_pid,
                        "image": "[Unobserved Parent]",
                        "command_line": "",
                        "process_guid": None,
                        "is_unobserved": True,
                        "reason": MissingParentReason.UNKNOWN.value,
                        "first_referenced": time.time()
                    })
                    unobserved_ancestors += 1
                    break
                else:
                    break
                
                depth += 1
            
            # Build descendant tree (going down)
            descendants = []
            total_descendants = 0
            
            def collect_descendants(node_guid: str, current_depth: int = 0):
                nonlocal total_descendants
                if current_depth >= max_depth or node_guid not in self.processes:
                    return
                
                node = self.processes[node_guid]
                for child_guid in node.children:
                    if child_guid in self.processes:
                        child_node = self.processes[child_guid]
                        descendants.append({
                            "pid": child_node.pid,
                            "image": child_node.image_path,
                            "command_line": child_node.command_line,
                            "process_guid": child_node.process_guid,
                            "depth": current_depth + 1
                        })
                        total_descendants += 1
                        collect_descendants(child_guid, current_depth + 1)
            
            collect_descendants(process_guid)
            
            # Calculate tree metrics
            tree_depth = len(ancestors) + 1  # Include root
            tree_width = len(root_node.children)
            
            # Build full tree structure for visualization (includes unobserved parents)
            def build_tree_node(node_guid: Optional[str], node_pid: Optional[int], current_depth: int = 0) -> Optional[Dict[str, Any]]:
                if current_depth >= max_depth:
                    return None
                
                if node_guid and node_guid in self.processes:
                    # Observed node
                    node = self.processes[node_guid]
                    tree_node = {
                        "pid": node.pid,
                        "image": node.image_path,
                        "command_line": node.command_line,
                        "process_guid": node.process_guid,
                        "is_unobserved": False,
                        "depth": current_depth,
                        "children": []
                    }
                    
                    # Add children
                    for child_guid in node.children:
                        child_tree = build_tree_node(child_guid, None, current_depth + 1)
                        if child_tree:
                            tree_node["children"].append(child_tree)
                    
                    return tree_node
                elif node_pid and node_pid in self.referenced_parents:
                    # Unobserved parent placeholder
                    ref_parent = self.referenced_parents[node_pid]
                    tree_node = {
                        "pid": node_pid,
                        "image": "[Unobserved Parent]",
                        "command_line": "",
                        "process_guid": None,
                        "is_unobserved": True,
                        "reason": ref_parent.reason.value,
                        "depth": current_depth,
                        "children": []
                    }
                    
                    # Add children (they should be observed)
                    for child_guid in ref_parent.child_process_guids:
                        if child_guid in self.processes:
                            child_tree = build_tree_node(child_guid, None, current_depth + 1)
                            if child_tree:
                                tree_node["children"].append(child_tree)
                    
                    return tree_node
                
                return None
            
            full_tree = build_tree_node(process_guid, None)
            
            return GenealogyTree(
                root_pid=pid,
                root_process_guid=process_guid,
                tree_depth=tree_depth,
                tree_width=tree_width,
                total_descendants=total_descendants,
                observed_ancestors=observed_ancestors,
                unobserved_ancestors=unobserved_ancestors,
                ancestors=ancestors,
                descendants=descendants,
                full_tree=full_tree or {}
            )
    
    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get process information for a PID"""
        with self._lock:
            # Find by PID
            process_guid = None
            if pid in self.pid_to_guid:
                potential_guid = self.pid_to_guid[pid]
                if potential_guid in self.processes:
                    process_guid = potential_guid
            
            if not process_guid:
                return None
            
            node = self.processes[process_guid]
            return {
                "pid": pid,
                "process_guid": node.process_guid,
                "image": node.image_path,
                "command_line": node.command_line,
                "parent_pid": node.parent_pid,
                "parent_guid": node.parent_guid,
                "parent_image": node.parent_image,
                "children_count": len(node.children),
                "children": list(node.children)
            }
    
    def cleanup_old_processes(self) -> None:
        """Cleanup processes older than cleanup_sec"""
        current_time = time.time()
        with self._lock:
            to_remove = []
            for process_guid, node in self.processes.items():
                if current_time - node.last_seen > self.cleanup_sec:
                    # Mark as ended
                    if not node.end_time:
                        node.end_time = current_time
                    to_remove.append(process_guid)
            
            for process_guid in to_remove:
                node = self.processes.pop(process_guid, None)
                if node:
                    self.guid_to_node.pop(process_guid, None)
                    # Clean up PID mapping if this was the last process with this PID
                    if node.pid in self.pid_to_guid and self.pid_to_guid[node.pid] == process_guid:
                        self.pid_to_guid.pop(node.pid, None)
            
            # Clean up old referenced parents (older than cleanup_sec and resolved)
            to_remove_refs = []
            for pid, ref_parent in self.referenced_parents.items():
                if (current_time - ref_parent.first_seen_time > self.cleanup_sec and 
                    ref_parent.resolved):
                    to_remove_refs.append(pid)
            
            for pid in to_remove_refs:
                self.referenced_parents.pop(pid, None)
            
            if to_remove or to_remove_refs:
                logger.debug(f"Cleaned up {len(to_remove)} old processes and {len(to_remove_refs)} referenced parents from genealogy")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get genealogy metrics"""
        with self._lock:
            return {
                "total_processes_tracked": len(self.processes),
                "total_referenced_parents": len(self.referenced_parents),
                "unresolved_parents": sum(1 for rp in self.referenced_parents.values() if not rp.resolved),
                "total_guid_mappings": len(self.pid_to_guid),
                "window_sec": self.window_sec,
                "cleanup_sec": self.cleanup_sec
            }
