"""
Graph Analytics for Stage 4

Analyzes process relationships, network connections, and file access patterns
to detect anomalous behavior through graph-based analysis.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("stage4_graph_analyzer")

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logger.warning("NetworkX not available. Install with: pip install networkx")


@dataclass
class ProcessNode:
    """Represents a process in the graph"""
    pid: int
    image_path: str
    start_time: float
    parent_pid: Optional[int] = None
    command_line: str = ""
    children: Set[int] = field(default_factory=set)
    network_connections: Set[Tuple[str, int]] = field(default_factory=set)  # (ip, port)
    files_accessed: Set[str] = field(default_factory=set)
    last_seen: float = field(default_factory=time.time)


@dataclass
class GraphMetrics:
    """Metrics extracted from graph analysis"""
    process_tree_depth: int = 0
    process_tree_width: int = 0
    total_descendants: int = 0
    network_degree: int = 0
    file_access_degree: int = 0
    centrality_score: float = 0.0
    clustering_coefficient: float = 0.0
    relationship_anomaly_score: float = 0.0
    isolated_process: bool = False
    unusual_parent: bool = False
    unusual_spawning_pattern: bool = False


class GraphAnalyzer:
    """
    Graph-based analysis for ransomware detection.
    
    Builds and analyzes:
    - Process tree graphs (parent-child relationships)
    - Network graphs (process-to-process via network)
    - File access graphs (process-to-file relationships)
    """
    
    def __init__(self, window_sec: int = 3600, cleanup_sec: int = 7200):
        """
        Initialize Graph Analyzer.
        
        Args:
            window_sec: Time window for graph analysis (default 1 hour)
            cleanup_sec: Cleanup processes older than this (default 2 hours)
        """
        self.window_sec = window_sec
        self.cleanup_sec = cleanup_sec
        
        # Process nodes
        self.processes: Dict[int, ProcessNode] = {}
        
        # Graph structures (if NetworkX available)
        self.process_graph = None
        self.network_graph = None
        self.file_graph = None
        
        if NETWORKX_AVAILABLE:
            self.process_graph = nx.DiGraph()  # Directed for parent-child
            self.network_graph = nx.Graph()    # Undirected for network connections
            self.file_graph = nx.Graph()       # Undirected for file access
        
        logger.info("GraphAnalyzer initialized")
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the graph and update relationships"""
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
            
            # Get or create process node
            if pid not in self.processes:
                self.processes[pid] = ProcessNode(
                    pid=pid,
                    image_path=event.get("Image") or event.get("image") or "",
                    start_time=time.time(),
                    parent_pid=event.get("ParentProcessId") or event.get("parent_process_id"),
                    command_line=event.get("CommandLine") or event.get("command_line") or ""
                )
                if NETWORKX_AVAILABLE:
                    self.process_graph.add_node(pid, **{
                        'image': self.processes[pid].image_path,
                        'start_time': self.processes[pid].start_time
                    })
            
            node = self.processes[pid]
            node.last_seen = time.time()
            
            # Update parent-child relationships
            # Priority 1: Use genealogy data from Stage 3 if available (more complete)
            stage3_genealogy = event.get("__stage3_genealogy")
            if stage3_genealogy and stage3_genealogy.get("ancestors"):
                # Use parent from genealogy (most accurate)
                ancestors = stage3_genealogy.get("ancestors", [])
                if ancestors:
                    parent_pid = ancestors[0].get("pid")  # First ancestor is direct parent
                    if parent_pid and parent_pid != pid:
                        node.parent_pid = parent_pid
                        if parent_pid in self.processes:
                            self.processes[parent_pid].children.add(pid)
                        if NETWORKX_AVAILABLE:
                            self.process_graph.add_edge(parent_pid, pid)
            
            # Priority 2: Fallback to direct parent fields from event
            if not node.parent_pid:
                parent_pid = event.get("ParentProcessId") or event.get("parent_process_id")
                if parent_pid:
                    try:
                        parent_pid = int(parent_pid)
                        if parent_pid != pid:
                            node.parent_pid = parent_pid
                            if parent_pid in self.processes:
                                self.processes[parent_pid].children.add(pid)
                            if NETWORKX_AVAILABLE:
                                self.process_graph.add_edge(parent_pid, pid)
                    except (ValueError, TypeError):
                        pass
            
            # Update network connections
            if "NETWORK" in str(event.get("type", "")).upper() or event.get("EventID") == 3:
                dest_ip = event.get("DestinationIp") or event.get("destination_ip") or ""
                dest_port = event.get("DestinationPort") or event.get("destination_port") or 0
                if dest_ip and dest_port:
                    node.network_connections.add((dest_ip, dest_port))
                    if NETWORKX_AVAILABLE:
                        # Connect processes that communicate with same IP/port
                        for other_pid, other_node in self.processes.items():
                            if other_pid != pid and (dest_ip, dest_port) in other_node.network_connections:
                                self.network_graph.add_edge(pid, other_pid, ip=dest_ip, port=dest_port)
            
            # Update file access
            target_file = event.get("TargetFilename") or event.get("target_filename")
            if target_file:
                node.files_accessed.add(target_file)
                if NETWORKX_AVAILABLE:
                    # Create file node and connect
                    file_id = f"file:{target_file}"
                    self.file_graph.add_node(file_id, type='file', path=target_file)
                    self.file_graph.add_edge(pid, file_id)
            
        except Exception:
            logger.exception(f"Error adding event to graph: {event.get('EventID', 'unknown')}")
    
    def analyze_process(self, pid: int) -> GraphMetrics:
        """
        Analyze a specific process and return graph metrics.
        
        Args:
            pid: Process ID to analyze
            
        Returns:
            GraphMetrics object with analysis results
        """
        if pid not in self.processes:
            return GraphMetrics()
        
        node = self.processes[pid]
        metrics = GraphMetrics()
        
        # Process tree analysis
        metrics.process_tree_depth = self._calculate_tree_depth(pid)
        metrics.process_tree_width = len(node.children)
        metrics.total_descendants = self._count_descendants(pid)
        
        # Network analysis
        metrics.network_degree = len(node.network_connections)
        
        # File access analysis
        metrics.file_access_degree = len(node.files_accessed)
        
        # Graph centrality (if NetworkX available)
        if NETWORKX_AVAILABLE and self.process_graph.has_node(pid):
            try:
                # Calculate centrality in process graph
                if len(self.process_graph) > 1:
                    centrality = nx.degree_centrality(self.process_graph)
                    metrics.centrality_score = centrality.get(pid, 0.0)
                    
                    # Clustering coefficient
                    clustering = nx.clustering(self.process_graph.to_undirected())
                    metrics.clustering_coefficient = clustering.get(pid, 0.0)
            except Exception:
                logger.debug(f"Error calculating graph metrics for PID {pid}")
        
        # Relationship anomaly detection
        metrics.relationship_anomaly_score = self._calculate_relationship_anomaly(pid, node)
        
        # Flags
        metrics.isolated_process = (metrics.network_degree == 0 and 
                                   metrics.file_access_degree == 0 and 
                                   metrics.total_descendants == 0)
        metrics.unusual_parent = self._is_unusual_parent(node)
        metrics.unusual_spawning_pattern = (metrics.total_descendants > 10 or 
                                          metrics.process_tree_width > 5)
        
        return metrics
    
    def _calculate_tree_depth(self, pid: int) -> int:
        """Calculate depth of process tree from this PID"""
        if pid not in self.processes:
            return 0
        
        node = self.processes[pid]
        if not node.children:
            return 0
        
        max_depth = 0
        for child_pid in node.children:
            depth = self._calculate_tree_depth(child_pid)
            max_depth = max(max_depth, depth)
        
        return max_depth + 1
    
    def _count_descendants(self, pid: int) -> int:
        """Count total number of descendant processes"""
        if pid not in self.processes:
            return 0
        
        node = self.processes[pid]
        count = len(node.children)
        for child_pid in node.children:
            count += self._count_descendants(child_pid)
        
        return count
    
    def _calculate_relationship_anomaly(self, pid: int, node: ProcessNode) -> float:
        """
        Calculate relationship anomaly score.
        Higher score = more anomalous relationships.
        """
        score = 0.0
        
        # Unusual parent-child relationship
        if node.parent_pid and node.parent_pid in self.processes:
            parent = self.processes[node.parent_pid]
            # System process spawning user process is suspicious
            if "system32" in parent.image_path.lower() and "users" in node.image_path.lower():
                score += 2.0
        
        # High fan-out (spawning many children)
        if len(node.children) > 5:
            score += min(3.0, len(node.children) * 0.3)
        
        # Isolated process with high activity
        if (len(node.children) == 0 and 
            len(node.network_connections) == 0 and 
            len(node.files_accessed) > 10):
            score += 2.0
        
        # Unusual network patterns
        if len(node.network_connections) > 20:
            score += 1.5
        
        return min(10.0, score)  # Cap at 10.0
    
    def _is_unusual_parent(self, node: ProcessNode) -> bool:
        """Check if process has unusual parent"""
        if not node.parent_pid or node.parent_pid not in self.processes:
            return False
        
        parent = self.processes[node.parent_pid]
        parent_image = parent.image_path.lower()
        child_image = node.image_path.lower()
        
        # System process spawning from user directory
        if "system32" in parent_image and ("users" in child_image or "appdata" in child_image):
            return True
        
        # Unusual parent-child combinations
        suspicious_parents = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
        if any(sp in parent_image for sp in suspicious_parents):
            if "system32" not in child_image:
                return True
        
        return False
    
    def get_process_subgraph(self, pid: int, depth: int = 2) -> Dict[str, Any]:
        """
        Get subgraph around a process (for visualization/analysis).
        
        Args:
            pid: Root process ID
            depth: How many levels deep to include
            
        Returns:
            Dictionary with nodes and edges
        """
        if pid not in self.processes:
            return {"nodes": [], "edges": []}
        
        nodes = []
        edges = []
        visited = set()
        
        def collect_subgraph(current_pid: int, current_depth: int):
            if current_pid in visited or current_depth > depth:
                return
            
            visited.add(current_pid)
            if current_pid in self.processes:
                node = self.processes[current_pid]
                nodes.append({
                    "pid": current_pid,
                    "image": node.image_path,
                    "children_count": len(node.children)
                })
                
                # Add edges to children
                for child_pid in node.children:
                    if child_pid in self.processes:
                        edges.append({
                            "from": current_pid,
                            "to": child_pid,
                            "type": "parent-child"
                        })
                        collect_subgraph(child_pid, current_depth + 1)
        
        collect_subgraph(pid, 0)
        
        return {"nodes": nodes, "edges": edges}
    
    def cleanup_old_processes(self) -> None:
        """Remove processes older than cleanup_sec"""
        now = time.time()
        to_remove = [
            pid for pid, node in self.processes.items()
            if (now - node.last_seen) > self.cleanup_sec
        ]
        
        for pid in to_remove:
            if pid in self.processes:
                del self.processes[pid]
            if NETWORKX_AVAILABLE:
                if self.process_graph.has_node(pid):
                    self.process_graph.remove_node(pid)
                if self.network_graph.has_node(pid):
                    self.network_graph.remove_node(pid)
        
        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} old processes from graph")

