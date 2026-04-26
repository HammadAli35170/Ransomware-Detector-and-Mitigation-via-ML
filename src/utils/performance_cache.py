"""
Performance Cache for Expensive Operations

Provides caching with TTL for expensive operations like file system queries,
process lookups, and feature calculations.
"""

import time
import threading
from typing import Dict, Any, Optional, Callable, TypeVar, Hashable
from functools import wraps
from collections import OrderedDict

T = TypeVar('T')


class TTLCache:
    """
    Thread-safe TTL cache with size limit and automatic expiration.
    """
    
    def __init__(self, maxsize: int = 1000, ttl: float = 300.0):
        """
        Args:
            maxsize: Maximum number of items in cache
            ttl: Time-to-live in seconds (default 5 minutes)
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self._cache: Dict[Hashable, tuple] = {}  # key -> (value, timestamp)
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: Hashable) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    self._hits += 1
                    return value
                else:
                    # Expired, remove it
                    del self._cache[key]
            
            self._misses += 1
            return None
    
    def set(self, key: Hashable, value: Any) -> None:
        """Set value in cache"""
        with self._lock:
            # Remove oldest if at capacity
            if len(self._cache) >= self.maxsize and key not in self._cache:
                # Remove oldest item
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            
            self._cache[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def cleanup_expired(self) -> int:
        """Remove expired entries, returns count of removed entries"""
        now = time.time()
        removed = 0
        
        with self._lock:
            expired_keys = [
                key for key, (_, timestamp) in self._cache.items()
                if now - timestamp >= self.ttl
            ]
            for key in expired_keys:
                del self._cache[key]
                removed += 1
        
        return removed
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 2),
                "ttl_sec": self.ttl
            }


# Global caches for common operations
_process_info_cache = TTLCache(maxsize=5000, ttl=60.0)  # Process info: 1 minute TTL
_file_stat_cache = TTLCache(maxsize=10000, ttl=300.0)   # File stats: 5 minutes TTL
_feature_cache = TTLCache(maxsize=1000, ttl=30.0)       # Feature vectors: 30 seconds TTL


def cached_process_info(ttl: float = 60.0):
    """Decorator to cache process information lookups"""
    def decorator(func: Callable[[int], Optional[Dict[str, Any]]]):
        @wraps(func)
        def wrapper(pid: int) -> Optional[Dict[str, Any]]:
            cache_key = f"process_{pid}"
            cached = _process_info_cache.get(cache_key)
            if cached is not None:
                return cached
            
            result = func(pid)
            if result is not None:
                _process_info_cache.set(cache_key, result)
            return result
        return wrapper
    return decorator


def cached_file_stat(ttl: float = 300.0):
    """Decorator to cache file system operations"""
    def decorator(func: Callable[[str], Optional[Any]]):
        @wraps(func)
        def wrapper(filepath: str) -> Optional[Any]:
            cache_key = f"file_{filepath}"
            cached = _file_stat_cache.get(cache_key)
            if cached is not None:
                return cached
            
            result = func(filepath)
            if result is not None:
                _file_stat_cache.set(cache_key, result)
            return result
        return wrapper
    return decorator


def get_cache_stats() -> Dict[str, Dict[str, Any]]:
    """Get statistics for all caches"""
    return {
        "process_info": _process_info_cache.get_stats(),
        "file_stat": _file_stat_cache.get_stats(),
        "feature": _feature_cache.get_stats()
    }


def cleanup_all_caches() -> Dict[str, int]:
    """Cleanup expired entries in all caches"""
    return {
        "process_info": _process_info_cache.cleanup_expired(),
        "file_stat": _file_stat_cache.cleanup_expired(),
        "feature": _feature_cache.cleanup_expired()
    }

