"""
Storage Manager for MCP Server
Handles cache and file storage operations

INTENTIONALLY VULNERABLE - No validation or sanitization
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime


class StorageManager:
    """
    Manages in-memory cache and file system storage for MCP server
    
    VULNERABILITIES:
    - No input validation
    - No path sanitization (path traversal possible)
    - No content sanitization (XSS/injection possible)
    - No size limits (DoS possible)
    """
    
    def __init__(self, cache_dir: str = "cache", files_dir: str = "files"):
        self.cache: Dict[str, Any] = {}
        self.cache_dir = Path(cache_dir)
        self.files_dir = Path(files_dir)
        
        # Create directories if they don't exist
        self.cache_dir.mkdir(exist_ok=True)
        self.files_dir.mkdir(exist_ok=True)
        
        print(f"[StorageManager] Initialized")
        print(f"  Cache dir: {self.cache_dir.absolute()}")
        print(f"  Files dir: {self.files_dir.absolute()}")
    
    # ==================== CACHE OPERATIONS ====================
    
    def set_cache(self, key: str, value: Any) -> bool:
        """
        Store value in cache
        
        VULNERABILITY: No validation of key or value
        Can store malicious XSS, prompt injection, etc.
        """
        try:
            self.cache[key] = {
                "value": value,
                "timestamp": datetime.now().isoformat()
            }
            print(f"[Cache] SET: {key}")
            return True
        except Exception as e:
            print(f"[Cache] ERROR setting {key}: {e}")
            return False
    
    def get_cache(self, key: str) -> Optional[Any]:
        """
        Retrieve value from cache
        
        VULNERABILITY: Returns unsanitized data
        XSS, prompt injection can be served to clients
        """
        if key in self.cache:
            print(f"[Cache] GET: {key} (hit)")
            return self.cache[key]["value"]
        else:
            print(f"[Cache] GET: {key} (miss)")
            return None
    
    def delete_cache(self, key: str) -> bool:
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
            print(f"[Cache] DELETE: {key}")
            return True
        return False
    
    def clear_cache(self) -> None:
        """Clear all cache"""
        self.cache.clear()
        print(f"[Cache] CLEARED")
    
    def list_cache_keys(self) -> list:
        """List all cache keys"""
        return list(self.cache.keys())
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "total_keys": len(self.cache),
            "keys": list(self.cache.keys()),
            "total_size_bytes": len(json.dumps(self.cache))
        }
    
    # ==================== FILE OPERATIONS ====================
    
    def write_file(self, filepath: str, content: str) -> bool:
        """
        Write content to file
        
        VULNERABILITY: No path validation or sanitization
        Path traversal possible: ../../.ssh/authorized_keys
        """
        try:
            # VULNERABLE: Directly use user-provided path
            full_path = self.files_dir / filepath
            
            print(f"[Files] WRITE: {filepath}")
            print(f"  Full path: {full_path.absolute()}")
            
            # Create parent directories if needed
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file (no validation!)
            full_path.write_text(content)
            
            print(f"  ✓ Written {len(content)} bytes")
            return True
            
        except Exception as e:
            print(f"[Files] ERROR writing {filepath}: {e}")
            return False
    
    def read_file(self, filepath: str) -> Optional[str]:
        """
        Read file content
        
        VULNERABILITY: No path validation
        Can read arbitrary files on system
        """
        try:
            full_path = self.files_dir / filepath
            
            print(f"[Files] READ: {filepath}")
            print(f"  Full path: {full_path.absolute()}")
            
            if full_path.exists():
                content = full_path.read_text()
                print(f"  ✓ Read {len(content)} bytes")
                return content
            else:
                print(f"  ✗ File not found")
                return None
                
        except Exception as e:
            print(f"[Files] ERROR reading {filepath}: {e}")
            return None
    
    def delete_file(self, filepath: str) -> bool:
        """Delete file"""
        try:
            full_path = self.files_dir / filepath
            
            if full_path.exists():
                full_path.unlink()
                print(f"[Files] DELETE: {filepath}")
                return True
            return False
            
        except Exception as e:
            print(f"[Files] ERROR deleting {filepath}: {e}")
            return False
    
    def list_files(self, directory: str = ".") -> list:
        """
        List files in directory
        
        VULNERABILITY: No path validation
        Can list arbitrary directories
        """
        try:
            dir_path = self.files_dir / directory
            
            if not dir_path.exists():
                return []
            
            files = []
            for item in dir_path.rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(self.files_dir)
                    files.append(str(rel_path))
            
            print(f"[Files] LIST: {directory} ({len(files)} files)")
            return files
            
        except Exception as e:
            print(f"[Files] ERROR listing {directory}: {e}")
            return []
    
    def get_file_stats(self) -> Dict[str, Any]:
        """Get file system statistics"""
        files = self.list_files()
        total_size = sum(
            (self.files_dir / f).stat().st_size 
            for f in files 
            if (self.files_dir / f).exists()
        )
        
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "files": files
        }
    
    # ==================== COMBINED OPERATIONS ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get overall storage statistics"""
        return {
            "cache": self.get_cache_stats(),
            "files": self.get_file_stats()
        }
    
    def clear_all(self) -> None:
        """Clear all cache and files (for testing)"""
        self.clear_cache()
        
        # Delete all files
        for file in self.list_files():
            self.delete_file(file)
        
        print(f"[Storage] ALL DATA CLEARED")


# Global instance
storage = StorageManager()