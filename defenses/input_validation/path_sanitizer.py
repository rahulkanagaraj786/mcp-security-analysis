"""
Path Sanitizer for File Operations

This module provides path validation and sanitization to prevent path traversal
attacks. It ensures that file paths stay within allowed directories and blocks
malicious path sequences.

Path traversal attacks exploit servers that don't validate file paths, allowing
attackers to access files outside intended directories using sequences like ../
or absolute paths.
"""

from pathlib import Path
from typing import Tuple, Optional
import os


class PathSanitizer:
    """
    Sanitizes and validates file paths to prevent path traversal attacks.
    
    Ensures that all file operations stay within the allowed directory
    by normalizing paths and checking that resolved paths don't escape
    the base directory.
    """
    
    def __init__(self, base_directory: str = "files", strict_mode: bool = True):
        """
        Initialize the path sanitizer.
        
        Args:
            base_directory: The base directory where files are allowed.
                          All file operations must stay within this directory.
            strict_mode: If True, blocks all suspicious paths.
                        If False, only logs warnings.
        """
        self.base_directory = Path(base_directory).resolve()
        self.strict_mode = strict_mode
        
        # Ensure base directory exists
        self.base_directory.mkdir(parents=True, exist_ok=True)
        
        print(f"[PathSanitizer] Initialized")
        print(f"  Base directory: {self.base_directory}")
        print(f"  Strict mode: {strict_mode}")
    
    def is_path_traversal(self, filepath: str) -> bool:
        """
        Check if a path contains traversal sequences.
        
        Args:
            filepath: The file path to check
            
        Returns:
            True if path contains traversal sequences
        """
        if not filepath:
            return False
        
        path_str = str(filepath)
        
        # Check for common traversal patterns
        traversal_patterns = [
            '..',           # Basic traversal
            '../',          # Unix traversal
            '..\\',         # Windows traversal
            '/',            # Absolute path (Unix)
            '\\',           # Absolute path (Windows, or escape)
        ]
        
        # Check if path starts with absolute path
        if path_str.startswith('/') or (len(path_str) > 1 and path_str[1] == ':'):
            return True
        
        # Check for traversal sequences
        if '..' in path_str:
            return True
        
        # Check for encoded traversal (basic check)
        encoded_patterns = [
            '%2e%2e',      # URL encoded ..
            '%2e%2e%2f',   # URL encoded ../
            '..%2f',       # Mixed encoding
            '%252e%252e',  # Double encoded
        ]
        path_lower = path_str.lower()
        for pattern in encoded_patterns:
            if pattern in path_lower:
                return True
        
        return False
    
    def normalize_path(self, filepath: str) -> Path:
        """
        Normalize a file path relative to the base directory.
        
        Args:
            filepath: The file path to normalize
            
        Returns:
            Normalized Path object
        """
        # Remove leading slashes and normalize
        normalized = filepath.lstrip('/').lstrip('\\')
        
        # Create path relative to base directory
        # This prevents traversal by joining with base first
        safe_path = self.base_directory / normalized
        
        # Resolve to get absolute path (removes .. sequences)
        resolved = safe_path.resolve()
        
        return resolved
    
    def is_within_base_directory(self, resolved_path: Path) -> bool:
        """
        Check if a resolved path is within the base directory.
        
        Args:
            resolved_path: The resolved absolute path to check
            
        Returns:
            True if path is within base directory
        """
        try:
            # Check if resolved path is within base directory
            # Use resolve() on both to ensure absolute paths
            base_resolved = self.base_directory.resolve()
            path_resolved = Path(resolved_path).resolve()
            
            # Check if the resolved path is a subpath of base
            # Using commonpath to check if they share a common ancestor
            try:
                common = os.path.commonpath([base_resolved, path_resolved])
                return common == str(base_resolved)
            except ValueError:
                # Paths on different drives (Windows) or invalid
                return False
        except Exception:
            return False
    
    def sanitize_path(self, filepath: str) -> Tuple[bool, Optional[Path], str]:
        """
        Sanitize and validate a file path.
        
        Args:
            filepath: The file path to sanitize
            
        Returns:
            Tuple of (is_safe, sanitized_path, message)
            - is_safe: True if path is safe to use
            - sanitized_path: The sanitized Path object (None if unsafe)
            - message: Explanation message
        """
        if not filepath:
            return False, None, "Empty file path provided"
        
        # Check for traversal patterns
        if self.is_path_traversal(filepath):
            if self.strict_mode:
                return False, None, f"Path traversal detected in path: {filepath}. Paths containing '..', absolute paths, or encoded traversal sequences are not allowed."
            else:
                # Warning mode - still normalize but warn
                print(f"[PathSanitizer] WARNING: Suspicious path detected: {filepath}")
        
        # Normalize the path
        try:
            normalized = self.normalize_path(filepath)
        except Exception as e:
            return False, None, f"Error normalizing path: {e}"
        
        # Check if normalized path is within base directory
        if not self.is_within_base_directory(normalized):
            if self.strict_mode:
                return False, None, f"Path resolves outside allowed directory. Requested: {filepath}, Resolved: {normalized}, Base: {self.base_directory}"
            else:
                print(f"[PathSanitizer] WARNING: Path resolves outside base directory: {normalized}")
                return True, normalized, f"Warning: Path resolves outside base directory"
        
        return True, normalized, "Path is safe"
    
    def validate_file_operation(self, filepath: str, operation: str = "read") -> Tuple[bool, Optional[Path], str]:
        """
        Validate a file operation path.
        
        Args:
            filepath: The file path to validate
            operation: The operation type ("read", "write", "delete")
            
        Returns:
            Tuple of (is_allowed, sanitized_path, message)
        """
        is_safe, sanitized_path, message = self.sanitize_path(filepath)
        
        if not is_safe:
            return False, None, f"File {operation} blocked: {message}"
        
        return True, sanitized_path, f"File {operation} allowed: {message}"
    
    def get_allowed_directory(self) -> Path:
        """
        Get the allowed base directory.
        
        Returns:
            Path to the base directory
        """
        return self.base_directory


def create_path_sanitizer(base_directory: str = "files", strict_mode: bool = True) -> PathSanitizer:
    """
    Create a path sanitizer instance.
    
    Args:
        base_directory: The base directory where files are allowed
        strict_mode: If True, blocks suspicious paths
        
    Returns:
        PathSanitizer instance
    """
    return PathSanitizer(base_directory, strict_mode)

