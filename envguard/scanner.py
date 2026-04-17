"""
Environment File Scanner for EnvGuard

Scans .env files for sensitive information using security rules.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
from envguard.rules import SecurityRule, SecurityRules, Severity


@dataclass
class Finding:
    """Single security finding"""
    rule_id: str
    rule_name: str
    severity: Severity
    key: str
    value_preview: str
    line_number: int
    description: str
    fix_suggestion: str
    file_path: str


@dataclass  
class ScanResult:
    """Complete scan result for a file"""
    file_path: str
    findings: List[Finding]
    lines_scanned: int
    variables_found: int
    
    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
    
    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


class EnvScanner:
    """
    Scanner for environment files.
    
    Features:
    - Multiple file format support (.env, .env.local, .env.production, etc.)
    - Pattern-based detection
    - Key name analysis
    - Value pattern matching
    - Severity classification
    """
    
    # Default file patterns to scan
    DEFAULT_PATTERNS = [
        ".env",
        ".env.local",
        ".env.development",
        ".env.test",
        ".env.production",
        ".env.staging",
        ".env.*",
    ]
    
    # Directories to skip
    SKIP_DIRS = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".env",
        "dist",
        "build",
        ".tox",
        ".pytest_cache",
    }
    
    def __init__(
        self,
        rules: Optional[List[SecurityRule]] = None,
        max_value_preview: int = 20
    ):
        self.rules = rules or SecurityRules.RULES
        self.max_value_preview = max_value_preview
    
    def scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single .env file."""
        findings: List[Finding] = []
        lines_scanned = 0
        variables_found = 0
        
        if not file_path.exists():
            return ScanResult(
                file_path=str(file_path),
                findings=[],
                lines_scanned=0,
                variables_found=0
            )
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            
            for line_num, line in enumerate(lines, start=1):
                lines_scanned += 1
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                
                parsed = self._parse_env_line(stripped)
                if not parsed:
                    continue
                
                key, value = parsed
                variables_found += 1
                
                for rule in self.rules:
                    if self._matches_rule(rule, key, value):
                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            key=key,
                            value_preview=self._preview_value(value),
                            line_number=line_num,
                            description=rule.description,
                            fix_suggestion=rule.fix_suggestion,
                            file_path=str(file_path)
                        ))
                        break
            
        except Exception as e:
            pass
        
        return ScanResult(
            file_path=str(file_path),
            findings=findings,
            lines_scanned=lines_scanned,
            variables_found=variables_found
        )
    
    def scan_directory(
        self,
        directory: Path,
        patterns: Optional[List[str]] = None,
        recursive: bool = True
    ) -> List[ScanResult]:
        """Scan a directory for .env files."""
        patterns = patterns or self.DEFAULT_PATTERNS
        results: List[ScanResult] = []
        directory = Path(directory)
        
        if not directory.exists():
            return results
        
        for root, dirs, files in os.walk(directory):
            if not recursive:
                dirs.clear()
            else:
                dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            
            for filename in files:
                if self._matches_pattern(filename, patterns):
                    file_path = Path(root) / filename
                    result = self.scan_file(file_path)
                    results.append(result)
        
        return results
    
    def _parse_env_line(self, line: str) -> Optional[Tuple[str, str]]:
        """Parse a single env line into key-value pair."""
        eq_pos = line.find("=")
        if eq_pos == -1:
            return None
        
        key = line[:eq_pos].strip()
        value = line[eq_pos + 1:].strip()
        
        if not key:
            return None
        
        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
        
        return key, value
    
    def _matches_rule(self, rule: SecurityRule, key: str, value: str) -> bool:
        """Check if key-value matches any rule pattern"""
        for pattern in rule.key_patterns:
            if pattern.search(key):
                return True
        
        for pattern in rule.patterns:
            if pattern.search(value):
                return True
        
        return False
    
    def _preview_value(self, value: str) -> str:
        """Create a preview of the value (hidden for security)"""
        if len(value) <= self.max_value_preview:
            return "*" * len(value)
        return "*" * self.max_value_preview + "..."
    
    def _matches_pattern(self, filename: str, patterns: List[str]) -> bool:
        """Check if filename matches any pattern"""
        for pattern in patterns:
            if pattern.startswith("*."):
                if filename.endswith(pattern[1:]):
                    return True
            elif pattern.endswith(".*"):
                if filename.startswith(pattern[:-1]):
                    return True
            elif filename == pattern:
                return True
        return False


def find_env_files(
    directory: Path,
    patterns: Optional[List[str]] = None
) -> List[Path]:
    """Find all .env files in a directory."""
    patterns = patterns or EnvScanner.DEFAULT_PATTERNS
    files: List[Path] = []
    directory = Path(directory)
    
    if not directory.exists():
        return files
    
    for root, dirs, filenames in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EnvScanner.SKIP_DIRS]
        
        for filename in filenames:
            for pattern in patterns:
                if pattern.startswith("*."):
                    if filename.endswith(pattern[1:]):
                        files.append(Path(root) / filename)
                        break
                elif pattern.endswith(".*"):
                    if filename.startswith(pattern[:-1]):
                        files.append(Path(root) / filename)
                        break
                elif filename == pattern:
                    files.append(Path(root) / filename)
                    break
    
    return files
