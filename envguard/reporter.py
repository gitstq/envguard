"""
Report Generator for EnvGuard

Generates human-readable and machine-readable security reports.
"""

import json
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from envguard.scanner import ScanResult, Finding
from envguard.rules import Severity


class Reporter:
    """Multi-format security report generator."""
    
    COLORS = {
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "green": "\033[92m",
        "cyan": "\033[96m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }
    
    SEVERITY_ICONS = {
        Severity.CRITICAL: "[!!!]",
        Severity.HIGH: "[!!]",
        Severity.MEDIUM: "[!]",
        Severity.LOW: "[i]",
        Severity.INFO: "[i]",
    }
    
    def __init__(self, use_colors: bool = True, use_emoji: bool = False):
        self.use_colors = use_colors
        self.use_emoji = use_emoji
    
    def format_terminal(
        self,
        results: List[ScanResult],
        show_suggestions: bool = True
    ) -> str:
        """Format results for terminal output."""
        lines: List[str] = []
        
        lines.append(self._header("EnvGuard Security Report"))
        lines.append("")
        
        total_findings = sum(len(r.findings) for r in results)
        total_files = len(results)
        files_with_issues = sum(1 for r in results if r.has_issues)
        
        lines.append(self._bold("Summary:"))
        lines.append(f"  Files scanned: {total_files}")
        lines.append(f"  Files with issues: {files_with_issues}")
        lines.append(f"  Total findings: {total_findings}")
        
        if total_findings > 0:
            critical = sum(r.critical_count for r in results)
            high = sum(r.high_count for r in results)
            medium = sum(r.medium_count for r in results)
            low = sum(r.low_count for r in results)
            
            lines.append("")
            lines.append(self._bold("By Severity:"))
            lines.append(f"  {self._color('red', f'CRITICAL: {critical}')}")
            lines.append(f"  {self._color('yellow', f'HIGH: {high}')}")
            lines.append(f"  {self._color('blue', f'MEDIUM: {medium}')}")
            lines.append(f"  {self._color('cyan', f'LOW: {low}')}")
        
        lines.append("")
        
        for result in results:
            if not result.has_issues:
                continue
            
            lines.append(self._separator())
            lines.append(self._bold(f"File: {result.file_path}"))
            lines.append("")
            
            for finding in result.findings:
                icon = self.SEVERITY_ICONS.get(finding.severity, "[?]")
                severity_str = finding.severity.value.upper()
                severity_colored = self._severity_color(severity_str)
                
                lines.append(f"  {icon} {severity_colored}: {finding.rule_name}")
                lines.append(f"      Line {finding.line_number}: {finding.key} = {finding.value_preview}")
                lines.append(f"      {finding.description}")
                
                if show_suggestions:
                    lines.append(f"      Fix: {finding.fix_suggestion}")
                
                lines.append("")
        
        lines.append(self._separator())
        if total_findings == 0:
            lines.append(self._color("green", "No security issues found!"))
        else:
            lines.append(self._color("red", f"Found {total_findings} potential security issues!"))
            lines.append("")
            lines.append("Review the findings above and take action to secure your environment variables.")
        
        return "\n".join(lines)
    
    def format_json(
        self,
        results: List[ScanResult],
        pretty: bool = True
    ) -> str:
        """Format results as JSON."""
        output = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "files_scanned": len(results),
                "files_with_issues": sum(1 for r in results if r.has_issues),
                "total_findings": sum(len(r.findings) for r in results),
                "by_severity": {
                    "critical": sum(r.critical_count for r in results),
                    "high": sum(r.high_count for r in results),
                    "medium": sum(r.medium_count for r in results),
                    "low": sum(r.low_count for r in results),
                    "info": sum(r.info_count for r in results),
                }
            },
            "results": [
                {
                    "file": r.file_path,
                    "lines_scanned": r.lines_scanned,
                    "variables_found": r.variables_found,
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "rule_name": f.rule_name,
                            "severity": f.severity.value,
                            "key": f.key,
                            "value_preview": f.value_preview,
                            "line_number": f.line_number,
                            "description": f.description,
                            "fix_suggestion": f.fix_suggestion,
                        }
                        for f in r.findings
                    ]
                }
                for r in results
            ]
        }
        
        indent = 2 if pretty else None
        return json.dumps(output, indent=indent, ensure_ascii=False)
    
    def format_markdown(
        self,
        results: List[ScanResult],
        title: str = "EnvGuard Security Report"
    ) -> str:
        """Format results as Markdown."""
        lines: List[str] = []
        
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        total_findings = sum(len(r.findings) for r in results)
        critical = sum(r.critical_count for r in results)
        high = sum(r.high_count for r in results)
        medium = sum(r.medium_count for r in results)
        
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Files Scanned | {len(results)} |")
        lines.append(f"| Files with Issues | {sum(1 for r in results if r.has_issues)} |")
        lines.append(f"| Total Findings | {total_findings} |")
        lines.append(f"| **CRITICAL** | {critical} |")
        lines.append(f"| **HIGH** | {high} |")
        lines.append(f"| **MEDIUM** | {medium} |")
        lines.append("")
        
        if total_findings > 0:
            lines.append("## Findings")
            lines.append("")
            
            for result in results:
                if not result.has_issues:
                    continue
                
                lines.append(f"### {result.file_path}")
                lines.append("")
                
                for finding in result.findings:
                    severity_badge = f"`{finding.severity.value.upper()}`"
                    lines.append(f"#### {severity_badge} {finding.rule_name}")
                    lines.append("")
                    lines.append(f"- **Line:** {finding.line_number}")
                    lines.append(f"- **Variable:** `{finding.key}`")
                    lines.append(f"- **Description:** {finding.description}")
                    lines.append(f"- **Fix:** {finding.fix_suggestion}")
                    lines.append("")
        
        return "\n".join(lines)
    
    def format_sarif(self, results: List[ScanResult]) -> str:
        """Format results as SARIF."""
        rules = []
        rule_ids = set()
        
        for result in results:
            for finding in result.findings:
                if finding.rule_id not in rule_ids:
                    rule_ids.add(finding.rule_id)
                    rules.append({
                        "id": finding.rule_id,
                        "name": finding.rule_name,
                        "shortDescription": {
                            "text": finding.description
                        },
                        "helpUri": f"https://github.com/gitstq/envguard/wiki/{finding.rule_id}",
                        "properties": {
                            "severity": finding.severity.value
                        }
                    })
        
        sarif_results = []
        for result in results:
            for finding in result.findings:
                sarif_results.append({
                    "ruleId": finding.rule_id,
                    "level": self._severity_to_sarif_level(finding.severity),
                    "message": {
                        "text": f"{finding.description} Variable: {finding.key}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.file_path
                                },
                                "region": {
                                    "startLine": finding.line_number
                                }
                            }
                        }
                    ]
                })
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "EnvGuard",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/gitstq/envguard",
                            "rules": rules
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
        
        return json.dumps(sarif, indent=2, ensure_ascii=False)
    
    def _header(self, text: str) -> str:
        if self.use_colors:
            return f"{self.COLORS['bold']}{self.COLORS['cyan']}{text}{self.COLORS['reset']}"
        return text
    
    def _bold(self, text: str) -> str:
        if self.use_colors:
            return f"{self.COLORS['bold']}{text}{self.COLORS['reset']}"
        return text
    
    def _color(self, color: str, text: str) -> str:
        if self.use_colors and color in self.COLORS:
            return f"{self.COLORS[color]}{text}{self.COLORS['reset']}"
        return text
    
    def _severity_color(self, severity: str) -> str:
        colors = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "cyan",
            "INFO": "cyan",
        }
        return self._color(colors.get(severity, "cyan"), severity)
    
    def _separator(self) -> str:
        return "-" * 60
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")
