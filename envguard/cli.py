"""
Command-Line Interface for EnvGuard
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional
from envguard.scanner import EnvScanner, ScanResult, find_env_files
from envguard.reporter import Reporter
from envguard.rules import Severity
from envguard import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Environment Variable Security Auditor - Detect sensitive info in .env files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  envguard scan                    Scan current directory
  envguard scan ./myproject        Scan specific directory
  envguard scan .env .env.local    Scan specific files
  envguard scan -f json            Output as JSON
  envguard scan -o report.md       Save report to file
  envguard scan --severity high    Show only HIGH and CRITICAL issues

For more information, visit: https://github.com/gitstq/envguard
        """
    )
    
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available commands"
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan .env files for security issues"
    )
    scan_parser.add_argument(
        "path",
        nargs="*",
        default=["."],
        help="Path to scan (file or directory, default: current directory)"
    )
    scan_parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help="Scan directories recursively (default: True)"
    )
    scan_parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive scanning"
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "markdown", "sarif"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    scan_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Write output to file"
    )
    scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity level to report"
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    scan_parser.add_argument(
        "--no-suggestions",
        action="store_true",
        help="Hide fix suggestions in output"
    )
    scan_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show findings count (suppress details)"
    )
    scan_parser.add_argument(
        "--exit-code",
        action="store_true",
        default=True,
        help="Return non-zero exit code on findings (default: True)"
    )
    
    # List rules command
    rules_parser = subparsers.add_parser(
        "rules",
        help="List all built-in security rules"
    )
    rules_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter rules by severity"
    )
    rules_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format"
    )
    
    # Find files command
    find_parser = subparsers.add_parser(
        "find",
        help="Find all .env files in directory"
    )
    find_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to search (default: current directory)"
    )
    
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command"""
    scanner = EnvScanner()
    reporter = Reporter(
        use_colors=not args.no_color,
        use_emoji=False
    )
    
    results: List[ScanResult] = []
    
    for path_str in args.path:
        path = Path(path_str)
        
        if path.is_file():
            result = scanner.scan_file(path)
            results.append(result)
        elif path.is_dir():
            recursive = args.recursive and not args.no_recursive
            dir_results = scanner.scan_directory(
                path,
                recursive=recursive
            )
            results.extend(dir_results)
        else:
            print(f"Error: Path not found: {path}", file=sys.stderr)
            return 1
    
    if args.severity:
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_index = severity_order.index(args.severity)
        
        for result in results:
            result.findings = [
                f for f in result.findings
                if severity_order.index(f.severity.value) <= min_index
            ]
    
    if args.format == "json":
        output = reporter.format_json(results, pretty=True)
    elif args.format == "markdown":
        output = reporter.format_markdown(results)
    elif args.format == "sarif":
        output = reporter.format_sarif(results)
    else:
        output = reporter.format_terminal(
            results,
            show_suggestions=not args.no_suggestions
        )
    
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"Report saved to: {args.output}")
    else:
        print(output)
    
    total_findings = sum(len(r.findings) for r in results)
    
    if args.exit_code and total_findings > 0:
        has_critical = any(r.critical_count > 0 for r in results)
        has_high = any(r.high_count > 0 for r in results)
        
        if has_critical:
            return 2
        elif has_high:
            return 1
        else:
            return 0
    
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """Execute the rules command"""
    from envguard.rules import SecurityRules
    
    rules = SecurityRules.RULES
    
    if args.severity:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        rules = [r for r in rules if r.severity == severity_map[args.severity]]
    
    if args.format == "json":
        output = []
        for rule in rules:
            output.append({
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity.value,
                "description": rule.description,
                "fix_suggestion": rule.fix_suggestion,
            })
        import json
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(f"Total rules: {len(rules)}\n")
        
        current_severity = None
        for rule in sorted(rules, key=lambda r: r.severity.value):
            if rule.severity != current_severity:
                current_severity = rule.severity
                print(f"\n[{current_severity.value.upper()}]")
            
            print(f"  {rule.id}: {rule.name}")
            print(f"    {rule.description}")
    
    return 0


def cmd_find(args: argparse.Namespace) -> int:
    """Execute the find command"""
    path = Path(args.path)
    files = find_env_files(path)
    
    if not files:
        print("No .env files found.")
        return 0
    
    print(f"Found {len(files)} .env file(s):\n")
    for f in sorted(files):
        print(f"  {f}")
    
    return 0


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "rules":
        return cmd_rules(args)
    elif args.command == "find":
        return cmd_find(args)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
