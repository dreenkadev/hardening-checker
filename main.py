#!/usr/bin/env python3
"""Hardening Checker - Entry point"""

import argparse
import json
from dataclasses import asdict

from src import (
    VERSION, Colors, HardeningChecker,
    print_banner, print_results, print_summary
)


def demo_mode():
    print(f"{Colors.CYAN}Running demo mode...{Colors.RESET}\n")
    
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Security Checks (Demo){Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    demo_results = [
        ("SSH", "SSH Root Login", True, "critical"),
        ("SSH", "SSH Password Auth", False, "high"),
        ("SSH", "SSH Protocol 2", True, "medium"),
        ("FIREWALL", "UFW Enabled", True, "critical"),
        ("USERS", "No Empty Passwords", True, "critical"),
        ("FILESYSTEM", "/tmp noexec", False, "medium"),
        ("SERVICES", "Telnet disabled", True, "high"),
    ]
    
    current_cat = None
    for cat, name, passed, sev in demo_results:
        if cat != current_cat:
            current_cat = cat
            print(f"\n{Colors.BOLD}{cat}{Colors.RESET}")
        
        if passed:
            status = f"{Colors.GREEN}PASS{Colors.RESET}"
        else:
            color = Colors.RED if sev in ['critical', 'high'] else Colors.YELLOW
            status = f"{color}FAIL [{sev.upper()}]{Colors.RESET}"
        print(f"  {status} {name}")
    
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary{Colors.RESET}")
    print(f"  Total: 7 | {Colors.GREEN}Passed: 5{Colors.RESET} | {Colors.RED}Failed: 2{Colors.RESET}")
    print(f"  {Colors.BOLD}Security Score:{Colors.RESET} {Colors.YELLOW}71/100{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Linux Hardening Checker"
    )
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    parser.add_argument("--version", action="version", version=f"v{VERSION}")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    checker = HardeningChecker()
    
    if not checker.is_root:
        print(f"{Colors.YELLOW}Warning: Some checks require root privileges{Colors.RESET}\n")
    
    results = checker.run_checks()
    summary = checker.get_summary()
    
    print_results(results)
    print_summary(summary)
    
    if args.output:
        output = {
            'summary': summary,
            'results': [asdict(r) for r in results]
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
