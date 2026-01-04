"""Hardening Checker - Output formatting"""

from typing import List, Dict
from .constants import VERSION, Colors
from .checker import CheckResult


def print_banner():
    print(f"""{Colors.CYAN}
  _   _               _            _             
 | | | | __ _ _ __ __| | ___ _ __ (_)_ __   __ _ 
 | |_| |/ _` | '__/ _` |/ _ \\ '_ \\| | '_ \\ / _` |
 |  _  | (_| | | | (_| |  __/ | | | | | | | (_| |
 |_| |_|\\__,_|_|  \\__,_|\\___|_| |_|_|_| |_|\\__, |
   ____ _               _                  |___/ 
  / ___| |__   ___  ___| | _____ _ __            
 | |   | '_ \\ / _ \\/ __| |/ / _ \\ '__|           
 | |___| | | |  __/ (__|   <  __/ |              
  \\____|_| |_|\\___|\\___|_|\\_\\___|_|              
{Colors.RESET}                                    v{VERSION}
""")


def print_results(results: List[CheckResult]):
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Security Checks{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    current_category = None
    for result in results:
        if result.category != current_category:
            current_category = result.category
            print(f"\n{Colors.BOLD}{current_category.upper()}{Colors.RESET}")
        
        if result.passed:
            status = f"{Colors.GREEN}PASS{Colors.RESET}"
        else:
            severity_color = Colors.RED if result.severity in ['critical', 'high'] else Colors.YELLOW
            status = f"{severity_color}FAIL [{result.severity.upper()}]{Colors.RESET}"
        
        print(f"  {status} {result.name}")


def print_summary(summary: Dict):
    print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    
    print(f"  Total checks: {summary['total_checks']}")
    print(f"  {Colors.GREEN}Passed: {summary['passed']}{Colors.RESET}")
    print(f"  {Colors.RED}Failed: {summary['failed']}{Colors.RESET}")
    
    if summary['failed'] > 0:
        print(f"\n  Failed by severity:")
        for sev, count in summary['failed_by_severity'].items():
            if count > 0:
                color = Colors.RED if sev in ['critical', 'high'] else Colors.YELLOW
                print(f"    {color}{sev.upper()}: {count}{Colors.RESET}")
    
    score = summary['score']
    score_color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 60 else Colors.RED
    print(f"\n  {Colors.BOLD}Security Score:{Colors.RESET} {score_color}{score}/100{Colors.RESET}")
