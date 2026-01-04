"""Hardening Checker - Core checker"""

import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional

from .constants import SECURITY_CHECKS


@dataclass
class CheckResult:
    category: str
    name: str
    passed: bool
    severity: str
    details: str


class HardeningChecker:
    def __init__(self):
        self.results: List[CheckResult] = []
        self.is_root = os.geteuid() == 0
        
    def run_command(self, cmd: str) -> str:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=10
            )
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)
    
    def check_file_pattern(self, filepath: str, pattern: str) -> bool:
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return bool(re.search(pattern, content))
        except Exception:
            return False
    
    def check_command_pattern(self, cmd: str, pattern: str) -> bool:
        output = self.run_command(cmd)
        return bool(re.search(pattern, output))
    
    def run_checks(self) -> List[CheckResult]:
        self.results = []
        
        for category, checks in SECURITY_CHECKS.items():
            for check in checks:
                passed = False
                details = ""
                
                if 'file' in check:
                    passed = self.check_file_pattern(check['file'], check['pattern'])
                    details = f"File: {check['file']}"
                elif 'command' in check:
                    if check.get('expect_empty'):
                        output = self.run_command(check['command'])
                        passed = len(output.strip()) == 0
                        details = "Empty output expected"
                    else:
                        passed = self.check_command_pattern(check['command'], check['pattern'])
                        details = f"Command: {check['command']}"
                
                result = CheckResult(
                    category=category,
                    name=check['name'],
                    passed=passed,
                    severity=check['severity'],
                    details=details
                )
                self.results.append(result)
        
        return self.results
    
    def get_summary(self) -> Dict:
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        
        failed_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for r in self.results:
            if not r.passed:
                failed_by_severity[r.severity] += 1
        
        score = int((passed / len(self.results)) * 100) if self.results else 0
        
        return {
            'total_checks': len(self.results),
            'passed': passed,
            'failed': failed,
            'failed_by_severity': failed_by_severity,
            'score': score
        }
