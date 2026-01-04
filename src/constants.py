"""Hardening Checker - Constants"""

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Security checks to perform
SECURITY_CHECKS = {
    'ssh': [
        {'name': 'SSH Root Login', 'file': '/etc/ssh/sshd_config', 'pattern': r'PermitRootLogin\s+no', 'severity': 'critical'},
        {'name': 'SSH Password Auth', 'file': '/etc/ssh/sshd_config', 'pattern': r'PasswordAuthentication\s+no', 'severity': 'high'},
        {'name': 'SSH Protocol 2', 'file': '/etc/ssh/sshd_config', 'pattern': r'Protocol\s+2', 'severity': 'medium'},
    ],
    'firewall': [
        {'name': 'UFW Enabled', 'command': 'ufw status', 'pattern': r'Status:\s+active', 'severity': 'critical'},
        {'name': 'iptables Rules', 'command': 'iptables -L', 'pattern': r'Chain INPUT', 'severity': 'medium'},
    ],
    'users': [
        {'name': 'No Empty Passwords', 'command': 'awk -F: \'$2==\"\"{print}\' /etc/shadow', 'expect_empty': True, 'severity': 'critical'},
        {'name': 'Root Account Locked', 'command': 'passwd -S root', 'pattern': r'root L', 'severity': 'high'},
    ],
    'filesystem': [
        {'name': '/tmp noexec', 'command': 'mount | grep /tmp', 'pattern': r'noexec', 'severity': 'medium'},
        {'name': 'Sticky bit on /tmp', 'command': 'ls -ld /tmp', 'pattern': r'^drwxrwxrwt', 'severity': 'low'},
    ],
    'services': [
        {'name': 'Telnet disabled', 'command': 'systemctl is-enabled telnet 2>&1', 'pattern': r'disabled|not-found', 'severity': 'high'},
        {'name': 'FTP disabled', 'command': 'systemctl is-enabled vsftpd 2>&1', 'pattern': r'disabled|not-found', 'severity': 'medium'},
    ]
}
