#!/bin/bash
# System Hardening Checker - CIS Benchmark compliance scanner

VERSION="1.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

print_banner() {
    echo -e "${CYAN}"
    echo "  _   _               _            _             "
    echo " | | | | __ _ _ __ __| | ___ _ __ (_)_ __   __ _ "
    echo " | |_| |/ _\` | '__/ _\` |/ _ \ '_ \| | '_ \ / _\` |"
    echo " |  _  | (_| | | | (_| |  __/ | | | | | | | (_| |"
    echo " |_| |_|\__,_|_|  \__,_|\___|_| |_|_|_| |_|\__, |"
    echo "   ____ _               _                 |___/  "
    echo "  / ___| |__   ___  ___| | _____ _ __           "
    echo " | |   | '_ \ / _ \/ __| |/ / _ \ '__|          "
    echo " | |___| | | |  __/ (__|   <  __/ |             "
    echo "  \____|_| |_|\___|\___|_|\_\___|_|             "
    echo -e "${NC}"
    echo "                                      v${VERSION}"
    echo ""
}

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    echo -e "        ${YELLOW}Fix: $2${NC}"
    ((FAIL++))
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

check_filesystem() {
    echo -e "\n${BOLD}[1] Filesystem Configuration${NC}"
    
    # Check /tmp mount options
    if mount | grep -q "on /tmp "; then
        if mount | grep "/tmp" | grep -q "noexec"; then
            check_pass "/tmp mounted with noexec"
        else
            check_fail "/tmp missing noexec option" "Add noexec to /tmp mount options"
        fi
    else
        check_warn "/tmp not separately mounted"
    fi
    
    # Check /var/tmp
    if mount | grep -q "on /var/tmp "; then
        check_pass "/var/tmp is separately mounted"
    else
        check_warn "/var/tmp not separately mounted"
    fi
    
    # Check world-writable directories
    world_writable=$(find /tmp /var/tmp -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -5)
    if [[ -z "$world_writable" ]]; then
        check_pass "No world-writable directories without sticky bit"
    else
        check_fail "World-writable directories found" "Set sticky bit with chmod +t"
    fi
}

check_boot_settings() {
    echo -e "\n${BOLD}[2] Boot Settings${NC}"
    
    # Check GRUB password
    if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
        if grep -q "password" /boot/grub*/grub.cfg 2>/dev/null; then
            check_pass "GRUB password is set"
        else
            check_fail "GRUB password not set" "Set GRUB password with grub-mkpasswd-pbkdf2"
        fi
    fi
    
    # Check single user mode auth
    if grep -q "sulogin" /etc/sysconfig/init 2>/dev/null || \
       grep -q "sulogin" /usr/lib/systemd/system/rescue.service 2>/dev/null; then
        check_pass "Single user mode requires auth"
    else
        check_warn "Single user mode may not require auth"
    fi
}

check_process_hardening() {
    echo -e "\n${BOLD}[3] Process Hardening${NC}"
    
    # ASLR
    aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    if [[ "$aslr" == "2" ]]; then
        check_pass "ASLR is fully enabled"
    else
        check_fail "ASLR not fully enabled" "Set kernel.randomize_va_space=2"
    fi
    
    # Core dumps
    if grep -q "hard core 0" /etc/security/limits.conf 2>/dev/null; then
        check_pass "Core dumps are restricted"
    else
        check_warn "Core dumps may be enabled"
    fi
    
    # ptrace scope
    ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    if [[ "$ptrace" -ge "1" ]]; then
        check_pass "ptrace is restricted"
    else
        check_warn "ptrace is not restricted"
    fi
}

check_network() {
    echo -e "\n${BOLD}[4] Network Configuration${NC}"
    
    # IP forwarding
    ipfwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$ipfwd" == "0" ]]; then
        check_pass "IP forwarding is disabled"
    else
        check_fail "IP forwarding is enabled" "Set net.ipv4.ip_forward=0"
    fi
    
    # ICMP redirects
    icmp=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null)
    if [[ "$icmp" == "0" ]]; then
        check_pass "ICMP redirects are disabled"
    else
        check_fail "ICMP redirects accepted" "Set net.ipv4.conf.all.accept_redirects=0"
    fi
    
    # SYN cookies
    syncookies=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)
    if [[ "$syncookies" == "1" ]]; then
        check_pass "TCP SYN cookies enabled"
    else
        check_fail "TCP SYN cookies disabled" "Set net.ipv4.tcp_syncookies=1"
    fi
}

check_access_control() {
    echo -e "\n${BOLD}[5] Access Control${NC}"
    
    # SSH root login
    if grep -qE "^PermitRootLogin\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH root login is disabled"
    else
        check_fail "SSH root login may be allowed" "Set PermitRootLogin no"
    fi
    
    # SSH password auth
    if grep -qE "^PasswordAuthentication\s+no" /etc/ssh/sshd_config 2>/dev/null; then
        check_pass "SSH password auth is disabled"
    else
        check_warn "SSH password auth is enabled"
    fi
    
    # Empty passwords
    if grep -q "nullok" /etc/pam.d/common-auth 2>/dev/null || \
       grep -q "nullok" /etc/pam.d/system-auth 2>/dev/null; then
        check_fail "Empty passwords may be allowed" "Remove nullok from PAM config"
    else
        check_pass "Empty passwords are not allowed"
    fi
    
    # Root PATH
    if echo "$PATH" | grep -q "::"; then
        check_fail "Empty directory in root PATH" "Remove :: from PATH"
    elif echo "$PATH" | grep -q ":\.$"; then
        check_fail "Current directory in root PATH" "Remove . from PATH"
    else
        check_pass "Root PATH is secure"
    fi
}

check_logging() {
    echo -e "\n${BOLD}[6] Logging & Auditing${NC}"
    
    # Syslog running
    if systemctl is-active rsyslog >/dev/null 2>&1 || \
       systemctl is-active syslog-ng >/dev/null 2>&1; then
        check_pass "Syslog service is running"
    else
        check_fail "Syslog service not running" "Enable rsyslog or syslog-ng"
    fi
    
    # Auditd running
    if systemctl is-active auditd >/dev/null 2>&1; then
        check_pass "Audit daemon is running"
    else
        check_warn "Audit daemon not running"
    fi
    
    # Log permissions
    if [[ -f /var/log/syslog ]]; then
        perms=$(stat -c "%a" /var/log/syslog 2>/dev/null)
        if [[ "${perms: -1}" == "0" ]]; then
            check_pass "Syslog has secure permissions"
        else
            check_fail "Syslog is world-readable" "chmod 640 /var/log/syslog"
        fi
    fi
}

check_services() {
    echo -e "\n${BOLD}[7] Services${NC}"
    
    # Unnecessary services
    dangerous_services=("telnet" "rsh" "rlogin" "rexec" "tftp" "xinetd")
    
    for svc in "${dangerous_services[@]}"; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            check_fail "Dangerous service running: $svc" "Disable with: systemctl disable $svc"
        fi
    done
    
    check_pass "Common dangerous services checked"
}

print_summary() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}Summary${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $PASS"
    echo -e "  ${RED}Failed:${NC}  $FAIL"
    echo -e "  ${YELLOW}Warning:${NC} $WARN"
    echo ""
    
    total=$((PASS + FAIL + WARN))
    if [[ $total -gt 0 ]]; then
        score=$(( (PASS * 100) / total ))
    else
        score=0
    fi
    
    if [[ $score -ge 80 ]]; then
        score_color=$GREEN
    elif [[ $score -ge 50 ]]; then
        score_color=$YELLOW
    else
        score_color=$RED
    fi
    
    echo -e "${BOLD}Compliance Score:${NC} ${score_color}${score}%${NC}"
}

run_demo() {
    echo -e "${YELLOW}Running demo mode...${NC}"
    
    echo -e "\n${BOLD}[1] Filesystem Configuration${NC}"
    check_pass "/tmp mounted with noexec"
    check_fail "/var/tmp missing noexec option" "Add noexec to mount options"
    
    echo -e "\n${BOLD}[2] Boot Settings${NC}"
    check_warn "GRUB password not verified"
    
    echo -e "\n${BOLD}[3] Process Hardening${NC}"
    check_pass "ASLR is fully enabled"
    check_pass "ptrace is restricted"
    
    echo -e "\n${BOLD}[4] Network Configuration${NC}"
    check_pass "IP forwarding is disabled"
    check_fail "ICMP redirects accepted" "Set net.ipv4.conf.all.accept_redirects=0"
    check_pass "TCP SYN cookies enabled"
    
    echo -e "\n${BOLD}[5] Access Control${NC}"
    check_pass "SSH root login is disabled"
    check_fail "SSH password auth is enabled" "Set PasswordAuthentication no"
    check_pass "Empty passwords are not allowed"
    
    print_summary
}

main() {
    print_banner
    
    if [[ "$1" == "--demo" ]]; then
        run_demo
        exit 0
    fi
    
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        echo "Usage: hardening_check.sh [options]"
        echo ""
        echo "Options:"
        echo "  --demo     Run demo mode"
        echo "  -h, --help Show help"
        exit 0
    fi
    
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Warning: Running as non-root may limit some checks${NC}"
        echo ""
    fi
    
    check_filesystem
    check_boot_settings
    check_process_hardening
    check_network
    check_access_control
    check_logging
    check_services
    
    print_summary
}

main "$@"
