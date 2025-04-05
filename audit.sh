#!/bin/bash

# Security Audit and Hardening Script for Linux Servers
read -p  "Author" :
# Version: 1.0
read -p "Date" : 

LOGFILE="/var/log/security_audit.log"
CONFIG_FILE="./config.cfg"

# Function to log messages
log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

# Function to check if script is run as root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log "ERROR: This script must be run as root!"
        exit 1
    fi
}

# Function to audit users and groups
audit_users() {
    log "=== User and Group Audit ==="
    log "List of users:"
    cut -d: -f1 /etc/passwd | tee -a "$LOGFILE"

    log "Checking for UID 0 (root) users other than root..."
    awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | tee -a "$LOGFILE"

    log "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow | tee -a "$LOGFILE"
}

# Function to check file permissions
audit_files() {
    log "=== File and Directory Permissions Audit ==="
    log "World-writable files:"
    find / -type f -perm -o+w 2>/dev/null | tee -a "$LOGFILE"

    log "Checking for SUID/SGID files:"
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -lh {} \; | tee -a "$LOGFILE"
}

# Function to audit services
audit_services() {
    log "=== Service Audit ==="
    log "Running services:"
    systemctl list-units --type=service --state=running | tee -a "$LOGFILE"

    log "Checking for unnecessary services..."
    UNNECESSARY_SERVICES=("telnet" "ftp" "rsh" "rexec")
    for srv in "${UNNECESSARY_SERVICES[@]}"; do
        systemctl is-active --quiet "$srv" && log "$srv is running and should be disabled"
    done
}

# Function to audit firewall and network security
audit_firewall() {
    log "=== Firewall & Network Security Audit ==="
    log "Active firewall rules:"
    iptables -L -n | tee -a "$LOGFILE"

    log "Checking open ports:"
    netstat -tulnp | tee -a "$LOGFILE"

    log "Checking for IP forwarding:"
    sysctl net.ipv4.ip_forward | tee -a "$LOGFILE"
}

# Function to check network configuration
audit_network() {
    log "=== IP & Network Configuration ==="
    IP_LIST=$(hostname -I)
    log "Server IPs: $IP_LIST"

    for IP in $IP_LIST; do
        if [[ $IP =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            log "$IP is private"
        else
            log "$IP is public"
        fi
    done
}

# Function to check security updates
audit_updates() {
    log "=== Security Updates Audit ==="
    log "Checking for available updates..."
    apt update && apt list --upgradable | grep security | tee -a "$LOGFILE"
}

# Function to check logs for suspicious activity
audit_logs() {
    log "=== Log Monitoring ==="
    log "Checking for SSH brute force attempts..."
    grep "Failed password" /var/log/auth.log | tail -10 | tee -a "$LOGFILE"
}

# Function to perform server hardening
harden_server() {
    log "=== Server Hardening ==="

    log "Disabling password authentication for SSH..."
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd

    log "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    log "Setting GRUB password..."
    echo "password_pbkdf2 root $(grub-mkpasswd-pbkdf2 | grep 'grub.pbkdf2')" >> /etc/grub.d/40_custom
    update-grub
}

# Function to generate final report
generate_report() {
    log "=== Security Audit Report ==="
    cat "$LOGFILE"
}

# Main function
main() {
    check_root
    echo "Starting Security Audit..."
    echo "Logging to $LOGFILE"
    echo "Security Audit Report - $(date)" > "$LOGFILE"
    
    audit_users
    audit_files
    audit_services
    audit_firewall
    audit_network
    audit_updates
    audit_logs
    harden_server
    generate_report

    log "Audit complete. Check $LOGFILE for details."
}

# Execute main function
main
