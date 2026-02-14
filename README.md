![Kalash](pic/kalash.png)

```
    __ __      __           __  
   / //_/___ _/ /___ ______/ /_ 
  / ,< / __ `/ / __ `/ ___/ __ \
 / /| / /_/ / / /_/ (__  ) / / /
/_/ |_\__,_/_/\__,_/____/_/ /_/ 
                      Ruby Backdoor
```

> A high-performance post-exploitation framework designed for stealthy persistence, EDR evasion, and automated deployment on Linux environments.
> This project consists of two main components: install.sh (Deployment & Obfuscation) and uninstall.sh (Clean-up & Reversion).

# The deployment script implements several advanced techniques used by Red Team operators to remain undetected:

### 1. Pre-Flight & EDR Detection
**Before making any changes, the script audits the environment:**
- Security Scanning: Checks for active processes and binaries associated with major security vendors like CrowdStrike Falcon, SentinelOne, Wazuh, Ossec, and Carbon Black.
- Auditd Neutralization: If auditd (Linux Auditing System) is detected, the script attempts to pause it to prevent the logging of system calls and file modifications.

### 2. Multi-Layered Code Obfuscation
**The Ruby payload is never stored in plain text. It uses a Self-Encoded Loader strategy:**
- Zlib + Base64 Compression: The source code is compressed using Zlib and encoded into a Base64 string.
- Runtime Memory Execution: The final file on disk contains only a single-line "loader" that decodes and executes the payload directly in memory, bypassing static file scanners (YARA/AV).

### 3. Advanced Stealth Techniques
- Process Masquerading: The Ruby process dynamically renames its global $0 variable and process title to [kworker/u2:1], making it appear as a legitimate Linux kernel thread in tools like top, htop, and ps aux.
- Timestomping: The script uses the touch command to modify the Access and Modification timestamps (atime/mtime) of all created files to a date in the past (e.g., May 2021), evading forensic searches for "recently created files."
- Systemd Masking: The persistence service is named dbus-org-maintenance.service and uses a configuration "drop-in" to hide its description from systemctl list-units.

### 4. Log Tampering & Anti-Forensics
**The script automatically scrubs the system to remove Indicators of Compromise (IoCs):**
- Log Scrubbing: Uses sed to delete any lines mentioning the service name, the script filename, or the selected port within /var/log/syslog, auth.log, daemon.log, and audit.log.
- Journald Vacuuming: Clears binary logs via journalctl to remove the service's startup traces.
- Session Cleanup: Wipes the current Bash history and self-deletes the installer after successful execution.

---

## Payload Specifications
**The Ruby-based backdoor provides:**
- Password Authentication: Prevents unauthorized access from third parties or automated scanners.
- Interactive Shell: Spawns a fully interactive /bin/bash shell.
- Architecture Agnostic: Since it runs via the Ruby interpreter, it works seamlessly across x86, x64, ARM, and MIPS without recompilation.

## Usage
**Deployment**
- Make the script executable: chmod +x install.sh
- Run as root: sudo ./install.sh
- Enter the desired communication port and access password when prompted.

Connection

Use Netcat or any TCP client to connect:
Bash:
`nc [TARGET_IP] [PORT]`

## Uninstallation
**The uninstall.sh script provides a surgical cleanup:**
- Stops and removes the masqueraded service.
- Auto-Detection: Decodes the obfuscated Ruby file in memory to identify the port used, then automatically closes it in the firewall (iptables/ufw).
- Deletes all files and restarts the auditd service to return the system to its original state.

---

# Legal Disclaimer
This tool is for educational purposes and authorized penetration testing only. Accessing systems without explicit permission is illegal. The author assumes no liability for any misuse of this software.

