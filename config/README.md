# Configuration Files

This folder contains the Wazuh agent configuration files used in the lab.

## Files

### linux-ossec.conf
Configuration for the Ubuntu 22.04 client agent.

**Features enabled:**
- File Integrity Monitoring (FIM) on critical directories
- Authentication log monitoring (/var/log/auth.log)
- System log collection
- Rootkit detection
- Security Configuration Assessment (SCA)
- System inventory

**Key directories monitored:**
- /etc
- /usr/bin, /usr/sbin
- /bin, /sbin
- /home

### windows-ossec.conf
Configuration for the Windows Server 2022/2025 client agent.

**Features enabled:**
- Windows Event Log collection (Security, System, Application)
- **Sysmon integration** for enhanced EDR
- File Integrity Monitoring on critical paths
- Windows Registry monitoring
- PowerShell script block logging
- Windows Defender events
- RDP connection monitoring

**Important Event Channels:**
- Security (Event IDs: 4624, 4625, 4720, 4732, etc.)
- Sysmon/Operational (Event IDs: 1, 3, 5, 7, 11, 22)
- PowerShell/Operational
- TerminalServices (RDP)

## Usage

### Before using these files:

1. **Replace `WAZUH_MANAGER_IP`** with your actual Wazuh server private IP address
2. For Linux: Copy to `/var/ossec/etc/ossec.conf`
3. For Windows: Copy to `C:\Program Files (x86)\ossec-agent\ossec.conf`
4. Restart the agent after modifications

### Linux Agent:
```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

### Windows Agent:
```powershell
NET STOP WazuhSvc
NET START WazuhSvc
Get-Service WazuhSvc
```

## Notes

- These configurations enable comprehensive security monitoring
- Sysmon must be installed separately on Windows for full EDR capabilities
- Configurations are optimized for lab/educational purposes
- In production, adjust scan frequencies and monitored paths based on your needs
```

3. **Commit the file**

---

## Key Features of These Configurations:

### Linux Configuration Highlights:
✅ **File Integrity Monitoring** on critical system directories  
✅ **Real-time monitoring** enabled for /etc, /usr/bin, /usr/sbin  
✅ **Authentication logs** (/var/log/auth.log) for SSH monitoring  
✅ **Rootkit detection** enabled  
✅ **Command monitoring** (df, netstat, last)  
✅ **System inventory** collection  

### Windows Configuration Highlights:
✅ **Comprehensive Windows Event Log collection** (Security, System, Application)  
✅ **Sysmon integration** - Enhanced EDR with Event IDs 1, 3, 5, 7, 11, 22  
✅ **PowerShell logging** for script execution monitoring  
✅ **Registry monitoring** for persistence mechanisms  
✅ **RDP connection tracking**  
✅ **Windows Defender events**  
✅ **File Integrity Monitoring** on C:\Windows\System32, Program Files  

---

## What Makes These Production-Quality:

1. **Comprehensive Coverage:** Monitors all critical security events
2. **Performance Optimized:** Ignores noisy/temporary files
3. **Well Documented:** Inline comments explain each section
4. **Real-time Monitoring:** Enabled for critical paths
5. **Sysmon Integration:** Provides deep EDR visibility
6. **Labeled:** Easy identification in dashboard
7. **Buffer Configuration:** Handles high event volumes

---

Your GitHub repository will now have:
```
wazuh-siem-edr-lab/
├── README.md (comprehensive documentation)
├── config/
│   ├── README.md
│   ├── linux-ossec.conf
│   └── windows-ossec.conf
└── screenshots/
    └── 