# Threat Hunt - CORP HEALTH
Incident Response Report from Threat Hunt

**Incident Narrative** 

Your organization recently completed a phased deployment of an internal platform known as CorpHealth — a lightweight system monitoring and maintenance framework designed to: 

-	Track endpoint stability and performance
-	Run automated post-patch health checks
-	Collect system diagnostics during maintenance windows
-	Reduce manual workload for operations teams 

CorpHealth operates using a mix of scheduled tasks, background services, and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account.

This account was granted local administrator privileges on specific systems in order to: 

-	Register scheduled maintenance tasks
-	Install and remove system services
-	Write diagnostic and configuration data to protected system locations
-	Perform controlled cleanup and telemetry operations 

It was designed to be used only through approved automation frameworks, not through interactive sign-ins.

Anomalous Activity 

In mid-November, routine monitoring began surfacing unusual activity tied to a workstation in the operations environment.

At first glance, the activity appeared consistent with normal system maintenance tasks:
health checks, scheduled runs, configuration updates, and inventory synchronization.

However, closer review raised concerns:

-	Activity occurred outside normal maintenance windows
-	Script execution patterns deviated from approved baselines
-	Diagnostic processes were launched manually rather than through automation
-	Some actions resembled behaviors often associated with credential compromise or script misuse

Much of this activity was associated with an account that normally runs silently in the background.

Your Role 

You are taking over as the lead analyst assigned to review historical telemetry captured by: 

-	Microsoft Defender for Endpoint
-	Azure diagnostic and device logs
-	Supporting endpoint event artifacts 

You will not have live access to the machine — only its recorded activity.

Your task is to determine: 

-	What system was affected
-	When suspicious activity occurred
-	How the activity progressed across different stages
-	Whether the behavior represents authorized automation or misuse of a privileged account

The incident is not labeled as a confirmed breach.

It has been formally categorized as:

“An Operations Activity Review”

Your investigation will determine whether it remains just that — or escalates into something more.

**Establishing an investigation scope**

Before diving into deeper activity, your first responsibility as lead analyst is to identify the endpoint where the unusual telemetry originated.

Overnight, the monitoring queue tagged a single workstation with a cluster of correlated events. The alerts were low-severity and categorized under “Operational Maintenance Activity (Unclassified)”. Still, the timestamps looked unusual — the sequence occurred during an off-hours window, sometime mid-November, when no maintenance jobs were scheduled.

Your task is to confirm the correct device and the time frame you’ll be working within for the rest of the investigation within CorpHealth.

---

## 📝 INCIDENT RESPONSE REPORT

**Date of Report:** 2026-01-06  
**Incident Date Range:** 2025-11-15 – 2025-12-15  
**Severity Level:** HIGH  
**Report Status:** Open  
**Escalated To:** Incident Response Team  
**Incident ID:** Corp-Health-Incident<br> 
**Analyst:** Tony Ramos  

---

## 📌 SUMMARY OF FINDINGS

- On **2025-11-23-3:45AM**, a suspicious "MaintenanceRunner_Distributed.ps1" file was discovered in the **ch-ops-wks02** device.
- The suspicious maintenance script file initiated first outbound connection on the **2025-11-23T03:46am** using the loopback address 
- The script's successful beacon connection to the remoteIP was made on the **2025-11-30T01:03:17am** 
- The unexpected artifact staging activity was detected in the folder path **C:\ProgramData\Microsoft\Diagnostics\CorpHealth\**
- At **2025-11-25T04:14** a Registry Key was created for “Credential Harvesting Simulation” then a scheduled task Registry Key was created.
- At **2025-11-25T04:24am** a registrykey was added and its valuename was set toThe "MaintenanceRunner" for **Registry-based persistance.**
- An application event was found at **2025-11-23T03:47:21.8529749Z** which describes a **Privilige Scalation event**
- A file with an exec script was found which would exclude microsoft defender from scanning the specified folderpath "C:\ProgramData\Corp\Ops\staging -Force"
- An powershell encodedcommand execution script was found with an encoded payload.
- An windows registry event for privilige scalation was found as **ProcessPrimaryTokenModified event** with evidence of toke modification.
- A binary was recorded by Defender called **"revshell"**, which appears to be an ingress transfer tool.
- A outbound HTTPS connection was found to download the binary from an tunneling external platform source initiated by **curl.exe**.
- The threat actor then proceed to execute their tools from profile directory via explorer.exe
- The binary **"revshell"** once executed reached to the remote IP **13.228.171.119**
- The binary file was also copied into the **windows startup directory** to achieve persistence.
- The remote session device name was found and had a particular description **"对手"**
- Initial pivot internal IP address was identified with its timestamp and user account "chadmin".

---

## 👤 WHO

### Attacker Activity Sources
- **Initial Pivot Host:** ch-ops-wks02
- **Initial Pivot Account:** chadmin
- **Windows Deployment Targets:** Multiple systems  

### Compromised Accounts
- **chadmin** (Windows domain account )


---

## 📂 WHAT (Event Summary)

## 🚩 Flags & Indicators of Compromise (IOCs)

| Flag # | Category | Indicator | Timestamp |
|------:|---------|-----------|-----------|
| 1 | Remote Access | `ssh.exe backup-admin@10.1.0.189` | 2025-11-25T05:39:10Z |
| 2 | Lateral Movement Source | 10.1.0.108 | 2025-11-25T05:39:22Z |
| 3 | Compromised Account | backup-admin | 2025-11-25 |
| 4 | Backup Enumeration | `ls -la /backups/` | 2025-11-25T05:41:43Z |
| 5 | Archive Discovery | `find /backups -name *.tar.gz` | 2025-11-24T14:16:06Z |
| 6 | Account Enumeration | `cat /etc/passwd` | 2025-11-24T14:16:08Z |
| 7 | Scheduled Job Recon | `cat /etc/crontab` | 2025-11-24T14:16:08Z |
| 8 | Tool Download | `destroy.7z` | 2025-11-25T05:45:34Z |
| 9 | Credential Access | `all-credentials.txt` | 2025-11-24T14:14:14Z |
| 10 | Backup Destruction | `rm -rf /backups/*` | 2025-11-25T05:47:02Z |
| 11 | Service Stop | `systemctl stop cron` | 2025-11-25T05:47:03Z |
| 12 | Service Disable | `systemctl disable cron` | 2025-11-25T05:47:03Z |
| 13 | Remote Execution | PsExec64.exe | 2025-11-25T05:58:35Z |
| 14 | Ransomware Deployment | silentlynx.exe | 2025-11-25 |
| 15 | Payload Execution | silentlynx.exe | 2025-11-25 |
| 16 | Shadow Copy Stop | `net stop vss` | 2025-11-25T06:04:53Z |
| 17 | Backup Engine Stop | `net stop wbengine` | 2025-11-25T06:04:54Z |
| 18 | Process Termination | `taskkill /IM sqlservr.exe` | 2025-11-25T06:04:57Z |
| 19 | Shadow Deletion | `vssadmin delete shadows` | 2025-11-25T05:58:55Z |
| 20 | Storage Limitation | `vssadmin resize shadowstorage` | 2025-11-25 |
| 21 | Recovery Disabled | `bcdedit recoveryenabled No` | 2025-11-25T06:04:59Z |
| 22 | Catalog Deletion | `wbadmin delete catalog` | 2025-11-25T06:04:59Z |
| 23 | Registry Autorun | WindowsSecurityHealth | 2025-11-25T06:05:01Z |
| 24 | Scheduled Task | SecurityHealthService | 2025-11-25T06:05:01Z |
| 25 | Anti-Forensics | `fsutil usn deletejournal` | 2025-11-25T06:10:04Z |
| 26 | Ransom Note | SILENTLYNX_README.txt | 2025-11-25T06:05:01Z |

---

## ⏱ WHEN (UTC Timeline)

- **11-24:** Backup discovery and credential harvesting  
- **11-25 05:39:** SSH access to backup server  
- **11-25 05:47:** Backup destruction completed  
- **11-25 05:58:** Ransomware deployed via PsExec  
- **11-25 06:04:** Recovery mechanisms disabled  
- **11-25 06:05:** Persistence established  
- **11-25 06:10:** Anti-forensics executed  
- **11-27:** Ransom notes discovered enterprise-wide  

---

## 🖥 WHERE (Infrastructure Impact)

### Compromised Systems
- CH-OPS-WKS02

---

## ❓ WHY (Attacker Motivation & Root Cause)

### Root Cause
- Privileged account compromise with direct access to other endpoints.
- Insufficient segmentation between production and recovery assets.
- No "zero trust" controls in place.

### Attacker Objectives
- compromise admin account  
- pivoting and privilige escalation
- achieve persistance   
- exfiltrate company information

### Business Impact
- Compromised admin accounts.
- exfiltration of company sensitive information  
- Different endpoints at risk.

---

## ⚙️ HOW (Attack Chain Summary)

1. Initial Windows compromise  
2. Pivot to maintenance account
3. Persistance achieved via registry modification
4. ingress tool donwload 
5. information exfiltration


---

## 🚨 IMPACT ASSESSMENT

### Actual Impact
- Backup infrastructure destroyed  
- Enterprise ransomware deployment  
- Recovery mechanisms disabled  
- Forensic visibility reduced  

### Risk Level
**CRITICAL**

---

## 🛠 RECOMMENDATIONS

### 🔥 IMMEDIATE
- Isolate affected systems  
- Disable compromised accounts  
- Preserve remaining forensic artifacts  

---

## 🛡 LONG-TERM RECOMMENDATIONS

- Enforce MFA for backup/admin access  
- Segment endpoints
- Monitor SSH and PsExec usage  
- conduct cybersecurity training exercises.

---

## Threat Hunt - Corp Health Queries  

---  

### Flag 1 – Initial Access: Remote SSH Activity  

**Use Case:**  
Identify secure shell–based access from a Windows endpoint used to pivot into Linux backup infrastructure.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "azuki-adminpc"  
| where FileName in~ ("ssh.exe","scp.exe","sftp.exe","plink.exe")  
    or ProcessCommandLine has "ssh "  

---  

### Flag 2 – Lateral Movement: Attack Source Identification  

**Use Case:**  
Correlate authentication events to identify the originating host used to access the backup server.  

DeviceLogonEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where LogonType == "Network"  
| where AccountName == "backup-admin"  

---  

### Flag 3 – Credential Access: Compromised Backup Account  

**Use Case:**  
Confirm abuse of a privileged backup account used to access recovery-critical systems.  

DeviceLogonEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "backup-admin"  

---  

### Flag 4 – Discovery: Directory Enumeration  

**Use Case:**  
Detect file system reconnaissance used to locate backup directories and critical data stores.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "backup-admin"  
| where ProcessCommandLine has_any (  
    "ls",  
    "tree",  
    "find ",  
    "locate ",  
    "dir ",  
    "show flash",  
    "nvram"  
)  
| project TimeGenerated, ProcessCommandLine  

---  

### Flag 5 – Discovery: Backup Archive Identification  

**Use Case:**  
Identify searches for compressed backup archives likely targeted for destruction or exfiltration.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where ProcessCommandLine contains "find /backups"  
| where ProcessCommandLine contains ".tar.gz"  
| project TimeGenerated, ProcessCommandLine  

---  

### Flag 6 – Discovery: Local Account Enumeration  

**Use Case:**  
Detect enumeration of local Linux accounts to identify additional targets or escalation paths.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine has "/etc/passwd"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 7 – Discovery: Scheduled Job Reconnaissance  

**Use Case:**  
Identify reconnaissance of cron jobs to understand backup timing and persistence mechanisms.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine contains "cron"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 8 – Command and Control: Tool Download  

**Use Case:**  
Detect external tool downloads used to stage destructive or ransomware-related utilities.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where FileName has_any ("curl", "wget")  
| project TimeGenerated, ProcessCommandLine  

---  

### Flag 9 – Credential Access: Credential File Theft  

**Use Case:**  
Identify access to plaintext or sensitive credential files stored within backup configurations.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine has_any (  
    "/etc/shadow",  
    ".ssh/id_rsa",  
    ".ssh/id_ed25519",  
    ".ssh/authorized_keys",  
    "credentials",  
    "secrets"  
)  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 10 – Impact: Backup Data Destruction  

**Use Case:**  
Detect deletion of backup repositories intended to eliminate recovery options prior to ransomware deployment.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine has_any ("rm","del")  
| where ProcessCommandLine contains "backup"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 11 – Impact: Service Stopped  

**Use Case:**  
Identify immediate service disruption actions used to halt scheduled backup operations.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine has_any ("stop")  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 12 – Impact: Service Disabled  

**Use Case:**  
Detect disabling of services to ensure backup operations do not resume after reboot.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where DeviceName contains "BackupSrv"  
| where ProcessCommandLine has_any ("stop","kill","disable")  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 13 – Lateral Movement: Remote Execution via PsExec  

**Use Case:**  
Detect remote execution tooling used to deploy ransomware across Windows systems.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where FileName =~ "psexec.exe"  
    or ProcessCommandLine contains "psexec"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 14 – Lateral Movement: Ransomware Deployment Command  

**Use Case:**  
Capture full deployment commands revealing targeted hosts, credentials, and malicious payloads.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where ProcessCommandLine contains "PsExec"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 15 – Execution: Ransomware Payload Identification  

**Use Case:**  
Identify the malicious executable responsible for encryption activity.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where ProcessCommandLine contains "silentlynx.exe"  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 16 – Impact: Shadow Copy Service Stopped  

**Use Case:**  
Detect attempts to stop Volume Shadow Copy Services to prevent recovery.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where ProcessCommandLine has_any ("net stop", "sc stop", "vss")  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 17 – Impact: Backup Engine Disabled  

**Use Case:**  
Identify commands stopping Windows backup engines to prevent ongoing protection.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine has_any ("net","sc","vss")  
| project TimeGenerated, AccountName, ProcessCommandLine  

---  

### Flag 18 – Defense Evasion: Process Termination  

**Use Case:**  
Detect forced termination of processes that lock files prior to encryption.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine contains "taskkill"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 19 – Impact: Shadow Copy Deletion  

**Use Case:**  
Identify deletion of recovery points to permanently remove restore options.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine contains "shadows"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 20 – Impact: Shadow Storage Limitation  

**Use Case:**  
Detect resizing of shadow storage to prevent new recovery points from being created.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where ProcessCommandLine contains "shadowstorage"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 21 – Impact: Recovery Disabled  

**Use Case:**  
Identify disabling of Windows recovery mechanisms to prevent automated repair.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine contains "bcdedit"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 22 – Impact: Backup Catalog Deletion  

**Use Case:**  
Detect deletion of backup catalogs that track available restore points.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine contains "wbadmin"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 23 – Persistence: Registry Autorun  

**Use Case:**  
Identify registry-based persistence mechanisms executed at system startup.  

DeviceRegistryEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"  
| where DeviceName == "azuki-adminpc"  

---  

### Flag 24 – Persistence: Scheduled Task Execution  

**Use Case:**  
Detect scheduled task creation or execution used to maintain persistence.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where FileName contains "schtasks"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 25 – Defense Evasion: USN Journal Deletion  

**Use Case:**  
Detect deletion of NTFS change journals to hinder forensic reconstruction.  

DeviceProcessEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where AccountName == "yuki.tanaka"  
| where ProcessCommandLine contains "fsutil"  
| project TimeGenerated, FileName, AccountName, ProcessCommandLine  

---  

### Flag 26 – Impact: Ransom Note Creation  

**Use Case:**  
Identify ransom note files indicating successful encryption and attack completion.  

DeviceFileEvents  
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-12-06))  
| where FileName contains ".txt"  
| project TimeGenerated, FileName, FolderPath  

---  
