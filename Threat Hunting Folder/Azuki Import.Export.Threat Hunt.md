# Helpdesk-Deception

**Analyst:** Neal Patel  
**Date:** November 15, 2025  
**Environment:** Log Analytics Workspace  
**Primary Host:** gab-intern-vm  
**Timeframe Investigated:** October 1–15, 2025

---

## Summary

During early October 2025, multiple endpoints executed suspicious support-themed files from the Downloads directory. These items contained keywords such as support, help, desk, and tool, and intern-operated systems appeared most impacted. Among all hosts, gab-intern-vm revealed the earliest activity matching the pattern. What seemed to be a routine remote support session instead represented a structured sequence of reconnaissance, validation, staging, and persistence actions. The actor used helpdesk-themed filenames to disguise their intrusion and activity. 

### Key actions included:

- Execution of a PowerShell script from Downloads
- Staged artifact creation
- Reconnaissance covering clipboard, session data, privileges, processes, and storage  
- Outbound connectivity validation  
- Creation of a ZIP archive staging recon data  
- Outbound connections to external IPs  
- Scheduled task and autorun registry persistence  
- Dropping a “support chat log” as narrative misdirection  

DefenderTamperArtifact.lnk and SupportChat_log.lnk suggest intentional misdirection designed to appear as a legitimate support session.

---

## Hunt Scope

### Data sources analyzed:

- DeviceProcessEvents  
- DeviceFileEvents  
- DeviceNetworkEvents  
- DeviceRegistryEvents  

### Objectives:

- Identify earliest execution  
- Reconstruct recon sequence  
- Identify staging and simulated exfil attempts  
- Identify persistence  
- Detect planted narrative artifacts  
- Align with MITRE ATT&CK  

---

# Attack Timeline

| Flag | Phase / Focus | Key Event |
|------|---------------|-----------|
| 0 | Starting Point Identification | gab-intern-vm first to show support-themed execution |
| 1 | Initial Execution | PowerShell ran script using -ExecutionPolicy bypass |
| 2 | Defense Deception | DefenderTamperArtifact.lnk accessed |
| 3 | Quick Data Probe | Get-Clipboard usage |
| 4 | Host / Session Recon | qwinsta and query user activity |
| 5 | Storage Enumeration | Logical disk enumeration via WMIC |
| 6 | Connectivity / Egress Check | Outbound checks parented by RuntimeBroker |
| 7 | Interactive Session Discovery | Query session tied to UniqueProcessId |
| 8 | Runtime Application Inventory | tasklist.exe |
| 9 | Privilege Surface Check | whoami /groups |
| 10 | Proof-of-Access & Egress Validation | First outbound web contact: msftconnecttest.com |
| 11 | Artifact Staging | ReconArtifacts.zip created |
| 12 | Simulated Outbound Transfer | Contact to 100.29.147.161 |
| 13 | Scheduled Task Persistence | SupportToolUpdater task created |
| 14 | Autorun Fallback Persistence | Autorun entry: RemoteAssistUpdater |
| 15 | Planted Narrative Artifact | SupportChat_log.lnk created |

---

# Flag-by-Flag Analysis  


---

## Flag 0 — Starting Point Identification

### Objective:
Determine which endpoint is most likely associated with the initiation of suspicious activity in the Downloads folder. 

### Finding: 

Suspicious support-themed executions occurred on several systems, but gab-intern-vm matched all indicators (naming patterns, path, timing, intern-operated machine).

### Query Used:
```
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" 
    or ProcessCommandLine has @"\Downloads\"
| where ProcessCommandLine has_any ("Downloads", "support", "help", "desk", "tool")
    or FileName has_any ("Downloads", "support", "help", "desk", "tool")
```
<img width="792" height="258" alt="image" src="https://github.com/user-attachments/assets/059556a3-4a03-4d8a-8137-e96b1acc0eac" />

**Flag Answer:** gab-intern-vm

---

## Flag 1 — Initial Execution Detection

### Objective:

Identify the first CLI parameter used during initial execution.

### Finding: 

-ExecutionPolicy was used to launch SupportTool.ps1. 

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" 
    or ProcessCommandLine has @"\Downloads\"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1163" height="176" alt="image" src="https://github.com/user-attachments/assets/a677ab7b-fdff-434a-8e45-ffb8796d8fe2" />

**Flag Answer:** -ExecutionPolicy

---

## Flag 2 — Defense Disabling (Staged Tamper)

### Objective:

Search for artifact creation or short-lived process activity that contains tamper-related content or simulated security posture changes.

### Finding:

A shortcut file, DefenderTamperArtifact.lnk, was created and accessed. No real Defender settings were modified, suggesting it was staged.

### Query Used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-01)..datetime(2025-10-15))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe") 
    and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="993" height="200" alt="image" src="https://github.com/user-attachments/assets/6f0e3cf8-2b49-437e-bd88-c481cbf7eb20" />

**Flag Answer:** DefenderTamperArtifact.lnk

---

## Flag 3 — Quick Data Probe

### Objective:

Detect opportunistic access to read transient data sources common on endpoints.

### Finding:

The actor probed the clipboard via PowerShell for sensitive data.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "clip"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="895" height="114" alt="image" src="https://github.com/user-attachments/assets/ca4cb02d-b84c-4026-8369-c4b664fb6ee4" />

**Flag Answer:** powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

---

## Flag 4 — Host Context Recon

### Objective:

Find activity that gathers basic host and user context to inform follow-up actions.

### Finding:

The actor used session enumeration commands to check active users.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("qwi", "qwinsta", "query user", "quser")
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="552" height="175" alt="image" src="https://github.com/user-attachments/assets/0b77c32f-1167-4fc9-ad4c-04a9579875dd" />

**Flag Answer:** 2025-10-09T12:51:44.3425653Z

---

## Flag 5 — Storage Surface Mapping

### Objective:

Detect disk enumeration.

### Finding:

Storage and filesystem enumeration occurred using WMIC logical disk queries.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "wmic"
    or FileName contains "wmic"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="714" height="91" alt="image" src="https://github.com/user-attachments/assets/7eab63d6-0eed-4b61-8daa-837eb2d887a2" />

**Flag Answer:** WMIC logical disk enumeration

---

## Flag 6 — Connectivity & Name Resolution Check

### Objective:

Detect indicators of outbound connections and DNS resolution attempts. 

### Finding:

Connectivity checks were traced back to processes parented by RuntimeBroker.exe.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") 
| where ProcessCommandLine has_any ("ping","nslookup")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```
<img width="936" height="166" alt="image" src="https://github.com/user-attachments/assets/9115cb3b-f967-4ec9-a80a-234e785aaa1b" />

**Flag Answer:** RuntimeBroker.exe

---

## Flag 7 — Interactive Session Discovery

### Objective:

Detect active user session enumeration.

### Finding:

Session enumeration was tied to a specific initiating process.

**Query Used:**  
```
DeviceProcessEvents 
| where DeviceName == "gab-intern-vm" 
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15)) 
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") 
| where ProcessCommandLine contains "query session"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
```
<img width="1173" height="63" alt="image" src="https://github.com/user-attachments/assets/9cc4e4de-b72a-4455-a1e3-4d651853048b" />

**Flag Answer:** InitiatingProcessUniqueId 2533274790397065

---

## Flag 8 — Runtime Application Inventory

### Objective:

Detect enumeration of running applications and services to inform risk and opportunity.

### Finding:

The attacker listed running applications using tasklist.exe. 

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("tasklist")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="559" height="62" alt="image" src="https://github.com/user-attachments/assets/79a1d2f7-7f74-490c-9e5e-3271304bec8b" />

**Flag Answer:** tasklist.exe

---

## Flag 9 — Privilege Surface Check

### Objective:

Detect privilege mapping attempts.

### Finding:

Privilege enumeration first detected at 2025-10-09T12:52:14.3135459Z. 

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("whoami", "whoami /priv", "whoami /groups", "net user")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="584" height="259" alt="image" src="https://github.com/user-attachments/assets/e6b9a6b6-f2be-406f-ae3f-69a7adda9e25" />

**Flag Answer:** 2025-10-09T12:52:14.3135459Z

---

## Flag 10 — Proof-of-Access & Egress Validation

### Objective:

Collect evidence of outbound network checks and artifacts created as proof that the actor can view or collect host data.

### Finding:

Final instance of outbound connectivity was to www.msftconnecttest.com (IP = 23.218.218.182) over port 80. 

### Query Used:
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1191" height="116" alt="image" src="https://github.com/user-attachments/assets/462e8997-8f8e-4f9b-810d-7ad88ae7a51d" />

**Flag Answer:** www.msftconnecttest.com

---

## Flag 11 — Bundling / Staging Artifacts

### Objective:

Detect consolidation of artifacts into a single location or package for transfer.

### Finding:

Recon artifacts were bundled into a ZIP file.

### Query Used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| where ActionType == "FileCreated"
| where FileName contains ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="1004" height="59" alt="image" src="https://github.com/user-attachments/assets/5083786f-0fa5-49f5-893b-dc7b6926e4fd" />

**Flag Answer:** C:\Users\Public\ReconArtifacts.zip

---

## Flag 12 — Outbound Transfer Attempt (Simulated)

### Objective:

Identify attempts to move data off-host or test upload capability.

### Finding:

After ReconArtifacts.zip was created, there were connection attempts to the outbound IP 100.29.147.161. No successful file upload confirmed. 

### Query Used:
```
DeviceNetworkEvents 
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where InitiatingProcessCommandLine == "\"powershell.exe\" "
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe")
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
```
<img width="1288" height="92" alt="image" src="https://github.com/user-attachments/assets/eee8c1df-c2cd-47fa-82a6-8c8334abcb8e" />

**Flag Answer:** 100.29.147.161

---

## Flag 13 — Scheduled Re-Execution Persistence

### Objective:

Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

### Finding:

A scheduled task named SupportToolUpdater ensured continued execution.

### Query Used:
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| where ProcessCommandLine has_any ("schtasks", "Create")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="1406" height="233" alt="image" src="https://github.com/user-attachments/assets/1565c419-8d93-4077-a340-707b76ac2846" />

**Flag Answer:** SupportToolUpdater

---

## Flag 14 — Autorun Fallback Persistence

### Objective:

Detect lightweight autorun entries placed as backup persistence in user scope.

### Finding:

Unable to retrieve autorun registry record in the available data due to data retention expiry. CTF Admin confirm RemoteAssistUpdater.

### Query Used:
```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```
<img width="330" height="85" alt="image" src="https://github.com/user-attachments/assets/912a7b7b-4c72-47df-9405-84d72c4626ed" />

**Flag Answer:** RemoteAssistUpdater

---

## Flag 15 — Planted Narrative / Cover Artifact

### Objective:

Identify narrative or misdirection artifacts.

### Finding:

A shortcut file, SupportChat_log.lnk, was created and accessed. implying/mimicking help desk session. 

### Query Used:
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where ActionType == "FileCreated" 
    or ActionType == "FileModified"
| where FileName endswith ".txt" 
    or FileName endswith ".lnk" 
    or FileName endswith ".log"
| project TimeGenerated, FileName, ActionType, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="987" height="144" alt="image" src="https://github.com/user-attachments/assets/5d938ada-bd17-4bff-b0b9-295b2ea5cc55" />

**Flag Answer:** SupportChat_log.lnk

---

# MITRE ATT&CK Mapping

| Flag | Technique ID        | Technique Name                         | Description                               |
|------|----------------------|-----------------------------------------|-------------------------------------------|
| 1    | T1059.001           | PowerShell                              | Script executed with execution policy bypass |
| 2    | T1036               | Masquerading                            | Fake Defender tamper artifact             |
| 3    | T1115               | Clipboard Collection                    | Clipboard probing                         |
| 4,7  | T1033 / T1087       | Account & Session Discovery             | Session/user enumeration                  |
| 5    | T1083               | File and Directory Discovery            | Storage enumeration                       |
| 6,10 | T1016               | Network Discovery                       | Connectivity and DNS checks               |
| 8    | T1057               | Process Discovery                       | tasklist / process enumeration            |
| 9    | T1069               | Permission Group Discovery              | whoami group mapping                      |
| 11   | T1074               | Data Staging                            | Recon data archived                       |
| 12   | T1567               | Exfiltration Over Web                   | Outbound transfer attempt                 |
| 13   | T1053.005           | Scheduled Task                          | Persistence via SupportToolUpdater        |
| 14   | T1547.001           | Registry Run Key                        | Autorun fallback persistence              |
| 15   | T1036.004           | Masquerading: Deception Artifact        | Fake support chat log                     |

---

# Lessons Learned

User directories remain among the highest-risk execution points.
Fake artifacts can distort later investigations.
Intern-operated systems require enhanced monitoring.
Telemetry gaps (registry/log rollover) hinder complete analysis.

---

# Recommendations

1. Quarantine infected endpoints.
2. Delete SupportTool.ps1, DefenderTamperArtifact.lnk, ReconArtifacts.zip, and SupportChat_log.lnk.
3. Remove SupportToolUpdater and registry key RemoteAssistUpdater
4. Enforce PowerShell restrictions and enable script block logging.
5. Block script execution from Downloads using AppLocker.
6. Harden intern systems with least privilege + mandatory MFA.
7. Monitor for recon commands (qwinsta, whoami, wmic, tasklist).
8. Restrict outbound traffic to known-good destinations.
9. Detect ZIP creation in public user paths.
10. Alert on scheduled task creation and Run key changes.
11. Train users on fake support session social engineering patterns.
