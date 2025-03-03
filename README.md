<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/priya48011/threat-hunting-scenario-tor/blob/main/Threat%20Hunting%20Folder/Threat_Hunt_Event_(TOR%20Usage).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents Table for ANY file that had the string “tor” in it and discovered what looks like the user “priya” downloaded a tor installer, did something that resulted in many tor related files being copied to desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-03-03T00:59:20.1157225Z. These events began at : 2025-03-02T05:38:41.4752944Z

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "win10irpriya"
|where FileName contains "tor"
|where InitiatingProcessAccountName == "priya"
|where Timestamp >= datetime(2025-03-02T05:38:41.4752944Z)
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
|order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-14.0.6.exe”. Based on the logs returned, At 
2025-03-02T05:43:08.0346809Z, the user 'priya' on the device 'win10irpriya' initiated the execution of a file named 'tor-browser-windows-x86_64-portable-14.0.6.exe' located in the 'C:\Users\priya\Downloads' directory, using a command that triggered a silent installation.


**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "win10irpriya"
|where ProcessCommandLine contains"tor-browser-windows-x86_64-portable-14.0.6.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256,ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “priya” actually opened the tor browser. There was evidence that they did open it at: 2025-03-02T05:45:31.9957274Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "win10irpriya"
|where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe" )
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName, ProcessCommandLine
|order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DevinceNetworkEvents table for any indication the tor browser was used to establish a connection, using of any tor ports. At 2025-03-02T05:45:44.6577035Z, the user 'priya' on the device 'win10irpriya' initiated a successful network connection from the application 'tor.exe' located at 'c:\users\priya\desktop\tor browser\browser\torbrowser\tor\tor.exe'. This connection was established to the remote IP address 202.169.99.195 on port 9001. There were a couple other connections as well. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "win10irpriya"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
|where RemotePort in("9001", "9030", "9040","9050", "9150", "9158", "88", "443")
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-02T05:38:41.4752944Z`
- **Event:** The user “priya” downloaded a file named “tor-browser-windows-x86_64-portable-14.0.6.exe” to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\priya\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-02T05:43:08.0346809Z`
- **Event:** The user "priya" executed the file “tor-browser-windows-x86_64-portable-14.0.6.exe” in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\priya\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-02T05:45:31.9957274Z`
- **Event:** User "priya" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\priya\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-02T05:45:44.6577035Z`
- **Event:** A network connection to IP “202.169.99.195” on port “9001” by user "priya" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\priya\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-02T05:45:57.0201471Z` - Local connection to '127.0.0.1' on port '9150'.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "priya" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-03T00:59:20.1157225Z`
- **Event:** The user "priya" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\priya\Desktop\tor-shopping-list.txt`

---

## Summary

The user "priya" on the "win10irpriya" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `win10irpriya` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
