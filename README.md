
# Threat Hunt Report: Persistence via Suspicious Scheduled Task
- [Scenario Creation](https://github.com/nickpamatian/threat-hunting-scenario-persistence-via-suspicious-scheduled-task/blob/main/threat-hunting-scenario-persistence-via-suspicious-scheduled-task-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
  
##  Scenario

Management has noticed unusual file activity and the creation of scheduled tasks across multiple endpoints in the network. There are concerns that an attacker might have established persistence by creating suspicious batch files and setting them to execute regularly. Recent monitoring also shows the use of schtasks.exe in ways that are inconsistent with normal administrative tasks. If any suspicious tasks or files are found, they should be flagged for immediate review and action.


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** to detect the download, file creation, movement, and deletion actions of suspicious tasks or files. 
- **Check `DeviceProcessEvents`** to detect the launch and runtime of scheduled tasks.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table to detect creation or modification of .bat files

A `not-a-virus.bat` file was created at 2025-04-19T02:48:19.2837723Z on the endpoint “apoy-threat-hun” being created by user "apoy”. The file's presence in this location is unusual, and prompted further investigation. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName endswith ".bat"
| where FolderPath has @"C:\Users\Public"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256


```
![image](https://github.com/user-attachments/assets/c8e728f6-3f67-4183-bf23-a4f2b4b03e22)

---

### 2. Searched the `DeviceProcessEvents` table to detect execution of the .bat file

Did not detect direct execution of the `not-a-virus.bat` file on the endpoint. This suggests that the file may not have been run manually. The next logical step is to investigate the possibility that the file is being executed through alternative methods.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where FileName == "not-a-virus.bat"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256


```
![image](https://github.com/user-attachments/assets/c41ba666-8903-4047-b572-dddf23eba01a)

---

### 3. Searched the `DeviceProcessEvents` table to detect schtasks.exe usage

The file not-a-virus.bat was executed through a scheduled task. The user created schtasks.exe at 2025-04-19T02:58:04.5905556Z and launched the task at 2025-04-19T02:58:12.7256133Z, effectively disguising its execution. Afterward, the user immediately deleted schtasks.exe at 2025-04-19T02:58:58.456802Z.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ActionType, ProcessCommandLine, SHA256

```
![image](https://github.com/user-attachments/assets/698f6740-dc6b-4bf0-b74c-b4bd1d7845ab)

---

### 4. Searched the `DeviceFileEvents` table to detect deletion of the .bat file

No deletion event for not-a-virus.bat was detected, suggesting it may remain available for future use or reactivation.
Query used to locate events: 


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName == "not-a-virus.bat" and ActionType == "FileDeleted"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256

```
![image](https://github.com/user-attachments/assets/546a1ef9-33ee-4591-b08a-195fe7925c38)

---

## Chronological Event Timeline

### 1. File Creation - Suspicious Batch File

- **Timestamp:** `2025-04-18T21:48:19.2837723Z`  
- **Event:** User "apoy" created a file named `not-a-virus.bat` on endpoint `apoy-threat-hun`.  
- **Action:** File creation detected.  
- **File Path:** `C:\Users\Public\not-a-virus.bat`  
- **Note:** The file's placement in a shared public directory raised suspicions and triggered further investigation.

---

### 2. Scheduled Task Creation - WindowsSystemCheck

- **Timestamp:** `2025-04-18T21:48:39.000Z`  
- **Event:** User "apoy" created a scheduled task named `WindowsSystemCheck` to run the `not-a-virus.bat` script daily at 12:00 PM using the `schtasks.exe` utility.  
- **Action:** Task creation detected.  
- **Command Executed:**  
  `schtasks.exe /create /tn WindowsSystemCheck /tr C:\Users\Public\not-a-virus.bat /sc daily /st 12:00`

---

### 3. Scheduled Task Execution - WindowsSystemCheck

- **Timestamp:** `2025-04-18T21:48:51.000Z`  
- **Event:** User "apoy" manually ran the scheduled task `WindowsSystemCheck`, executing the `not-a-virus.bat` file.  
- **Action:** Scheduled task executed.  
- **Command Executed:**  
  `schtasks.exe /run /tn WindowsSystemCheck`

---

### 4. Scheduled Task Deletion - WindowsSystemCheck

- **Timestamp:** `2025-04-18T21:50:42.000Z`  
- **Event:** User "apoy" deleted the scheduled task `WindowsSystemCheck` using the `/f` (force) flag.  
- **Action:** Scheduled task deleted.  
- **Command Executed:**  
  `schtasks.exe /delete /tn WindowsSystemCheck /f`


---

## Summary

On April 18, 2025, user "apoy" on the device "apoy-threat-hun" engaged in actions that involved the creation, execution, and deletion of a scheduled task related to the file "not-a-virus.bat." The file was initially created in the C:\Users\Public directory, a location that raised suspicion. The user proceeded to create a scheduled task using schtasks.exe to execute the "not-a-virus.bat" file daily at 12:00 PM. After execution, the task was deleted immediately. This pattern of creating, executing, and deleting the task suggests an attempt to persistently run the file without leaving traces of its existence after execution, aligning with tactics used for stealth persistence. The deletion of "not-a-virus.bat" was not detected, which may have suggested reuse if not detected. 


---

## Response Taken

Device apoy-threat-hun was isolated to prevent further execution of suspicious tasks. User’s direct manager was notified to take appropriate internal actions. Further investigation into the file and scheduled task activity commenced, with a focus on identifying potential escalation paths and understanding the nature of the threat. The situation was escalated to higher-level security teams for deeper analysis and remediation steps.


---
