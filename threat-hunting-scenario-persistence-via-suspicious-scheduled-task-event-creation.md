# Threat Event (Persistence via Suspicious Scheduled Task)
**Suspicious Powershell Scripts to Establish Persistence**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Create a .bat file to deploy a payload for persistence  
```Set-Content -Path "C:\Users\Public\not-a-virus.bat" -Value "echo Hello from the scheduled task >> C:\Users\Public\task-output.txt"```
2. Create a Scheduled Task that executes the script daily  
```schtasks /create /tn "WindowsSystemCheck" /tr "C:\Users\Public\not-a-virus.bat" /sc daily /st 12:00```
3. Trigger the task  
```schtasks /run /tn "WindowsSystemCheck"```
4. Delete the scheduled task
```schtasks /delete /tn "WindowsSystemCheck" /f```
5. Delete the .bat file
```Remove-Item "C:\Users\Public\not-a-virus.bat" -Force```
---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect the download, file creation, movement, and deletion actions. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect the launch and runtime of scheduled tasks.|

---

## Related Queries:
```kql
// Detect creation or modification of .bat files
DeviceFileEvents
| where FileName endswith ".bat"
| where FolderPath has @"C:\Users\Public"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256

// Detect execution of the .bat file
DeviceProcessEvents
| where FileName endswith ".bat"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256

// Detect schtasks.exe usage
DeviceProcessEvents
| where FileName == "schtasks.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, SHA256

// Detect deletion of the task file
DeviceFileEvents
| where FileName == "not-a-virus.bat" and ActionType == "FileDeleted"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256
```

---

## Created By:
- **Author Name**: Nick Pamatian
- **Author Contact**: https://www.linkedin.com/in/nick-pamatian-b8828b28a/
- **Date**: April 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 19, 2025`  | `Nick Pamatian`    
