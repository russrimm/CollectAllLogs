# CollectAllLogs

CollectAllLogs is designed to be used with the **Run Scripts** feature of MECM (SCCM). It will collect many logs from a device or collection of devices, upload them to
a management point, and send a status message of **1234** which in turn will cause the primary to copy the zip from the management point to an output directory of choice to store all of the zipped up logs.

The logs which are currently collectable by this solution are as follows:

- SCCM Client
- WindowsUpdate
- Windows Defender
- Edge Updates
- Windows Servicing (from in-place upgrades)
- DISM (Deployment Image Servicing and Management)
- CBS (Component Based Servicing)
- OneDrive
- System Eventlog
- PNP Driver Package enumeration
- PNP Device enumeration
- Application Eventlog
- MDMDiagnosticsTool outputs for
  - Autopilot
  - Device Provisioning
  - Device Enrollment
- Intune Management Extension
- Symantec Antivirus Exclusions

1. Copy Microsoft.ConfigurationManagement.Messaging.dll to <ConfigMgr Installation Dir>\CCM\Incoming\MessagingDll and \SMS_CCM\Temp on each Management Point
2. Create a new “Run Script” using the contents of the script “CollectAllLogs.ps1” and approve it.
3. Place the MoveLogtoPrimary.ps1 to the primary site server in a <SCRIPTSDIR> of choice.
4. Create a directory for logs <COLLECTALLLOGSDIR>
5. Create a status filter rule with Message ID 1234
6. On the Actions Tab, check “Run a Program”
   Command line:
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass -file "<SCRIPTSDIR>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -PrimaryLogFolder <COLLECTALLLOGSDIR>
7. Move status filter rule up in priority to the top
8. Right-click a device or collection in the MECM console
9. Click Run Script
10. Select the “Collect All Logs” script
11. Check the path chosen at <CollectAllLogsDir> for a .zip file after a few minutes
