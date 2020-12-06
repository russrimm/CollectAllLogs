# CollectAllLogs

CollectAllLogs is designed to be used with the **Run Scripts** feature of MECM (SCCM). It will collect many logs from a device or collection of devices, upload them to
a management point, and send a status message of **1234** which in turn will cause the primary to copy the zip from the management point to an output directory of choice to store all of the zipped up logs.

The logs which are currently collectable by this solution are as follows:

- SCCM Client
- WindowsUpdate
- Windows Defender Logs and all output from [-GetFiles](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/collect-diagnostic-data)
- Edge Updates
- Windows Servicing (from in-place upgrades)
- DISM (Deployment Image Servicing and Management)
- CBS (Component Based Servicing)
- OneDrive
- System Eventlog
- PNP Driver Package enumeration
- PNP Device enumeration
- Application Eventlog
- Admin/Operational Device Management Diagnostics Eventlogs
- MDMDiagnosticsTool area outputs for
  - Autopilot
  - Device Provisioning
  - Device Enrollment
- Intune Management Extension
- Symantec Antivirus Exclusions
- Registry exports from
  - Windows Updates
  - Language Packs
  - Delivery Optimization
  - Windows as a Service
  - Windows Setup

1. Copy Microsoft.ConfigurationManagement.Messaging.dll to <ConfigMgr Installation Dir>\CCM\Incoming\MessagingDll and \SMS_CCM\Temp on each Management Point
2. Create a new “Run Script” using the contents of the script “CollectAllLogs.ps1” and approve it. If you aren't able to approve your own script, there is a checkbox in Hierarchy Settings to allow you to. _THIS STEP IS A BUSINESS DECISION_. As a best practice, only approve your own scripts if you're a proven perfectionist, or you have a true lab.
3. Place the MoveLogtoPrimary.ps1 script to the primary site server in a directory of choice - let's refer to it as <ScriptsDir>.
4. Create a directory for logs - let's refer to it as <CollectAllLogsDir>.
5. Create a status filter rule with Message ID _1234_ (Image-1)
   ![Image-1](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img1.png "Image-1")
6. On the Actions Tab, check the box for “Run a Program”
   Command line:
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass -file "<ScriptsDir>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -PrimaryLogFolder <CollectAllLogsDir>
7. Move status filter rule up in priority to the top
8. Right-click a single device or a collection of devices in the MECM console
9. Click _Run Script_
10. Select the _Collect All Logs_ script (Image-2)
    ![Image-2](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img2.png "Image-2")
11. Check the path chosen at <CollectAllLogsDir> for a .zip file after a few minutes
