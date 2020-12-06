# CollectAllLogs

## Features
CollectAllLogs is designed to be used with the **Run Scripts** feature of MECM (SCCM). It will collect many logs from a device or collection of devices, upload them to
a management point, and send a status message of **1234** which in turn will cause the primary to copy the zip from the management point to an output directory of choice to store all of the zipped up logs.

The logs which are currently collectable by this solution are as follows:

| MECM | Windows Update | Base OS |        MDM       |    O365   |3rd Party|
|:-------------:|:----------------:|:-------------:|:------------------:|:-----------:|:---------:|
|MECM Client Logs|Windows Update Registry Settings|Windows Setup|MDMDiagnosticsTool \(provisioning, enrollment, autopilot\)|OneDrive Logs|Symantec Antivirus Exclusions|
|             |WUA GPO Settings|PNP Drivers|MDM Eventlogs | | | |
|             |CBS.LOG         |PNP Devices|Device Provisioning | | |
|             |WUA Version Info|System Eventlog|   Device Enrollment | | |
|             |Edge Updates |Application Eventlog|Intune Management Extension Logs| | |
|             |                |Language Packs| | | |
|             |                |Delivery Optimization||||
|             |                |Windows Servicing (Feature Upgrades)| | | |
|             |                |   DISM.LOG   | | | |
|             |                |WaaS | | | |
|             |                |Registry.POL corruption<sup>1</sup> | | | |
|             |                |Windows Defender Logs | | | |
|             |                |Windows Defender Diagnostic Data<sup>2</sup>| | | |
|             |                |Windows Setup Registry | | | | 


<sup>1</sup> ***Corruption of REGISTRY.POL is known to cause GPOs and Software Updates to fail indefinitely until resolved.***
<sup>2</sup> See [-GetFiles](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/collect-diagnostic-data) for more details.

CollectAllLogs wouldn't exist without the original idea and fully functional starting script provided by the *brilliant* MECM Guru David Anderson, Customer Engineer (he's really a PFE).  His wizardy and mastery of Powershell scripting facilitated the complete plumbing and initial foundation of this utility.

## Installation Instructions
1. Copy **Microsoft.ConfigurationManagement.Messaging.dll** to \<***ConfigMgr Installation Dir***\>\CCM\Incoming\MessagingDll and \SMS_CCM\Temp on each Management Point
2. Create a new **Run Script** using the contents of the script **CollectAllLogs.ps1** and approve it. If you aren't able to approve your own script, there is a checkbox in Hierarchy Settings to allow you to. ***THIS STEP IS A BUSINESS DECISION***. As a best practice, only approve your own scripts if you're a proven perfectionist, or you have a true lab.
3. Place the MoveLogtoPrimary.ps1 script to the primary site server in a directory of choice - let's refer to it as ScriptsDir>.
4. Create a directory for logs - let's refer to it as \<***CollectAllLogsDir***\>.
5. Create a status filter rule with Message ID **1234**

   ![Image-1](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img1.png "Image-1")

6. On the Actions Tab, check the box for “Run a Program”
   Command line:
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File "\<*ScriptsDir*\>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -PrimaryLogFolder \<CollectAllLogsDir\>
7. Move status filter rule up in priority to the top
8. Right-click a single device or a collection of devices in the MECM console
9. Click **Run Script**
10. Select the **Collect All Logs** script created in step 2

    ![Image-2](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img2.png "Image-2")

11. Monitor the path chosen for \<***CollectAllLogsDir***\> for a .zip file after a few minutes containing all of the log files, eventlogs, registry exports, and system information which will be named \<***ComputerNameMM-DD-YYYYHHMMSS***\>.zip.  In my lab, these zip files range from 12MB to 60MB in size depending on the data collected, log historical retention settings and eventlog settings.  It is recommended to test this on smaller collections (<10 clients) to determine what, if any, impact will be noticed by the enduser and network overseers.

