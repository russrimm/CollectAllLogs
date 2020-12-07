# CollectAllLogs
A script developed by Microsoft Customer Engineers [Russ Rimmerman](mailto://russ.rimmerman@microsoft.com) and David Anderson.
## Features
CollectAllLogs is designed to be used with the **Run Scripts** feature of MECM (SCCM). The purpose of CollectAllLogs is to quickly and easily collect a very extensive list of logs, registry settings, and a variety of other diagnostic data from a device or collection of devices.  CollectAllLogs also works on clients which are connected to Cloud Management Gateway. Once deployed, the client will compress the payload and upload it using BITS to the client's assigned Management Point. Finally, a status message will be sent, triggering the parent site server to copy the compressed ZIP file from the Management Point to a configurable destination directory of choice.

>Note: This script has not yet been tested thoroughly in a hierarchy (with a CAS).  If you have a CAS you will need to edit line 73 of MoveLogToPrimary.ps1 to reflect where you want your logs stored. Please provide feedback if you test the solution in a hierarchy.

The logs, registry settings, and diagnostic data which can currently be collected are as follows:

| MECM | Windows Update | Base OS |        MDM       |    Office365   |3rd Party|
|:-------------:|:----------------:|:-------------:|:------------------:|:-----------:|:---------:|
|MECM Client Logs|Windows Update Registry Settings|Windows Setup|MDMDiagnosticsTool \(provisioning, enrollment, autopilot\)|OneDrive Logs|Symantec Antivirus Exclusions|
|MECM Client Registry Keys|Windows Update GPO Settings|PNP Devices & Drivers|MDM Eventlogs | | | |
|MobileClient.TCF|CBS.LOG         |Filter Drivers|Device Provisioning & Enrollment | | |
|CCMStore.SDF |Windows Update Agent Version Info|Eventlogs (System/App/Setup)|Intune Management Extension Logs| | |
|             |Edge Updates |Processes & Services|| | |
|             |Update Install Sources|Language Packs| | | |
|             |Update Install History|Delivery Optimization||||
|             |                |Windows Servicing (Feature Upgrade) & SetupDiag Logs| | | |
|             |                |DISM.LOG   | | | |
|             |                |WaaS | | | |
|             |                |Registry.POL corruption<sup>1</sup> | | | |
|             |                |Windows Defender Logs | | | |
|             |                |Windows Defender Diagnostic Data<sup>2</sup>| | | |
|             |                |Windows Setup Registry | | | | 
|             |                |BCD Store| | | |
|             |                |Disks/Volumes| | | |


<sup>1</sup> ***Corruption of REGISTRY.POL is known to cause GPOs and Software Updates to fail indefinitely until resolved. Registry.POL corruption is typically caused by antivirus exclusions not excluding it.***

<sup>2</sup> See [Collect Microsoft Defender AV diagnostic data](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/collect-diagnostic-data) for more details.

CollectAllLogs wouldn't exist without the original idea and fully functional starting script provided by the *brilliant and fearless* MECM Guru David Anderson, PFE/CE.  David's mastery of Powershell scripting facilitated the complete plumbing and initial foundation of this utility.

## Installation Instructions

First, start by reviewing lines 31-43 in CollectAllLogs.ps1 to determine if there are any logs you do not need.  If you set them to 'No', that section will not execute.  Otherwise, the default is to log everything except Symantec Antivirus Exclusions.

$GatherSystemInfo = 'Yes'
$GatherBaseSCCMLogs = 'Yes'
$GatherWindowsUpdateLogs = 'Yes'
$GatherDefenderLogs = 'Yes'
$GatherEdgeUpdateLogs = 'Yes'
$GatherLogsRelatedToWindowsServicing = 'Yes'
$GatherOneDriveLogs = 'Yes'
$SendStatusMessage = 'Yes'
$DumpSystemEventLog = 'Yes'
$DumpSystemAppLog = 'Yes'
$GatherSepExclusions = 'No'
$GatherMDMDiagnostics = 'Yes'
$SentstatusMessage = 'No'

1. Copy **Microsoft.ConfigurationManagement.Messaging.dll** to \<***ConfigMgr Installation Dir***\>\CCM\Incoming\MessagingDll on each Management Point. This directory will need created.
2. In Software Library, create a new **Run Script** using the contents of the script **CollectAllLogs.ps1** and approve it. If you aren't able to approve your own script, there is a checkbox in Hierarchy Settings to allow you to. ***CHANGING THIS CONFIGURATION SHOULD BE A BUSINESS DECISION***. As a best practice, only approve your own scripts if you're a proven perfectionist, or you have a true lab.
3. Place the **MoveLogtoPrimary.ps1** script to the primary site server in a directory of choice - going forward referred to as \<***ScriptsDir***\>.
4. Create a directory for logs - going forward referred to as \<***CollectAllLogsDir***\>.
5. On the **General** tab, create a status filter rule with Message ID **1234**.

   ![Image-1](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img1.png "Image-1")

6. On the **Actions** tab, check the **Run a program** box.
7. Enter the following command line into the **Program** blank and click **Ok**.

  > **C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "\<***ScriptsDir***\>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -PrimaryLogFolder ***\<CollectAllLogsDir\>*****


   ![Image-2](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img3.png "Image-2")

8. Move the new status filter rule up in priority somewhere towards the top.
9. Right-click a single device or a collection of devices in the MECM console.
10. In Software Library, Click **Run Script**.
11. Select the **Collect All Logs** script created in step 2 and click **Next** twice.

    ![Image-3](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img2.png "Image-3")

12. Monitor the path used for \<***CollectAllLogsDir***\> for a .zip file after around 5 minutes containing all of the requested files, eventlogs, registry exports, and system information which will be named \<***ComputerNameMM-DD-YYYYHHMMS\>.zip***.  In my lab, these zip files range from 12MB to 60MB in size depending on the data collected, log historical retention settings and eventlog settings.  It is recommended to test this on smaller collections (<10 clients) to determine what, if any, impact will be noticed by the enduser and network overseers.

If you have any additional ideas for logs or other diagnostics to collect, please feel free to contribute to this wonderful utility.

## Appendix
# Windows Defender Logs

>MPDetection*.log shows product, engine, service, and definition version updates and times
>MSSupportFiles.cab contains a significant amount of in-depth files for analysis for Windows Defender health and activities.