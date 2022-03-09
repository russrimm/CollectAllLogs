# CollectAllLogs

## Features
The purpose of CollectAllLogs is to quickly and effortlessly collect a very extensive list of logs, registry settings, and a variety of other diagnostic data from a single device or collection of devices.  The CollectAllLogs script is designed to be pushed to clients using the **Run Scripts** feature of Microsoft Endpoint Configuration Manager (MECM/SCCM/ConfigMgr).  CollectAllLogs also works on clients which are remotely connected by way of Cloud Management Gateway (CMG) (with PKI only. Enhanced HTTP is not yet supported as the client will gather, but not upload). Once the CollectAllLogs script is pushed to a client using the Run Scripts functionality, the client will gather, compress and upload a compressed ZIP file (using BITS) to the client's currently assigned Management Point. Finally, a status message will be sent up which triggers a status filter rule on the site server that moves the compressed ZIP file from the Management Point to a configurable local path or UNC share of choice.

>Note: This script has not yet been tested thoroughly in a hierarchy (with a CAS).  If you have a CAS you will need to edit line 73 of MoveLogToPrimary.ps1 to reflect where you want your logs stored. Please provide feedback if you test the solution in a hierarchy.

The logs, registry settings, and diagnostic data which can currently be collected are as follows:

| MECM | Windows Update | Base OS |        MDM       |    Office365   |3rd Party|
|:-------------:|:----------------:|:-------------:|:------------------:|:-----------:|:---------:|
|MECM Client Logs|Windows Update Agent Version, Install Sources, Install History, Registry & GPO Settings|Windows Setup|MDM Diagnostics Tool \(provisioning, enrollment, autopilot\) output|OneDrive Logs|Symantec Antivirus Exclusions|
|MECM Client Registry Keys|Edge Updates|PNP Devices & Drivers|MDM Eventlogs | | | |
|MobileClient.TCF|CBS.LOG         |Filter Drivers|AAD Device Provisioning | | |
|CCMStore.SDF ||Eventlogs (System/Application)|Intune Policies, Enrollment Status, & Management Extension Logs| | |
|             | |Running Processes & Services|| | |
|             ||Language Packs|| | |
|             |                |Delivery Optimization||||
|             |                |Windows Servicing & SetupDiag Logs| | | |
|             |                |DISM.LOG   | | | |
|             |                |WaaS | | | |
|             |                |Registry.POL corruption<sup>1</sup> | | | |
|             |                |Windows Defender Logs, Preferences, & Diagnostic Data<sup>2</sup> | | | |
|             |                |Disk/Volume Info| | | |
|             |                |Windows Setup Registry values| | | | 
|             |                |BCD Store| | | |
|             |                || | | |
|             |                || | | |


<sup>1</sup> ***Corruption of REGISTRY.POL is known to cause GPOs and Software Updates to fail indefinitely until resolved. Registry.POL corruption is typically caused by antivirus exclusions not excluding it.***

<sup>2</sup> See [Collect Microsoft Defender AV diagnostic data](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/collect-diagnostic-data) for more details.

## Installation Instructions

First, start by reviewing lines 24-37 in CollectAllLogs.ps1 to determine if there are any logs you do not need.  If there are, set them to 'No' so that bit of collection will not happen.  Otherwise, everything is 'Yes' by default except for Symantec Antivirus Exclusions.

1. Copy the file **Microsoft.ConfigurationManagement.Messaging.dll** from \<***ConfigMgr Installation Dir***\AdminConsole\bin\ to \<***ConfigMgr Installation Dir***\>\CCM\Incoming\MessagingDll on each Management Point. The \CCM\Incoming should already exist on each MP, but the MessagingDll directory will need created.
2. In Software Library, create a new **Run Script** using the contents of the script **CollectAllLogs.ps1** and approve it. If you aren't able to approve your own script, there is a checkbox in Hierarchy Settings to allow you to. ***CHANGING THIS CONFIGURATION SHOULD BE A BUSINESS DECISION***. As a best practice, only approve your own scripts if you're a proven perfectionist, or you have a true lab.
3. Place the **MoveLogtoPrimary.ps1** script into the primary site server in a directory of choice - going forward referred to as \<***ScriptsDir***\>.
4. Create a directory for logs - going forward referred to as \<***CollectAllLogsDir***\>.  \<***CollectAllLogsDir***\> can either be a local path on the site server, or a UNC path on a remote server. The only requirement is that the site server's computer account must have create rights to this destination share.
5. In the ConfigMgr Admin Console, go to Administration, Sites, Select the Site, and click Status Filter Rules.  
6. On the **General** tab, create a status filter rule with Message ID **1234**.

   ![Image-1](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img1.png "Image-1")

7. On the **Actions** tab, check the **Run a program** box.
8. Enter the following command line into the **Program** blank and click **Ok**.

  > **C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "\<***ScriptsDir***\>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -LogFolder ***\<CollectAllLogsDir\>*****


   ![Image-2](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img5.png "Image-2")

9. Right-click a single device or a collection of devices in the MECM console. In Software Library, Click **Run Script**.
10. Select the **Collect All Logs** script created in step 2 and click **Next** twice.

    ![Image-3](https://rimcoblob.blob.core.windows.net/blogimg/CollectAllLogs/img2.png "Image-3")

10. Monitor the path used for \<***CollectAllLogsDir***\> for a .zip file after around 5 minutes containing all of the requested files, eventlogs, registry exports, and system information which will be named \<***ComputerNameMM-DD-YYYYHHMMS\>.zip***.  In my lab, these zip files range from 12MB to 60MB in size depending on the data collected, log historical retention settings and eventlog settings.  It is recommended to test this on smaller collections (<10 clients) to determine what, if any, impact will be noticed by the enduser and network overseers.

If you have any additional ideas for logs or other diagnostics to collect, please feel free to contribute to this wonderful utility.

## Credits
The CollectAllLogs script was developed by Microsoft Customer Engineers [Russ Rimmerman](mailto://russ.rimmerman@microsoft.com) and David Anderson. CollectAllLogs wouldn't exist without the original idea and fully functional starting script provided by the *brilliant and fearless* MECM Guru David Anderson, PFE/CE.  David's mastery of Powershell scripting facilitated the complete plumbing and initial foundation of this utility.

## Appendix
## Windows Defender Logs

>MPDetection*.log shows product, engine, service, and definition version updates and update times.
>MSSupportFiles.cab contains a significant amount of in-depth files for analysis for Windows Defender health and activities.
