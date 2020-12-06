<#
.SYNOPSIS
    Automatically collect various logs, registry settings, and diagnostic data from client machines.
    
.DESCRIPTION
    A complete script that collects key troubleshooting data from endpoints.
     
.EXAMPLES
    .\SCCM-ClientHealthMonitor.ps1 -TestProvMode -TestGPOFiles (this will run the test and remediation for both options and log to file locally)

    .\SCCM-ClientHealthMonitor.ps1 -TestProvMode -TestGPOFiles -SendEmail (this will run the test and remediation for both options and log to file locally and send an email with the log attached)

    .\SCCM-ClientHealthMonitor.ps1 -TestSCCMClient -TestBITS -TestProvMode -TestGPOFiles -InstallSCCMClient -EmailStatus -TeamsStatus

.NOTES
    Filename: CollectAllLogs.ps1
    Version: 1.0
    Author: Russ Rimmerman, David Anderson

    Version history:
    1.0 - Script created

.LINKS
    The Readme can be located: https://github.com/russrimm/CollectAllLogs/blob/1.0/README.md

.CREDIT    
    This script was developed in a collaborative effort by Microsoft Customer Engineers Russ Rimmerman and David Anderson.
    
#> 

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
$GatherSpecifiedLog = "GatherNothing"
$GatherSepExclusions = 'No'
$GatherMDMDiagnostics = 'Yes'
$GatherDateCreatedRegistryPol = 'No'
$SentstatusMessage = 'No'


$UploadedClientLogs = $False

$MP = $null
$HttpMode = $null
$ClientCommunicationMode = $null
$NumericDate = Get-Date -uFormat "%m%d%Y%H%MS"            
$UplodadFileName = "$env:ComputerName-$numericdate.zip"
$CCMLogdirectory = Get-ItemProperty -Path HKLM:\Software\Microsoft\CCM\Logging\@global -Name LogDirectory | Select-Object LogDirectory -ExpandProperty LogDirectory 
$CCMTempDir = Get-ItemProperty -Path HKLM:\Software\Microsoft\CCM -Name TempDir | Select-Object TempDir -ExpandProperty TempDir           
$LogsZip = $CCMTempDir + "logs.zip"
$CCMFilestoZip = $CCMTempDir + "logs"
$ClientCommunicationMode = Get-WmiObject -Class "CCM_ClientSiteMode" -Namespace "ROOT\CCM" | Select-Object CommunicationMode -ExpandProperty CommunicationMode # 1 = intranet 2= Deprecated. We don't have always intranet client anymore 3=Internet 4=Always internet

function BuildAndSend-Registration {
    Param ([string]$ManagementPointHostName, [int]$MsgId, [string]$InsString1, [string]$InsString2, [string]$InsString3, [string]$InsString4, [string]$InsString5, [string]$InsString6)

    Write-Verbose "Building Registration to $ManagementPointHostName"
    If ((Test-Path -Path "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll")) {
        If (!(Get-Module -Name "Microsoft.ConfigurationManagement.Messaging")) {
            Import-Module "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll" -Force
        }
    }
    Else {
        Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq 'DLLDownload' | Remove-BitsTransfer #Remove BITS job if unsuccessfull in downloading messaging dll and do not send a status message
        Return
    }
    
    $Script:httpsender = New-Object Microsoft.ConfigurationManagement.Messaging.Sender.Ccm.CcmSender

    # Rolling the time back to account for the default time zone in PE being Pacific
    $ThreeHoursAgoInWmiDateTimeFormat = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($(Get-Date).AddHours(-5))

    $UnknownStatusMessage = New-Object Microsoft.ConfigurationManagement.Messaging.StatusMessages.UnknownStatusMessage
    $UnknownStatusMessage.ModuleName = 'CCMLogGatherer'
    $UnknownStatusMessage.ComponentName = 'CCMLogGatherer'
    $UnknownStatusMessage.MessageId = $MsgId
    $UnknownStatusMessage.SiteCode = $Sitecode
    $UnknownStatusMessage.InsertionString1 = $InsString1
    $UnknownStatusMessage.InsertionString2 = $InsString2
    $UnknownStatusMessage.InsertionString3 = $InsString3
    $UnknownStatusMessage.InsertionString4 = $InsString4
    $UnknownStatusMessage.InsertionString5 = $InsString5
    $UnknownStatusMessage.InsertionString6 = $InsString6


    $StatusMessage = New-Object Microsoft.ConfigurationManagement.Messaging.Messages.ConfigMgrStatusMessage
   
    #add mp name
    $StatusMessage.Settings.HostName = $ManagementPointHostName
    $StatusMessage.Settings.HttpPort = 80
    $StatusMessage.Settings.HttpsPort = 443
    $StatusMessage.Settings.MessageSourceType = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageSourceType]::Client
    $StatusMessage.Settings.SecurityMode = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageSecurityMode]::httpmode
    $StatusMessage.Settings.OverrideValidityChecks = $true
    $StatusMessage.ParseStatusMessage($UnknownStatusMessage)
    $StatusMessage.SendMessage($httpsender)

    # format string
    $PSArgsArray = @($UnknownStatusMessage.ModuleName, $UnknownStatusMessage.ComponentName, $UnknownStatusMessage.MessageId, $UnknownStatusMessage.SiteCode, $UnknownStatusMessage.DateTime, $UnknownStatusMessage.InsertionString1, `
            $UnknownStatusMessage.InsertionString2, $UnknownStatusMessage.InsertionString3, $UnknownStatusMessage.InsertionString4, $UnknownStatusMessage.InsertionString5, $UnknownStatusMessage.InsertionString6, $UnknownStatusMessage.Attribute403, `
            $StatusMessage.Settings.HostName, $StatusMessage.Settings.HttpPort)
    $WriteOutput = "'" + [string]::join("','", $PSArgsArray) + "'"

    Write-Verbose "Sending Status MSG: $writeoutput"
    $SentstatusMessage = $true
    Return $SentstatusMessage
}

Function New-ZipFile {
    #.Synopsis
    #  Create a new zip file, optionally appending to an existing zip...
    [CmdletBinding()]
    Param(
        # The path of the zip to create
        [Parameter(Position = 0, Mandatory = $true)]
        $ZipFilePath,

        # Items that we want to add to the ZipFile
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("PSPath", "Item")]
        [string[]]$InputObject = $Pwd,

        # Append to an existing zip file, instead of overwriting it
        [Switch]$Append,

        # The compression level (defaults to Optimal):
        #   Optimal - The compression operation should be optimally compressed, even if the operation takes a longer time to complete.
        #   Fastest - The compression operation should complete as quickly as possible, even if the resulting file is not optimally compressed.
        #   NoCompression - No compression should be performed on the file.
        [System.IO.Compression.CompressionLevel]$Compression = "Optimal"
    )
    Begin {
        Add-Type -As System.IO.Compression.FileSystem
        # Make sure the folder already exists
        [string]$File = Split-Path $ZipFilePath -Leaf
        [string]$Folder = $(If ($Folder = Split-Path $ZipFilePath) { Resolve-Path $Folder } Else { $Pwd })
        $ZipFilePath = Join-Path $Folder $File
        # If they don't want to append, make sure the zip file doesn't already exist.
        If (!$Append) {
            If (Test-Path $ZipFilePath) { Remove-Item $ZipFilePath }
        }
        $Archive = [System.IO.Compression.ZipFile]::Open( $ZipFilePath, "Update" )
    }
    Process {
        ForEach ($Path in $InputObject) {
            ForEach ($Item in Resolve-Path $Path) {
                # Push-Location so we can use Resolve-Path -Relative
                Push-Location (Split-Path $Item)
                # This will get the file, or all the files in the folder (recursively)
                ForEach ($file in Get-ChildItem $Item -Recurse -File -Force | ForEach-Object FullName) {
                    # Calculate the relative file path
                    $Relative = (Resolve-Path $File -Relative).TrimStart(".\")
                    # Add the file to the zip
                    $Null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($Archive, $File, $Relative, $Compression)
                }
                Pop-Location
            }
        }
    }
    End {
        $Archive.Dispose()
        Get-Item $ZipFilePath
    }
}

If ($ClientCommunicationMode -eq 1) {
    #Intranet
    $MP = Get-WmiObject -Class "CCM_Authority" -Namespace "ROOT\ccm" | Where-Object index -eq 1 | Select-Object CurrentManagementPoint -ExpandProperty CurrentManagementPoint
    If ($null -eq $MP) {
        Write-Host "Unable to determine current Management for CCM_Authority"
    }
    If ($null -ne $MP) {
        $MPCapability = Get-WmiObject -Class "SMS_ActiveMPCandidate"  -Namespace "ROOT\ccm\LocationServices" | Where-Object index -eq 1 | Where-Object MP -eq $MP | Select-Object Capabilities -ExpandProperty Capabilities
        If ($MPCapability.Contains("63")) {
            $HttpMode = "https://"
        }
        Else {
            $HttpMode = "http://"
        }

    }
}

If (($ClientCommunicationMode -eq 4) -or ($ClientCommunicationMode -eq 3)) {
    #Always Internet
   
    $MP = Get-WmiObject -Class "SMS_ActiveMPCandidate" -Namespace "ROOT\ccm\LocationServices" | Select-Object -First 1 | Select-Object MP -Expand MP
    $HttpMode = "https://"
}

$Destination = "$HttpMode$MP/ccm_Incoming"

If (Test-Path -Path $CCMFilestoZip) {
    Remove-Item -Recurse -Force $CCMFilestoZip
}

If (Test-Path -Path $LogsZip) {
    Remove-Item $LogsZip -Force
}

#Gather SystemInfo output
If ($GatherSystemInfo -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\SystemInfo | Out-Null
    Invoke-Expression -Command "$env:windir\System32\systeminfo.exe >$CCMTempDir\logs\SystemInfo\SystemInfo.log"
    Invoke-Expression -Command "reg.exe export HKLM\SYSTEM\Setup $CCMTempDir\logs\SystemInfo\registry_setup.txt"
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization $CCMTempDir\logs\SystemInfo\registry_DO.txt"
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion $CCMTempDir\logs\SystemInfo\registry_buildinfo.txt"
    Invoke-Expression -Command "reg.exe export HKLM\SYSTEM\CurrentControlSet\Control\MUI\UILanguages $CCMTempDir\logs\SystemInfo\registry_langpack.txt"    
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Superfetch $CCMTempDir\logs\SystemInfo\registry_superfetch.txt"  
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WaaSAssessment $CCMTempDir\logs\SystemInfo\registry_waasassessment.txt"  
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\WindowsSelfhost $CCMTempDir\logs\SystemInfo\registry_windowsselfhost.txt"  
    Invoke-Expression -Command "reg.exe export HKLM\Software\Microsoft\SQMClient $CCMTempDir\logs\SystemInfo\registry_sqmmachineid.txt"
    #Get Filter Drivers
    Invoke-Expression -Command "fltmc filters > $CCMTempDir\logs\SystemInfo\FilterDrivers.txt"
    #Get Services
    $svc = Get-Service | Sort-Object Status, Name
    $svc | Select-Object Status, StartType, Name, DisplayName | Out-File $CCMTempDir\logs\SystemInfo\Services.txt -Force # Services
    $svc | Format-List * | Out-File $CCMTempDir\logs\SystemInfo\Services.txt -Append # Services 
    
    #Get Processes
    $proc = Get-Process | Sort-Object ProcessName
    $proc | Select-Object ProcessName, StartTime, Description, Path | Out-File $CCMTempDir\logs\SystemInfo\Processes.txt -Force # Processes
    $proc | Format-List * | Out-File $CCMTempDir\logs\Systeminfo\Processes.txt -Append

}

#Gather SCCM Client Info
If ($GatherBaseSCCMLogs -eq 'Yes') {
    Copy-Item -Path $CCMLogdirectory -Destination $CCMTempDir\logs\CCM -Force -Recurse | Out-Null
    Copy-Item -Path $env:windir\ccmsetup\*.log -Destination $CCMTempDir\logs\CCM -Force -Recurse | Out-Null
    Copy-Item $env:windir\ccmsetup\MobileClient*.tcf $CCMTempDir\logs\CCM | Out-Null
    Copy-Item $env:windir\CCM\CCMStore.sdf $CCMTempDir\logs\CCM | Out-Null

    #Get SMS Reigstry Key if SCCM client logs are being gathered
    If ($GatherBaseSCCMLogs -eq 'Yes') {
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\SMS $CCMTempDir\logs\SystemInfo\registry_SMS.txt"
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\CCM $CCMTempDir\logs\SystemInfo\registry_CCM.txt"
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\CCMSetup $CCMTempDir\logs\SystemInfo\registry_CCMSetup.txt"
    }
}

#Gather WindowsUpdate Logs
If ($GatherWindowsUpdateLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\WindowsUpdate | Out-Null
    $OSversion = (Get-WmiObject -Namespace Root\CimV2 -Class Win32_OperatingSystem).Version
    If ($OSversion -like "10.*") {
        If ( -not ( Test-Path alias:out-default ) ) { New-Alias Out-Default Write-Verbose -Scope Global } #Hack get-windowsUpdate writing to Out-Default instead of best practive of Write-host,etc
        Get-WindowsUpdateLog -LogPath $CCMTempDir\logs\WindowsUpdate\WindowsUpdate.log | Out-Null
        Remove-Item alias:Out-Default -Force -EA SilentlyContinue | Out-Null #Clean out hack to workaround out-default issue with Get-WindowsUpdate
        
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate $CCMTempDir\logs\WindowsUpdate\registry_wu.txt"
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\WindowsUpdate $CCMTempDir\logs\WindowsUpdate\registry_wuhandlers.txt"
        Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate $CCMTempDir\logs\WindowsUpdate\registry_wupolicy.txt"
        Invoke-Expression -Command "reg.exe export HKLM\Software\Microsoft\PolicyManager\current\device\Update $CCMTempDir\logs\WindowsUpdate\registry_wupolicy_mdm.txt"
        Invoke-Expression -Command "reg.exe export HKLM\Software\Microsoft\WindowsUpdate\UX\Settings $CCMTempDir\logs\WindowsUpdate\registry_wupolicy_UX.txt"

        # Get software update(s) history
        try {
  
            $Session = New-Object -ComObject "Microsoft.Update.Session"
            $Searcher = $Session.CreateUpdateSearcher()
            $historyCount = $Searcher.GetTotalHistoryCount()
            $UpdateHistory = $Searcher.QueryHistory(0, $historyCount) | Select-Object ClientApplicationID, Date, Title,
            @{name = "Operation"; expression = { Switch ($_.operation) {
                        1 { "Installation" }; 2 { "Uninstallation" }; 3 { "Other" }
                    } }
            },

            @{name = "Status"; expression = { Switch ($_.Resultcode) {

                        1 { "In Progress" }; 2 { "Succeeded" }; 3 { "Succeeded With Errors" };

                        4 { "Failed" }; 5 { "Aborted" }
                    } }
            } | Where-Object ClientApplicationID -ne $null

            $UpdateHistory | Export-Clixml $CCMTempDir\logs\WindowsUpdate\UpdateHistory.xml
        }
        catch {  }

        # Retrieve update sources
        try {
            $SUS = New-Object -ComObject "Microsoft.Update.ServiceManager"
            $defaultAUService = $SUS.Services | Where-Object { $_.IsDefaultAUService -eq $true } | Select-Object Name -ExpandProperty Name
            if ($defaultAUService -ne "Windows Server Update Service")
            { "WSUS is NOT the default update source! Review ...\WindowsUpdate\WindowsUpdateSources.txt" | Out-File "$CCMTempDir\logs\WindowsUpdate\WindowsUpdateSources.txt" }
            else {  }
        
            $SUS.Services | Out-File $CCMTempDir\WindowsUpdate\WindowsUpdateSources.txt -Force
        }
        catch { "Failed to retrieve update sources! $($_.Exception.Message)" | Out-File "$CCMTempDir\logs\WindowsUpdate\WindowsUpdateSources.txt" }
        
        Function Test-IsRegistryPOLGood {
            [cmdletbinding()]
            Param
            (
                [Parameter(Mandatory = $false)]
                [string[]]$PathToRegistryPOLFile = $(Join-Path $env:windir 'System32\GroupPolicy\Machine\Registry.pol')
            )
 
            If (!(Test-Path -Path $PathToRegistryPOLFile -PathType Leaf)) { Return $null }
 
            [Byte[]]$FileHeader = Get-Content -Encoding Byte -Path $PathToRegistryPOLFile -TotalCount 4
 
            if (($FileHeader -Join '') -eq '8082101103') { Return 'Compliant' } Else { Return 'Not-Compliant' }
        }
        Test-IsRegistryPOLGood

        If (Test-IsRegistryPOLGood -eq 'Compliant' ) {"Registry.POL is NOT corrupted." | Out-File $CCMTempDir\logs\SystemInfo\REGISTRYPOL.GOOD.TXT}
        Else {"Registry.POL IS CORRUPT. It is recommended to delete it and verify it is excluded in antivirus exclusions." | Out-File $CCMTempDir\logs\SystemInfo\REGISTRY.POL.CORRUPTED.TXT}
    }

    Else {
        Copy-Item -Path $env:windir\WindowsUpdate.log -Destination $CCMTempDir\logs\WindowsUpdate\WindowsUpdate.log -Force | Out-Null
    }
}

#Gather Windows Defender Logs
If ($GatherDefenderLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\Defender | Out-Null
    $LatestDefenderDir=Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" | Sort-Object CreationTime | Select-Object -Last 1
    Start-Process -FilePath "$LatestDefenderDir\MPCmdRun.exe" -ArgumentList "-GetFiles" -Wait
    Copy-Item -Path "$env:ProgramData\Microsoft\Windows Defender\Support\*.log" -Destination $CCMTempDir\logs\Defender -Force -Recurse | Out-Null
    Copy-Item -Path "$env:ProgramData\Microsoft\Windows Defender\Support\MPSupportFiles.cab" -Destination $CCMTempDir\logs\Defender -Force -Recurse | Out-Null

}

#Gather OneDrive Logs
If ($GatherOneDriveLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\OneDrive | Out-Null
    Copy-Item -Path '$env:ProgramData\Microsoft OneDrive\Setup\logs\*.log' -Destination $CCMTempDir\logs\OneDrive -Force -Recurse | Out-Null
}

#Gather Edge Update Logs
If ($GatherEdgeUpdateLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EdgeUpdate | Out-Null
    Copy-Item -Path 'C:\Users\All Users\Microsoft\EdgeUpdate\Log\*.log' -Destination $CCMTempDir\logs\EdgeUpdate -Force -Recurse | Out-Null
}

#Gather System Eventlogs
If ($DumpSystemEventLog -eq 'Yes') {
    # Config
    $logFileName = "System" # Add Name of the Logfile (System, Application, etc)
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EventLogs | Out-Null
    $path = "$CCMTempDir\logs\EventLogs\" # Add Path, needs to end with a backsplash

    # do not edit
    $exportFileName = $logFileName + (Get-Date -f yyyyMMdd) + ".evt"
    $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object { $_.logfilename -eq $logFileName }
    $logFile.backupeventlog($path + $exportFileName) | Out-Null

    # Deletes all .evt logfiles in $path
    # Be careful, this script removes all files with the extension .evt not just the selfcreated logfiles
    $Daysback = "-7"

    $CurrentDate = Get-Date
    $DatetoDelete = $CurrentDate.AddDays($Daysback)
    Get-ChildItem $Path | Where-Object { ($_.LastWriteTime -lt $DatetoDelete) -and ($_.Extension -eq ".evt") } | Remove-Item

    #Clear-Eventlog -LogName $logFileName
}

#Gather Application EventLogs
If ($DumpSystemAppLog -eq 'Yes') {
    # Config
    $logFileName = "Application" # Add Name of the Logfile (System, Application, etc)
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EventLogs | Out-Null
    $path = "$CCMTempDir\logs\EventLogs\" # Add Path, needs to end with a backsplash

    # do not edit
    $exportFileName = $logFileName + (Get-Date -f yyyyMMdd) + ".evt"
    $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object { $_.logfilename -eq $logFileName }
    $logFile.backupeventlog($path + $exportFileName) | Out-Null

    # Deletes all .evt logfiles in $Path
    # Be careful, this script removes all files with the extension .evt not just the selfcreated logfiles
    $Daysback = "-7"

    $CurrentDate = Get-Date
    $DatetoDelete = $CurrentDate.AddDays($Daysback)
    Get-ChildItem $Path | Where-Object { ($_.LastWriteTime -lt $DatetoDelete) -and ($_.Extension -eq ".evt") } | Remove-Item
    #Clear-Eventlog -LogName $logFileName
}

#Gather Setup EventLogs
If ($DumpSystemAppLog -eq 'Yes') {
    # Config
    $logFileName = "Setup" # Add Name of the Logfile (System, Application, etc)
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EventLogs | Out-Null
    $path = "$CCMTempDir\logs\EventLogs\" # Add Path, needs to end with a backsplash

    # do not edit
    $exportFileName = $logFileName + (Get-Date -f yyyyMMdd) + ".evt"
    $logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object { $_.logfilename -eq $logFileName }
    $logFile.backupeventlog($path + $exportFileName) | Out-Null

    # Deletes all .evt logfiles in $Path
    # Be careful, this script removes all files with the extension .evt not just the selfcreated logfiles
    $Daysback = "-7"

    $CurrentDate = Get-Date
    $DatetoDelete = $CurrentDate.AddDays($Daysback)
    Get-ChildItem $Path | Where-Object { ($_.LastWriteTime -lt $DatetoDelete) -and ($_.Extension -eq ".evt") } | Remove-Item
    #Clear-Eventlog -LogName $logFileName
}

#Gather Windows Servicing (In-Place Upgrade) Logs
If ($GatherLogsRelatedToWindowsServicing -eq 'Yes') {


    Copy-Item -Path $env:windir\logs\CBS -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | Out-Null
    Copy-Item -Path $env:windir\logs\DISM -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | Out-Null
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\Panther | Out-Null
    Copy-Item -Path $env:windir\panther -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | Out-Null
    Copy-Item -Path $env:windir\panther -Filter *.XML -Destination $CCMTempDir\logs -Recurse -Force | Out-Null
    Invoke-Expression -Command "pnputil /enum-drivers >$CCMTempDir\logs\pnpdrivers.log" 
    Invoke-Expression -Command "pnputil /enum-devices >$CCMTempDir\logs\pnpdevices.log"

    #Download SetupDiag
    #If this link ever breaks, you can get the updated link from https://go.microsoft.com/fwlink/?linkid=870142 which is the current SetupDiag download link.
    Start-BitsTransfer https://download.microsoft.com/download/d/8/1/d8149356-6590-4bec-b1bd-a2adcf84ace9/SetupDiag.exe -Destination $env:TEMP
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\SetupDiag | Out-Null
    Invoke-Expression "$env:temp\SetupDiag.exe /Output:$CCMTempDir\logs\SetupDiag\SetupDiagResults.log /Ziplogs:False"

    #Gather log Files from C:\~BT
    If (Test-Path C:\~BT) {
        Copy-Item -Path C:\~BT -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | Out-Null
    }


    If (Test-Path 'C:\$WINDOWS.~BT\Sources\Panther') {
        New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\PantherCurrentCompat | Out-Null
        Copy-Item -Path 'C:\$WINDOWS.~BT\Sources\Panther' -Filter *.log -Destination $CCMTempDir\logs\PantherCurrentCompat -Recurse -Force | Out-Null
        Copy-Item -Path 'C:\$WINDOWS.~BT\Sources\Panther' -Filter *.xml -Destination $CCMTempDir\logs\PantherCurrentCompat -Recurse -Force | Out-Null

    }
}

#Gather MDM Diagnostics Logs
If ($GatherMDMDiagnostics -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\MDMLogs | Out-Null
    Copy-Item -Path $env:ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log $CCMTempDir\logs\MDMLogs | Out-Null
    Copy-Item -Path $env:windir\System32\winevt\Logs\Microsoft-Windows-DeviceManagement* -Filter *.evtx -Destination $CCMTempDir\logs\MDMLogs -Recurse -Force | Out-Null
    Invoke-Expression -Command "reg.exe export HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement $CCMTempDir\logs\MDMLogs\registry_IntuneApps.txt"  
    MDMDiagnosticstool.exe -out $CCMTempDir\logs\MDMLogs
    $areas = Get-ChildItem HKLM:Software\Microsoft\MDMDiagnostics\Area
    ForEach ($area in $areas) {
        If ($area.Name -notlike "*TPM") {
            MDMDiagnosticstool.exe -area $area.PSChildName -zip $CCMTempDir\logs\MDMLogs\$($area.PSChildName).zip | Out-Null
        }
    }
}

#Gather Symantec Antivirus Exclusions
If ($GatherSepExclusions -eq 'Yes') {

    If (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Directory\Admin') {

        $LogPath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $Symantec = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Directory\Admin\'
        $Results = ForEach ($entry in $Symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                DirName   = $var.DirectoryName
                Exclusion = $var.ExcludeSubDirs
            }

        }
        "ScanningEngines - Directories" | Out-File $LogPath
        $Results | Out-File $LogPath -Append

        $LogPath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $Symantec = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Filename\Admin\'
        $Results = ForEach ($entry in $Symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                FileName = $var.FileName
            }

        }
        "ScanningEngines - Filename" | Out-File $LogPath -Append
        $Results | Out-File $LogPath -Append

        $LogPath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $Symantec = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Extensions\Admin'
        $Results = ForEach ($entry in $Symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                Extensions = $var.Exts
            }

        }
        "ScanningEngines - Extensions" | Out-File $LogPath -Append
        $Results | Out-File $LogPath -Append

        $LogPath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $Symantec = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\HeuristicScanning\Directory\Admin'
        $Results = ForEach ($entry in $Symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                DirName   = $var.DirectoryName
                Exclusion = $var.ExcludeSubDirs
            }

        }
        "HeuristicScanning - Directories" | Out-File $LogPath -Append
        $Results | Out-File $LogPath -Append

        $LogPath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $Symantec = Get-ChildItem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\HeuristicScanning\Filename\Admin'
        $Results = ForEach ($entry in $Symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                Filename = $var.Filename
            }

        }
        "HeuristicScanning - Filename" | Out-File $LogPath -Append
        $Results | Out-File $LogPath -Append
        "$CCMTempDir\logs\Symantec-exclusions.log"
    }
}


New-ZipFile $LogsZip $CCMFilestoZip | Out-Null

Import-Module BitsTransfer -Force            

If ($HttpMode -eq "http://") {
    If ($SendStatusMessage -eq 'Yes') {
        If (Test-Path -Path "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll") {
            #File already exists do not download again
        }
        Else {
            Start-BitsTransfer -Source $destination\MessagingDLL\Microsoft.ConfigurationManagement.Messaging.dll -Destination "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll" -TransferType Download | Out-Null
        }
    }
    #End code for Status Message trigger
    Start-BitsTransfer -Source $LogsZip -Destination "$destination\$UplodadFileName" -TransferType Upload  # use this instead of what is below if SSL is not required 
    $UploadedClientLogs = $true
    # write-host "Uploaded Client Logs to $destination/$UplodadFileName"
}

Else {
    #MP is using https and needs a cert attached for any BITS jobs
    $Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -Like "*$env:ComputerName*" -and $_.NotAfter -gt (Get-Date) -and $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.2" }
    If ($Cert.Count -gt 1) { $Cert = $Cert[0] }
    $CertSubjectName = $Cert.Subject -Replace "(CN=)(.*?),.*", '$2' 


    $OSversion = (Get-WmiObject -Namespace Root\Cimv2 -Class Win32_OperatingSystem).Version
    If ($OSversion -like "6.1*") {
        $HasCert = [bool](Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -Like "*$CertSubjectName")  #Can't use newer CMDLet method on Windows 7
    }
    Else {
        $HasCert = [bool](Get-ChildItem Cert:\LocalMachine\My -DnsName $CertSubjectName | Where-Object EnhancedKeyUsageList -Like '*Client Authentication*' | Test-Certificate -AllowUntrustedRoot) #Verify Machine has a certificate that we can attach to the bits job
    }


    # if (Get-ChildItem Cert:\LocalMachine\My -DnsName $CertSubjectName |where EnhancedKeyUsageList -Like '*Client Authentication*'|Test-Certificate -AllowUntrustedRoot) #Verify Machine has a certificate that we can attach to the bits job
    If ($HasCert = $True) {
        #Verify Machine has a certificate that we can attach to the BITS job
        If ($SendStatusMessage -eq 'Yes') {
            #Code for Status Message trigger if desired to get Microsoft.ConfigurationManagement.Messaging.dll
            If (!(Test-Path -Path "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll")) {
                $DownloadJob = "DllDownload"
                $DownloadMessagingDLLBitsJob = Start-BitsTransfer -DisplayName $DownloadJob -Suspended -TransferType Download -Source $Destination\MessagingDLL\Microsoft.ConfigurationManagement.Messaging.dll -Destination  "$CCMTempDir\Microsoft.ConfigurationManagement.Messaging.dll"

                BitsAdmin /setclientCertificatebyName $DownloadJob 2 My $CertSubjectName | Out-Null #Using BitsAdmin to attach cert because can't do it with PowerShell Cmdlet
                Resume-BitsTransfer -BitsJob $DownloadMessagingDLLBitsJob
            }
            #End code for Status Message trigger
        }

        $BitsJobName = "$env:ComputerName-$numericdate.zip"
        $BitsJob = Start-BitsTransfer -DisplayName $BitsJobName -Source $LogsZip -Destination "$destination\$UplodadFileName" -TransferType Upload -Suspended
        BitsAdmin /setclientCertificatebyName $BitsJobName 2 MY $CertSubjectName | Out-Null #Using BitsAdmin to attach cert because can't do it with PowerShell Cmdlet
        Resume-BitsTransfer -BitsJob $BitsJob
        $UploadedClientLogs = $true
        # write-host "Uploaded Client Logs to $destination/$UplodadFileName"
    }
    Else {
        Write-Host "Unable to find Certificate to attach to BITS job Aborting"
    }

}

if ($SendStatusMessage -eq 'Yes') {
    $SentstatusMessage = BuildAndSend-Registration -ManagementPointHostName $MP -MsgId 1234 -InsString1 $MP -InsString2 $UplodadFileName  -InsString3 "Insstring3"  -InsString4 "Insstring4"  -InsString5 "Insstring5"  -InsString6 "Insstring6"
}



If ($UploadedClientLogs = $true)
{ Write-Host "Uploaded Client Logs to $destination/$UplodadFileName and sent Status Message $SentstatusMessage" }
