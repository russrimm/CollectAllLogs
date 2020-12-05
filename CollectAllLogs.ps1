<#
param(
[Parameter(Mandatory=$True)][string] $GatherBaseSCCMLogs,
[Parameter(Mandatory=$True)][string] $GatherWindowsUpdateLogs,
[Parameter(Mandatory=$True)][string] $GatherLogsRelatedToWindowsServicing,
[Parameter(Mandatory=$False)][string] $SendStatusMessage,
[Parameter(Mandatory=$True)][string] $DumpSystemEventLog,
[Parameter(Mandatory=$True)][string] $DumpSystemAppLog,
[Parameter(Mandatory=$True)][string] $GatherSEPExclusions,
[Parameter(Mandatory=$True)][string] $GatherMDMDiagnostics
)
#>



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
$GatherNomadLogs = 'No'
$GatherSepExclusions = 'No'
$GatherMDMDiagnostics = 'Yes'
$GatherDateCreatedRegistryPol = 'No'
$SentstatusMessage = 'No'


$UploadedClientLogs = $False

$MP = $null
$HttpMode = $null
$ClientCommunicationMode = $null
$NumericDate = Get-Date -uFormat "%m%d%Y%H%MS"            
$UplodadFileName = "$env:Computername-$numericdate.zip"
$CCMLogdirectory = Get-ItemProperty -path HKLM:\software\microsoft\ccm\Logging\@global -Name LogDirectory | Select-Object logdirectory -ExpandProperty Logdirectory 
$CCMTempDir = Get-ItemProperty -path HKLM:\software\microsoft\ccm -Name TempDir | Select-Object TempDir -ExpandProperty TempDir           
$LogsZip = $CCMTempDir + "logs.zip"
$CCMFilestoZip = $CCMTempDir + "logs"
$ClientCommunicationMode = Get-WmiObject -Class "CCM_ClientSiteMode" -Namespace "ROOT\ccm" | Select-Object CommunicationMode -ExpandProperty CommunicationMode # 1 = intranet 2= Deprecated. We don't have always intranet client anymore 3=Internet 4=Always internet

function BuildAndSend-Registration {
    Param ([string]$ManagementPointHostName, [int]$msgid, [string]$InsString1, [string]$InsString2, [string]$InsString3, [string]$InsString4, [string]$InsString5, [string]$InsString6)

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
    
    $script:httpsender = New-Object Microsoft.ConfigurationManagement.Messaging.Sender.Ccm.CcmSender

    # Rolling the time back to account for the default time zone in PE being Pacific
    $ThreeHoursAgoInWmiDateTimeFormat = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($(Get-Date).AddHours(-5))

    $unknownstatusmessage = New-Object Microsoft.ConfigurationManagement.Messaging.StatusMessages.UnknownStatusMessage
    $unknownstatusmessage.ModuleName = 'CCMLogGatherer'
    $unknownstatusmessage.ComponentName = 'CCMLogGatherer'
    $unknownstatusmessage.MessageId = $msgid
    $unknownstatusmessage.SiteCode = $Sitecode
    $unknownstatusmessage.InsertionString1 = $InsString1
    $unknownstatusmessage.InsertionString2 = $InsString2
    $unknownstatusmessage.InsertionString3 = $InsString3
    $unknownstatusmessage.InsertionString4 = $InsString4
    $unknownstatusmessage.InsertionString5 = $InsString5
    $unknownstatusmessage.InsertionString6 = $InsString6


    $statusMessage = New-Object Microsoft.ConfigurationManagement.Messaging.Messages.ConfigMgrStatusMessage
   
    #add mp name
    $statusMessage.Settings.HostName = $ManagementPointHostName
    $statusMessage.Settings.HttpPort = 80
    $statusMessage.Settings.HttpsPort = 443
    $statusMessage.Settings.MessageSourceType = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageSourceType]::Client
    $statusMessage.Settings.SecurityMode = [Microsoft.ConfigurationManagement.Messaging.Framework.MessageSecurityMode]::httpmode
    $statusMessage.Settings.OverrideValidityChecks = $true
    $statusMessage.ParseStatusMessage($unknownstatusmessage)
    $statusMessage.SendMessage($httpsender)

    # format string
    $PSArgsArray = @($unknownstatusmessage.ModuleName, $unknownstatusmessage.ComponentName, $unknownstatusmessage.MessageId, $unknownstatusmessage.SiteCode, $unknownstatusmessage.DateTime, $unknownstatusmessage.InsertionString1, `
            $unknownstatusmessage.InsertionString2, $unknownstatusmessage.InsertionString3, $unknownstatusmessage.InsertionString4, $unknownstatusmessage.InsertionString5, $unknownstatusmessage.InsertionString6, $unknownstatusmessage.Attribute403, `
            $statusMessage.Settings.HostName, $statusMessage.Settings.HttpPort)
    $writeoutput = "'" + [string]::join("','", $PSArgsArray) + "'"

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
        [string]$Folder = $(if ($Folder = Split-Path $ZipFilePath) { Resolve-Path $Folder } else { $Pwd })
        $ZipFilePath = Join-Path $Folder $File
        # If they don't want to append, make sure the zip file doesn't already exist.
        If (!$Append) {
            If (Test-Path $ZipFilePath) { Remove-Item $ZipFilePath }
        }
        $Archive = [System.IO.Compression.ZipFile]::Open( $ZipFilePath, "Update" )
    }
    Process {
        ForEach ($path in $InputObject) {
            ForEach ($item in Resolve-Path $path) {
                # Push-Location so we can use Resolve-Path -Relative
                Push-Location (Split-Path $item)
                # This will get the file, or all the files in the folder (recursively)
                ForEach ($file in Get-ChildItem $item -Recurse -File -Force | % FullName) {
                    # Calculate the relative file path
                    $relative = (Resolve-Path $file -Relative).TrimStart(".\")
                    # Add the file to the zip
                    $Null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($Archive, $file, $relative, $Compression)
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

If ($ClientCommunicationMode -eq 1) { #Intranet
    $MP = Get-WmiObject -Class "CCM_Authority" -Namespace "ROOT\ccm" | Where index -eq 1 | Select CurrentManagementPoint -ExpandProperty CurrentManagementPoint
    If ($MP -eq $null) {
        Write-Host "Unable to determine current Management for CCM_Authority"
    }
    If ($MP -ne $null) {
        $MPCapability = Get-WmiObject -Class "SMS_ActiveMPCandidate"  -Namespace "ROOT\ccm\LocationServices" | Where index -eq 1 | Where MP -eq $MP | Select Capabilities -ExpandProperty Capabilities
        If ($MPCapability.Contains("63")) {
            $HttpMode = "https://"
        }
        Else {
            $HttpMode = "http://"
        }

    }
}

If (($ClientCommunicationMode -eq 4) -or ($ClientCommunicationMode -eq 3)) { #Always Internet
   
    $MP = Get-WmiObject -Class "SMS_ActiveMPCandidate" -Namespace "ROOT\ccm\LocationServices" | Select-Object -First 1 | Select MP -Expand MP
    $HttpMode = "https://"
}

$Destination = "$HttpMode$MP/ccm_Incoming"

If (Test-Path -Path $CCMFilestoZip) {
    Remove-Item -Recurse -Force $CCMFilestoZip
}

If (Test-Path -Path $LogsZip) {
    Remove-Item $LogsZip -Force
}

If ($GatherBaseSCCMLogs -eq 'Yes') {
    Copy-Item -Path $CCMLogdirectory -Destination $CCMTempDir\logs\CCM -Force -Recurse | Out-Null
}

If ($GatherWindowsUpdateLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\WindowsUpdate | Out-Null
    $OSversion = (gwmi -namespace root\cimv2 -Class win32_operatingsystem).version
    IF ($OSversion -like "10.*") {
        IF ( -not ( Test-Path alias:out-default ) ) { New-Alias Out-Default Write-Verbose -Scope global } #Hack get-windowsUpdate writing to Out-Default instead of best practive of Write-host,etc
        Get-WindowsUpdateLog -LogPath $CCMTempDir\logs\WindowsUpdate\WindowsUpdate.log | out-null
        Remove-Item alias:Out-Default -Force -EA SilentlyContinue | Out-Null #Clean out hack to workaround out-default issue with Get-WindowsUpdate
    }

    Else {
        Copy-Item -path C:\windows\WindowsUpdate.log -Destination $CCMTempDir\logs\WindowsUpdate\WindowsUpdate.log -Force | Out-Null
    }
}

If ($GatherDefenderLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\Defender | Out-Null
    Copy-Item -Path 'C:\ProgramData\Microsoft\Windows Defender\Support\*.log' -Destination $CCMTempDir\logs\Defender -Force -Recurse | Out-Null
}

If ($GatherOneDriveLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\OneDrive | Out-Null
    Copy-Item -Path 'C:\ProgramData\Microsoft OneDrive\Setup\logs\*.log' -Destination $CCMTempDir\logs\OneDrive -Force -Recurse | Out-Null
}

If ($GatherEdgeUpdateLogs -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EdgeUpdate | Out-Null
    Copy-Item -Path 'C:\Users\All Users\Microsoft\EdgeUpdate\Log\*.log' -Destination $CCMTempDir\logs\EdgeUpdate -Force -Recurse | Out-Null
}

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

If ($DumpSystemAppLog -eq 'Yes') {
    # Config
    $logFileName = "Application" # Add Name of the Logfile (System, Application, etc)
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\EventLogs | Out-Null
    $path = "$CCMTempDir\logs\EventLogs\" # Add Path, needs to end with a backsplash

    # do not edit
    $exportFileName = $logFileName + (get-date -f yyyyMMdd) + ".evt"
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

If ($GatherLogsRelatedToWindowsServicing -eq 'Yes') {


    Copy-Item -path c:\windows\logs\cbs -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | out-null
    Copy-Item -path c:\windows\logs\dism -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | out-null
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\Panther | Out-Null
    Copy-Item -path c:\windows\panther -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | out-null
    Copy-Item -path c:\windows\panther -Filter *.XML -Destination $CCMTempDir\logs -Recurse -Force | out-null
    #pnputil /enum-drivers >$CCMTempDir\logs\pnpdrivers.log
    Invoke-Expression -Command "pnputil /enum-drivers >$CCMTempDir\logs\pnpdrivers.log" 


    #Gather log Files from C:\~BT
    If (Test-Path C:\~BT) {
        Copy-Item -path C:\~BT -Filter *.log -Destination $CCMTempDir\logs -Recurse -Force | Out-Null

    }


    If (Test-Path 'C:\$WINDOWS.~BT\Sources\Panther') {
        New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\PantherCurrentCompat | Out-Null
        Copy-Item -Path 'C:\$WINDOWS.~BT\Sources\Panther' -Filter *.log -Destination $CCMTempDir\logs\PantherCurrentCompat -Recurse -Force | Out-Null
        Copy-Item -Path 'C:\$WINDOWS.~BT\Sources\Panther' -Filter *.xml -Destination $CCMTempDir\logs\PantherCurrentCompat -Recurse -Force | Out-Null

    }
}

If ($GatherMDMDiagnostics -eq 'Yes') {
    New-Item -ItemType Directory -Force -Path $CCMTempDir\logs\MDMLogs | Out-Null
    Copy-Item -Path C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log $CCMTempDir\logs\MDMLogs | Out-Null
    $areas = Get-ChildItem HKLM:Software\Microsoft\MDMDiagnostics\Area
    ForEach ($area in $areas) {
        If ($area.Name -notlike "*TPM") {
            MDMDiagnosticstool.exe -area $area.PSChildName -zip $CCMTempDir\logs\MDMLogs\$($area.PSChildName).zip | Out-Null
        }
    }
}

If ($GatherSepExclusions -eq 'Yes') {

    If (Test-Path 'hklm:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Directory\Admin') {

        $logpath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $symantec = Get-Childitem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Directory\Admin\'
        $results = ForEach ($entry in $symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                DirName   = $var.DirectoryName
                Exclusion = $var.ExcludeSubDirs
            }

        }
        "ScanningEngines - Directories" | Out-File $logpath
        $results | Out-File $logpath -Append

        $logpath = "$CCMTempDir\logs\Symantec-Exclusions.log"
        $symantec = get-childitem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Filename\Admin\'
        $results = ForEach ($entry in $symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                FileName = $var.FileName
            }

        }
        "ScanningEngines - Filename" | Out-File $logpath -Append
        $results | Out-File $logpath -Append

        $logpath = 'C:\Temp\Symantec-Exclusions.log'
        $symantec = Get-Childitem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Extensions\Admin'
        $results = ForEach ($entry in $symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                Extensions = $var.Exts
            }

        }
        "ScanningEngines - Extensions" | Out-File $logpath -Append
        $results | Out-File $logpath -Append

        $logpath = 'C:\Temp\Symantec-Exclusions.log'
        $symantec = get-childitem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\HeuristicScanning\Directory\Admin'
        $results = ForEach ($entry in $symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                DirName   = $var.DirectoryName
                Exclusion = $var.ExcludeSubDirs
            }

        }
        "HeuristicScanning - Directories" | Out-File $logpath -Append
        $results | Out-File $logpath -Append

        $logpath = 'C:\Temp\Symantec-Exclusions.log'
        $symantec = Get-Childitem 'HKLM:\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Exclusions\HeuristicScanning\Filename\Admin'
        $results = ForEach ($entry in $symantec) {
            Set-Location $entry.PSPath
            $var = Get-ItemProperty -Path . 

            [PSCustomObject]@{
                Filename = $var.Filename
            }

        }
        "HeuristicScanning - Filename" | Out-File $logpath -Append
        $results | Out-File $logpath -Append
        "$CCMTempDir\logs\symantec-exclusions.log"
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

Else { #MP is using https and needs a cert attached for any bits jobs
    $Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -Like "*$env:computername*" -and $_.NotAfter -gt (Get-Date) -and $_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.5.5.7.3.2" }
    If ($Cert.Count -gt 1) { $Cert = $Cert[0] }
    $CertSubjectName = $Cert.Subject -replace "(CN=)(.*?),.*", '$2' 


    $OSversion = (Get-WmiObject -Namespace Root\Cimv2 -Class Win32_OperatingSystem).Version
    If ($OSversion -like "6.1*") {
        $HasCert = [bool](Get-ChildItem Cert:\LocalMachine\My | Where Subject -Like "*$CertSubjectName")  #Can't use newer CMDLet method on Windows 7
    }
    Else {
        $HasCert = [bool](Get-ChildItem Cert:\LocalMachine\My -DnsName $CertSubjectName | Where EnhancedKeyUsageList -Like '*Client Authentication*' | Test-Certificate -AllowUntrustedRoot) #Verify Machine has a certificate that we can attach to the bits job
    }


    # if (Get-ChildItem Cert:\LocalMachine\My -DnsName $CertSubjectName |where EnhancedKeyUsageList -Like '*Client Authentication*'|Test-Certificate -AllowUntrustedRoot) #Verify Machine has a certificate that we can attach to the bits job
    If ($HasCert = $True) { #Verify Machine has a certificate that we can attach to the bits job
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

        $BitsJobName = "$env:computername-$numericdate.zip"
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
    $SentstatusMessage = BuildAndSend-Registration -ManagementPointHostName $MP -msgid 1234 -InsString1 $MP -InsString2 $UplodadFileName  -InsString3 "Insstring3"  -InsString4 "Insstring4"  -InsString5 "Insstring5"  -InsString6 "Insstring6"
}



If ($UploadedClientLogs = $true)
{ Write-Host "Uploaded Client Logs to $destination/$UplodadFileName and sent Status Message $SentstatusMessage Regpol CreationDate $FileDate" }
