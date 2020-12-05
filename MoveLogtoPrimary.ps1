#Message Filter Variables https://technet.microsoft.com/en-us/library/bb693758.aspx
#IIS 6 WMI Compatibiliy or IIS Management Scripts and Tools must be installed in MP, preferabble IIS Management Scripts as it is the newer class


Param(
    [Parameter(Mandatory = $True)][string] $InsString1,
    [Parameter(Mandatory = $True)][string] $InsString2,
    [Parameter(Mandatory = $True)][string] $PrimaryLogFolder
)
$CMGConnected = $false


Function DetermineIfCMG {
    Param([string]$MP)
    If ($MP -match "CCM_PROXY_MUTUALAUTH") {
        $CMGConnected = $true
        $MPIndex = $InsString1.IndexOf('/')
        $MP = $MP.Substring(0, $MPIndex)

        $MP = Get-WmiObject -Class 'SMS_CloudProxyRoleEndpoint' -Namespace ROOT\SMS\site_CMG | Where-Object ProxyServiceName -eq $MP | Where-Object EndpointName -eq 'SMS_MP' | Select-Object -ExpandProperty RoleServerName

        Return $MP

    }

    Else {
        Return $MP
    }

}

Function get-CCMIncominglocation {
    If (get-wmiobject -ComputerName $InsString1 -namespace root -class __NAMESPACE -filter "name='MicrosoftIISv2'") {
        $CCMInComingIISV2 = Get-WmiObject -Class "IIsWebVirtualDirSetting" -ComputerName $InsString1 -Namespace 'ROOT\MicrosoftIISv2' | Where-Object Name -eq 'W3SVC/1/ROOT/CCM_Incoming' | Select-Object Path
        $CCMIncomingPath = $CCMInComingIISV2.path
    }

    ElseIf (get-wmiobject -ComputerName $InsString1 -namespace root -class __NAMESPACE -filter "name='WebAdministration'") {
        $CCMIncomingWebAdminPath = Get-WmiObject -Class 'VirtualDirectory' -ComputerName $InsString1 -Namespace 'ROOT\WebAdministration' | Where-Object ApplicationPath -eq  '/CCM_Incoming' | Select-Object PhysicalPath
        $CCMIncomingPath = $CCMIncomingPath.PhysicalPath
    }
    Else {
        Write-Host "Warning unable to determine SMB location of CCM Incoming on MP $InsString1 logs will be left on $InsString1"
    }
    Return $CCMIncomingPath
}


Function DetermineSiteHiearchy {
    $SiteCode = (Get-WmiObject -Namespace "ROOT\SMS" -class "__Namespace").Name
    $computer = $env:COMPUTERNAME
    $FQDNSystemName = [System.Net.Dns]::GetHostByName(($env:computerName)) | Select-Object Hostname -ExpandProperty Hostname
    $CASServerName = $null
    $CASServerName = Get-WmiObject -Class 'SMS_Site' -ComputerName $computer -Namespace "ROOT\SMS\$SiteCode" | Where-Object Type -eq 4 | Select-Object Servername -ExpandProperty servername
    Return $CASServerName
}


$CASServerName = $null
$InsString1 = DetermineIfCMG -MP $InsString1

$CCMIncoming = get-CCMIncominglocation
$CCMIncoming = $CCMIncoming -replace ":", "$"
$CCMIncoming = "\\$InsString1\$CCMIncoming"

$CASServerName = DetermineSiteHiearchy

if ($CASServerName -eq $null) {
    move-Item "$CCMIncoming\$InsString2" $PrimaryLogFolder -Force
}

else {
    $CASServerLogFolder = "\\cas\d$\GatheredClientLogs"
    move-Item "$CCMIncoming\$InsString2" $CASServerLogFolder -Force
}


