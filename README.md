# CollectAllLogs
CollectAllLogs is designed to be used with the Run Scripts feature of MECM (SCCM). It will collect many logs from a device or collection of devices, upload them to
a management point, and send a status message which causes the primary to copy the zip from the management point to a directory of choice.

Copy Microsoft.ConfigurationManagement.Messaging.dll to <ConfigMgr Installation Dir>\CCM\Incoming\MessagingDll and \SMS_CCM\Temp on each Management Point
Create a new “Run Script” using the contents of the script “CollectAllLogs.ps1”.
Place the MoveLogtoPrimary.ps1 to the primary site server in a <SCRIPTSDIR> of choice.
Create a directory for logs <COLLECTALLLOGSDIR>
Create a status filter rule with Message ID 1234
 

On the Actions Tab, check “Run a Program”
Command line:
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass -file "<SCRIPTSDIR>\MoveLogtoPrimary.ps1" -InsString1 %msgis01 -InsString2 %msgis02 -PrimaryLogFolder <COLLECTALLLOGSDIR>
Move status filter rule up in priority to the top
Right-click a device
Click Run Script
Select “Collect All Logs”
 
Check the path chosen at <CollectAllLogsDir> for a .zip file after a few minutes

