################################
### Script to execute Sysinternals/PSSuspend - Suspend processes executed not part of the approved SoftwarePolicy.
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# PSSupend will be executed using the Process ID in the sysmon_event1 event that triggered the Software Policy Violation.
# The Process ID will be checked against the process file image (full path) and PSSupend will execute if matched.
# A notification balloon will pop up in the notification area
##########
# Read the Alert that triggered the Active Response in manager and convert to Array
$INPUT_JSON = Read-Host
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json 
$INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
$ErrorActionPreference = "SilentlyContinue"
#Switch For Rule Group From Alert
$switch_condition = ($INPUT_ARRAY."parameters"."alert"."rule"."groups"[3]).ToString()
#Create Notification shown in User's context.
$notification = '{
$msecs=3000
$Text=""An application was suspended due to the software policies in place""
$Title=""Application Suspended""
Add-Type -AssemblyName System.Windows.Forms 
$global:balloon = New-Object System.Windows.Forms.NotifyIcon
$path = (Get-Process -id $pid).Path
$balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning 
$balloon.BalloonTipText = "$Text"
$balloon.BalloonTipTitle = "$Title" 
$balloon.Visible = $true 
$balloon.ShowBalloonTip($msecs)
}'
switch -Exact ($switch_condition){
"software_policy"
    {
#Extract Process ID and File Path from Alert
       $process_id_alert = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."processId"
       $process_file_alert = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."image"
       $process_file_alert = $process_file_alert -replace "\\\\", "\"
#Get-Process by Process ID and extract process full path
       $running_process_name = (Get-Process -Id $process_id_alert -FileVersionInfo).Filename
#Execute PSSuspend if match with alert
       if ($running_process_name -eq $process_file_alert) {
# Get User's Session ID, used for notification popup
        $user_session_id=(Get-Process -PID $process_id_alert).SessionID
# Execute Notification in user's context.
        c:\"Program Files"\Sysinternals\psexec64.exe /nobanner /accepteula -i $user_session_id pwsh.exe -executionpolicy bypass -WindowStyle Hidden -Command "& $notification"
# Suspend Process, sleep and then kill it.
        c:\"Program Files"\Sysinternals\pssuspend64.exe /nobanner /accepteula $process_id_alert
        Start-Sleep -s 3
        c:\"Program Files"\Sysinternals\pskill64.exe /accepteula $process_id_alert
       }
    break;
    }   
}
