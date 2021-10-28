**WINDOWS SOFTWARE POLICY USING WAZUH AND SYSINTERNALS**

# Intro

Applying a software/application policy using Wazuh and Sysinternals.

Detection mode: events where a process is started but is not part of the software policy will generate an alert.

Prevention mode: events where processes not part of the software policy are executed will generate an alert and the process will be suspended in the local machine using “PSSuspend” (Sysinternals). In the local machine a warning in the notification area will pop up to notify the user. After a number of seconds, “Pskill” will be executed over the process that was previously suspended. The reason behind this is avoiding malicious processes to spawn again right after being killed, usual behaviour in malware.

WARNING NOTE: Prevention mode may have unexpected consequences if the list of approved software/applications prevents legit software from being executed. Careful.

Wazuh Capabilities: CDB Lists and Active Response (only in prevention mode).

Sysinternals tools: [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon), [PSSuspend](https://docs.microsoft.com/en-us/sysinternals/downloads/pssuspend), [PSKill](https://docs.microsoft.com/en-us/sysinternals/downloads/pskill), [PSexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).


# Defining the software list (proactive mode)

If you already have a list of software (by vendor, product, etc.), use that info to create a Wazuh list. The names used for this list SHOULD match the vendor/product information that Sysmon (event ID =1, Process Started) reports in its “win.eventdata.company” / “win.eventdata.product” fields.


# Defining the software list (reactive mode)

A software inventory can be reactively built by evaluating the following fields in events where Wazuh’s rule groups = “sysmon_event1”:



* Software Company: “win.eventdata.company”.
* Software Product/Package: “win.eventdata.product”.

If Sysmon events have been collected for a significant period of time, the list will reflect an inventory of software, vendors or products, used in your environment.

In this document we’ll use Software Company to define the list of approved applications.


# Detecting process execution not part of the approved software policy

Create a CDB list with the list of approved software vendors (companies), “/var/ossec/etc/lists/software-vendors”. As an example:


```
Microsoft Corporation:
Sysinternals - www.sysinternals.com:
The Git Development Community:
Vivaldi Technologies AS:
GitHub, Inc.:
GitHub:
Brave Software, Inc.:
Node.js:
Avira Operations GmbH &amp; Co. KG:
BraveSoftware Inc.:
Sysinternals:
```


<span style="text-decoration:underline;">NOTE:</span> The colon at the end of each line is necessary.

Add the new list in ossec.conf (manager), under the "rulset" section:

```
 <ruleset>
     <!-- User-defined ruleset -->
    <list>etc/lists/software-vendors</list>
 </ruleset
 
```
    
Create detection rule to detect processes started where the field “win.eventdata.company” is NOT included in that list
(You can also add it at the bottom of this [rule](https://github.com/juaromu/wazuh/blob/main/MITRE_TECHNIQUES_FROM_SYSMON_EVENT1.xml) file):


```
<!-- Rules 100500 - 100999: Exceptions/Rule Level Mod -->
<rule id="100500" level="10">
<if_sid>61603</if_sid>
<list field="win.eventdata.company" lookup="not_match_key">etc/lists/software-vendors</list>
<description>Sysmon - Event 1: Process $(win.eventdata.description) started but not allowed by the software policy.</description>
<mitre>
<id>T1036</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event1,software_policy</group>
</rule>
```


After restarting Wazuh manager, check that the list was successfully compiled:


```
-rw-rw---- 1 root  ossec  239 Oct 21 19:11 software-vendors
-rw-rw---- 1 ossec ossec 2529 Oct 21 19:11 software-vendors.cdb
```


If the software policy should work in detection mode only, that’s it!

Alert (example):


```
{
   "timestamp":"2021-10-23T18:15:38.119+1100",
   "rule":{
      "level":10,
      "description":"Sysmon - Event 1: Process Sublime Text started but not allowed by the software policy.",
      "id":"100500",
      "mitre":{
         "id":[
            "T1036"
         ],
         "tactic":[
            "Defense Evasion"
         ],
         "technique":[
            "Masquerading"
         ]
      },
      "firedtimes":1,
      "mail":false,
      "groups":[
         "windows",
         "sysmon",
         "sysmon_event1",
         "software_policy"
      ]
   },
   "agent":{
      "id":"033",
      "name":"DESKTOP-NCLALBR",
      "ip":"192.168.252.120"
   },
   "manager":{
      "name":"tactical"
   },
   "id":"1634973338.510123480",
   "decoder":{
      "name":"windows_eventchannel"
   },
   "data":{
      "win":{
         "system":{
            "providerName":"Microsoft-Windows-Sysmon",
            "providerGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
            "eventID":"1",
            "version":"5",
            "level":"4",
            "task":"1",
            "opcode":"0",
            "keywords":"0x8000000000000000",
            "systemTime":"2021-10-23T07:15:27.4819375Z",
            "eventRecordID":"1465789",
            "processID":"3428",
            "threadID":"5360",
            "channel":"Microsoft-Windows-Sysmon/Operational",
            "computer":"DESKTOP-NCLALBR.MYORG.ORG",
            "severityValue":"INFORMATION",
            "message":"\"Process Create:\r\nRuleName: technique_id=T1204,technique_name=User Execution\r\nUtcTime: 2021-10-23 07:15:27.293\r\nProcessGuid: {ac15d313-b68f-6173-09be-000000000e00}\r\nProcessId: 2356\r\nImage: C:\\Program Files\\Sublime Text\\sublime_text.exe\r\nFileVersion: 4113\r\nDescription: Sublime Text\r\nProduct: Sublime Text\r\nCompany: Sublime HQ Pty Ltd\r\nOriginalFileName: sublime_text.exe\r\nCommandLine: \"C:\\Program Files\\Sublime Text\\sublime_text.exe\" \r\nCurrentDirectory: C:\\Program Files\\Sublime Text\\\r\nUser: MYORG\\jromero\r\nLogonGuid: {ac15d313-f7f4-6172-ffe3-a95600000000}\r\nLogonId: 0x56A9E3FF\r\nTerminalSessionId: 3\r\nIntegrityLevel: Medium\r\nHashes: SHA1=ED96EEAD6232E2A1591ECD5B0B3544F98F5E3DE1,MD5=4B9E87D1547A4FC9E47D6A6D8DC5E381,SHA256=0479327E7136FA14F69D231D1B38CF654421073C8A0166BF6690A3D2C0B14FFA,IMPHASH=72491100E121C09085313F2BAF04AD3A\r\nParentProcessGuid: {ac15d313-f7f7-6172-94b3-000000000e00}\r\nParentProcessId: 12888\r\nParentImage: C:\\Windows\\explorer.exe\r\nParentCommandLine: C:\\Windows\\Explorer.EXE\""
         },
         "eventdata":{
            "ruleName":"technique_id=T1204,technique_name=User Execution",
            "utcTime":"2021-10-23 07:15:27.293",
            "processGuid":"{ac15d313-b68f-6173-09be-000000000e00}",
            "processId":"2356",
            "image":"C:\\\\Program Files\\\\Sublime Text\\\\sublime_text.exe",
            "fileVersion":"4113",
            "description":"Sublime Text",
            "product":"Sublime Text",
            "company":"Sublime HQ Pty Ltd",
            "originalFileName":"sublime_text.exe",
            "commandLine":"\\\"C:\\\\Program Files\\\\Sublime Text\\\\sublime_text.exe\\\"",
            "currentDirectory":"C:\\\\Program Files\\\\Sublime Text\\\\",
            "user":"MYORG\\\\jromero",
            "logonGuid":"{ac15d313-f7f4-6172-ffe3-a95600000000}",
            "logonId":"0x56a9e3ff",
            "terminalSessionId":"3",
            "integrityLevel":"Medium",
            "hashes":"SHA1=ED96EEAD6232E2A1591ECD5B0B3544F98F5E3DE1,MD5=4B9E87D1547A4FC9E47D6A6D8DC5E381,SHA256=0479327E7136FA14F69D231D1B38CF654421073C8A0166BF6690A3D2C0B14FFA,IMPHASH=72491100E121C09085313F2BAF04AD3A",
            "parentProcessGuid":"{ac15d313-f7f7-6172-94b3-000000000e00}",
            "parentProcessId":"12888",
            "parentImage":"C:\\\\Windows\\\\explorer.exe",
            "parentCommandLine":"C:\\\\Windows\\\\Explorer.EXE"
         }
      }
   },
   "location":"EventChannel"
}
```



# Detecting and preventing process execution for apps not part of the approved software policy.

<span style="text-decoration:underline;">WARNING NOTE</span>: Prevention mode may have unexpected consequences if the list of approved software/applications prevents legit software from being executed. Careful.

After all the steps in the previous sections, create an active response configuration (oseec.conf in Wazuh manager):


```
<command>
    <name>pssuspend</name>
    <executable>pssuspend.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
   <disabled>no</disabled>
   <level>10</level>
   <command>pssuspend</command>
   <location>local</location>
   <rules_group>software_policy</rules_group>
  </active-response>
```


In the windows agents, we need to create the files “pssuspend.cmd” (active response bin folder):


```
:: Simple script to run Sysinternals PSSuspend.
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

pwsh.exe -executionpolicy ByPass -File "c:\Program Files\Sysinternals\pssuspend.ps1"

:Exit
```


NOTE: Powershell 7.x is required for properly parsing the JSON input (JSON alert included by Wazuh manager as part of the active response).

And the file “pssuspend.ps1” (in this example, placed in the sysinternals folder, see [here](https://github.com/juaromu/wazuh)). It can be placed in any folder in the local machine:


```
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
```

