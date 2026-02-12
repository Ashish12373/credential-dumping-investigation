# credential-dumping-investigation
Credential Dumping Detection & Attack Chain Reconstruction
📌 Executive Summary

This project documents the investigation and reconstruction of a multi-stage credential dumping attack using Splunk and Sysmon telemetry. The attack involved encoded PowerShell execution leading to LSASS memory extraction via Procdump. The activity was mapped to multiple MITRE ATT&CK techniques across Execution, Defense Evasion, and Credential Access tactics.

🖥 Environment

SIEM: Splunk Enterprise

Index: attack_data

Log Source: Windows Sysmon

Dataset: Atomic Red Team (T1003.001)

Total Events Analyzed: ~15,000

Primary Log File: windows-sysmon.log

🔍 Detection Methodology
Step 1 — Identify Encoded PowerShell Execution

Search for suspicious PowerShell usage:

index=attack_data source="*windows-sysmon.log"
| spath
| search "-EncodedCommand"


Indicators:

-EncodedCommand

-ExecutionPolicy Unrestricted

-NonInteractive

MITRE: T1059.001

Step 2 — Detect Credential Dump Execution
index=attack_data source="*windows-sysmon.log"
| spath
| search "notprocdump"


Command identified:

notprocdump64.exe -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp


MITRE: T1003.001

Step 3 — Confirm Dump File Creation

Sysmon Event ID 11 confirmed file creation:

C:\Windows\Temp\lsass_dump.dmp

🧭 Attack Chain Reconstruction
Stage	Action	MITRE ID
1	cmd.exe launched	—
2	Encoded PowerShell execution	T1059.001
3	Procdump executed against LSASS	T1003.001
4	Dump file created	T1003.001
5	Privileged account used	T1078
6	Base64 obfuscation	T1027
📊 Timeline Visualization

The timeline reconstruction confirmed:

CMD → PowerShell → Procdump → Dump File creation

(Screenshot here)

🚨 Security Impact

LSASS memory extracted

Administrator account used

Credential material exposed

Full domain compromise possible in real environment

Severity: High

🛡 Detection Rule (Splunk)
index=attack_data
| spath
| search Event.System.EventID=1 AND ("lsass.exe" OR "procdump")

🧠 MITRE ATT&CK Mapping

Execution — T1059.001
Defense Evasion — T1027
Credential Access — T1003.001
Valid Accounts — T1078

📈 Skills Demonstrated

Sysmon log analysis

SPL query development

XML parsing

Base64 decoding

Multi-stage attack reconstruction

MITRE ATT&CK mapping

Timeline visualization

Detection engineering
