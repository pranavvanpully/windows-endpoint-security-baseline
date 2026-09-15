<div align="center">

<img src="https://readmeforge.natrajx.in/api/banner?text=WINDOWS+ENDPOINT+SECURITY+BASELINE&subtext=Windows+%E2%80%A2+PowerShell+%E2%80%A2+Endpoint+Security+%E2%80%A2+SOC+Investigation&metal=chrome&type=wave&height=300&width=1200&animation=none&align=center&section=header&theme=dark&fontFamily=Orbitron&subtextFont=Rajdhani&visualStyle=metallic&border=none&borderWidth=2" alt="Windows Endpoint Security Baseline" width="100%">

<br>

<img src="https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 11">
<img src="https://img.shields.io/badge/Focus-Endpoint%20Security-1F6FEB?style=for-the-badge" alt="Endpoint Security">
<img src="https://img.shields.io/badge/SOC-Investigation-111827?style=for-the-badge" alt="SOC Investigation">
<img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">

</div>

# Windows Endpoint Security Baseline

> A practical Windows endpoint security baseline assessment focused on identifying normal system configuration, security controls, processes, services, persistence mechanisms, event activity, and network exposure.

---

## Objective

The objective of this project was to establish a security baseline for a Windows 11 endpoint and perform basic **SOC-style investigation** of selected system, security, and network components.

The assessment followed:

```text
Observe → Investigate → Correlate → Assess → Document → Recommend
```

The project focuses on understanding **normal endpoint behaviour** rather than assuming that unfamiliar activity is malicious.

---

## Environment

| Item             | Details                                                    |
| ---------------- | ---------------------------------------------------------- |
| Operating System | Windows 11 Home                                            |
| Architecture     | 64-bit                                                     |
| CPU              | Intel Core i5-13420 @ 2.61 GHz                             |
| RAM              | ~6 GB                                                      |
| Environment      | Windows 11 Virtual Machine                                 |
| Tools            | PowerShell, Command Prompt, Windows Security, Task Manager |
| Assessment Type  | Endpoint Security Baseline                                 |

---

## Skills Demonstrated

* Windows Endpoint Security
* Process and PID investigation
* Parent-process / PPID analysis
* Windows service analysis
* `svchost.exe` investigation
* Registry Run key analysis
* Startup persistence analysis
* Windows Security control verification
* Windows Event Log analysis
* Network port investigation
* Port-to-PID correlation
* Evidence-based security assessment
* Basic SOC investigation methodology

---

# Assessment Areas

## 1. System Overview

Reviewed the operating system, hardware architecture, CPU, and available memory to establish the endpoint's basic configuration.

**Evidence**

* `01-system-overview-1.png`
* `02-system-overview-2.png`

---

# 2. User Accounts and Privileges

Reviewed local user accounts and members of the local Administrators group.

### Commands Used

```cmd
net user
whoami
net localgroup administrators
```

The primary lab user was identified as a member of the local Administrators group.

### Security Observation

Excessive administrative privileges can increase the impact of account compromise.

**Recommendation:** Standard-user access should be preferred for routine activity where practical.

**Evidence:** `03-user-accounts-and-privileges.png`

---

# 3. Process Analysis

`ApplicationFrameHost.exe` was reviewed as a representative Windows process.

The process was located under:

```text
C:\Windows\System32
```

The process was associated with Microsoft and had a valid digital signature.

### Process Investigation

```powershell
Get-Process -Name ApplicationFrameHost
```

### Parent Process Investigation

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=4700" |
Select-Object Name, ProcessId, ParentProcessId
```

The parent process was then investigated:

```powershell
Get-Process -Id 308
```

### Process Correlation

```text
ApplicationFrameHost.exe
        ↓
PID 4700
        ↓
Parent PID 308
        ↓
svchost.exe
```

The process location, Microsoft signature, and parent-process relationship were consistent with normal Windows activity.

**Assessment:** No obvious anomaly was identified from the available evidence.

**Evidence**

* `04-process-analysis.png`
* `05-process-parent-analysis.png`

---

# 4. Windows Service Analysis

The Windows Defender Firewall service (`MpsSvc`) was investigated to understand its relationship with the underlying Windows service-hosting process.

### Service Investigation

```powershell
Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" |
Select-Object Name, State, StartMode, ProcessId, PathName
```

The service was identified as:

```text
Service   : MpsSvc
State     : Running
StartMode : Automatic
PID       : 3056
```

### Process Investigation

```powershell
Get-Process -Id 3056
```

### Service-to-Process Correlation

```cmd
tasklist /svc /FI "PID eq 3056"
```

### Correlation

```text
MpsSvc
   ↓
PID 3056
   ↓
svchost.exe
   ↓
BFE + MpsSvc
```

The observed architecture is consistent with normal Windows service hosting.

**Evidence**

* `06-windows-defender-firewall-service.png`
* `07-firewall-service-process.png`

---

# 5. Startup Application Analysis

Windows startup applications were reviewed to identify programs configured to launch during user logon.

Observed applications included:

* Microsoft Teams
* OneDrive
* Security Health Systray
* Windows Terminal

The identified applications appeared to be legitimate Windows/Microsoft components.

**Assessment:** No obvious suspicious startup application was identified.

**Evidence:** `08-startup-apps.png`

---

# 6. Startup Persistence Analysis

Windows Registry Run keys and both user-level and system-level Startup folders were reviewed.

### Registry Run Keys

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

Observed entries included Microsoft components such as:

* OneDrive
* Microsoft Edge
* Microsoft Copilot
* Windows Security

### Startup Folder Investigation

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

Both Startup folders were empty during the assessment.

**Assessment:** No obvious suspicious startup persistence entry was identified.

**Evidence:** `09-startup-persistence.png`

---

# 7. Security Control Verification

Windows Security protections were reviewed, including:

* Real-time Protection
* Cloud-delivered Protection
* Automatic Sample Submission
* Tamper Protection
* Windows Firewall

All reviewed protection controls were enabled.

**Evidence**

* `10-security-controls.png`
* `11-firewall-status.png`

---

# 8. Windows Update Status

The endpoint had pending Microsoft Defender and Windows security updates.

Updates were intentionally not completed during the baseline assessment to preserve the freshly installed lab state.

### Security Observation

A production endpoint should receive applicable security updates according to the organization's patch-management process.

**Evidence:** `12-windows-update-status.png`

---

# 9. Windows Event Log Analysis

Selected Windows Security and System events were reviewed to establish a basic endpoint activity baseline.

### Representative Event ID 4625

A representative **Event ID 4625** showed a failed interactive logon caused by an incorrect password.

Relevant fields included:

```text
Event ID       : 4625
Status         : 0xC000006D
SubStatus      : 0xC000006A
Failure Reason : Unknown user name or bad password
```

The observed failed-logon activity was low in volume and did not indicate a clear brute-force pattern.

Other reviewed events included:

* Event ID 4624 — Successful logon
* Event ID 4634 — Logoff
* Event ID 5379 — Credential Manager activity
* Event ID 6005 — Event Log startup
* Event ID 6006 — Event Log shutdown

No obvious malicious event pattern was identified from the selected events.

**Evidence:** `13-event-log-analysis.png`

---

# 10. Network Baseline

Network connections and listening ports were reviewed using:

```cmd
netstat -ano
```

The baseline included Windows listening ports such as:

```text
TCP 135
TCP 445
TCP 5040
Dynamic Windows RPC ports
```

Most observed established outbound connections used HTTP/HTTPS.

The investigation focused on correlating network ports with processes rather than treating an open port alone as evidence of malicious activity.

**Evidence:** `14-network-baseline.png`

---

# 11. Representative Network Investigation

## Port 135 — Windows RPC

The process associated with port 135 was investigated using:

```cmd
tasklist /FI "PID eq 564"
tasklist /svc /FI "PID eq 564"
```

### Correlation

```text
Port 135
   ↓
PID 564
   ↓
svchost.exe
   ↓
RpcEptMapper / RpcSs
```

These services are associated with normal Windows RPC functionality.

---

## Port 445 — SMB / Windows Networking

The process associated with port 445 was investigated using:

```cmd
tasklist /FI "PID eq 4"
```

Result:

```text
Port 445
   ↓
PID 4
   ↓
System
```

The Windows Server service was separately checked:

```powershell
Get-Service LanmanServer
```

The `LanmanServer` service was confirmed to be running, supporting the expected Windows networking functionality associated with SMB.

### Assessment

No obvious anomalous network listener was identified from these representative checks.

**Evidence:** `14-network-port-analysis.png`

---

# Key Findings

## Normal / Expected Activity

* Microsoft Windows system components were identified during process analysis.
* Process locations and digital signatures were consistent with legitimate Windows components.
* Windows Defender protections were enabled.
* Windows Firewall profiles were enabled.
* Startup applications appeared to be legitimate Microsoft/Windows components.
* Registry Run entries appeared to belong to legitimate applications.
* Both Windows Startup folders were empty.
* Representative network ports were associated with expected Windows functionality.
* Selected Windows event logs did not reveal an obvious malicious pattern.

---

## Security Observations

### 1. Local Administrative Privileges

The primary lab user was a member of the local Administrators group.

**Recommendation:** Use standard-user privileges for routine activity where practical.

### 2. Pending Security Updates

Windows and Microsoft Defender updates were available in the lab VM.

**Recommendation:** Production endpoints should follow an appropriate patch-management process.

### 3. Failed Authentication Event

A failed interactive logon caused by an incorrect password was observed.

The observed volume was low and did not indicate a clear brute-force pattern.

In a production SOC, repeated failed authentication events could be correlated using:

* Username
* Source IP
* Destination host
* Time window
* Authentication type
* Success/failure sequence

---

# Investigation Methodology

The project followed a structured endpoint investigation workflow:

```text
┌──────────────┐
│    Observe   │
└──────┬───────┘
       ↓
┌──────────────┐
│ Investigate  │
└──────┬───────┘
       ↓
┌──────────────┐
│  Correlate   │
└──────┬───────┘
       ↓
┌──────────────┐
│    Assess    │
└──────┬───────┘
       ↓
┌──────────────┐
│   Document   │
└──────┬───────┘
       ↓
┌──────────────┐
│  Recommend   │
└──────────────┘
```

Techniques used:

* Process identification using PIDs
* Parent-process investigation using PPIDs
* Windows service-to-process correlation
* Startup persistence review
* Registry Run key analysis
* Windows Security control verification
* Event log analysis
* Network port and PID correlation
* Normal versus potentially suspicious activity assessment
* Evidence-based security documentation

---

# SOC Relevance

This project demonstrates foundational endpoint investigation skills relevant to a **Junior SOC Analyst / Security Analyst** role.

A typical endpoint investigation can follow this logic:

```text
What happened?
      ↓
Which process was involved?
      ↓
Which user or service was involved?
      ↓
Who started the process?
      ↓
Was the activity expected?
      ↓
Is there supporting event-log evidence?
      ↓
Is there supporting network evidence?
      ↓
Does the activity require escalation?
```

The same investigation mindset can later be applied to:

* SIEM telemetry
* Sysmon
* EDR
* Windows Event Forwarding
* Authentication logs
* Network telemetry
* Detection rules
* Security alerts

---

# Key Investigation Commands

The following commands were used during the assessment.

## User Investigation

```cmd
net user
whoami
net localgroup administrators
```

## Process Investigation

```powershell
Get-Process
```

```powershell
Get-Process -Id <PID>
```

## Parent Process Investigation

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" |
Select-Object Name, ProcessId, ParentProcessId
```

## Windows Service Investigation

```powershell
Get-CimInstance Win32_Service |
Select-Object Name, State, StartMode, ProcessId, PathName
```

## Service-to-Process Correlation

```cmd
tasklist /svc /FI "PID eq <PID>"
```

## Registry Persistence Investigation

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

## Startup Folder Investigation

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

```powershell
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

## Network Investigation

```cmd
netstat -ano
```

## Network Port-to-PID Correlation

```cmd
tasklist /FI "PID eq <PID>"
```

---

# Limitations

This project represents a baseline assessment of a controlled Windows laboratory VM.

The assessment does not include:

* Enterprise EDR telemetry
* Centralized SIEM monitoring
* Threat-intelligence enrichment
* Production authentication infrastructure
* Real-world incident response
* Simulated malicious activity
* Enterprise-scale endpoint telemetry

The purpose of this project was to establish a **normal endpoint baseline and demonstrate investigation methodology**, rather than simulate a complete enterprise SOC environment.

---

# Conclusion

The Windows endpoint showed a generally normal baseline based on the selected configuration, process, service, persistence, event-log, security-control, and network checks.

No obvious malicious process, service, startup persistence mechanism, network listener, or suspicious event pattern was identified during the assessment.

The primary security observations were:

1. Local administrative privileges
2. Pending Windows security updates
3. A small number of failed authentication events

This project demonstrates a practical endpoint-baselining workflow and provides a foundation for deeper SOC investigations involving **SIEM platforms, Sysmon, detection engineering, alert triage, and incident investigation**.

---

# Evidence

All supporting screenshots are stored in the `evidence/` directory.

```text
evidence/
├── 01-system-overview-1.png
├── 02-system-overview-2.png
├── 03-user-accounts-and-privileges.png
├── 04-process-analysis.png
├── 05-process-parent-analysis.png
├── 06-windows-defender-firewall-service.png
├── 07-firewall-service-process.png
├── 08-startup-apps.png
├── 09-startup-persistence.png
├── 10-security-controls.png
├── 11-firewall-status.png
├── 12-windows-update-status.png
├── 13-event-log-analysis.png
├── 14-network-baseline.png
└── 14-network-port-analysis.png
```

---

<div align="center">

**Windows Endpoint Security • PowerShell • Event Logs • Process Investigation • Persistence Analysis • Network Analysis • SOC Fundamentals**

</div>
