<div align="center">

<img src="https://readmeforge.natrajx.in/api/banner?text=WINDOWS+ENDPOINT+SECURITY&subtext=Windows+%E2%80%A2+PowerShell+%E2%80%A2+Endpoint+Security+%E2%80%A2+SOC+Investigation&type=wave&height=280&width=1200&animation=none&align=center&section=header&theme=dark&fontFamily=Rajdhani&subtextFont=Rajdhani&visualStyle=cyber&border=none&borderWidth=0" alt="Windows Endpoint Security" width="100%">

<br>

<img src="https://img.shields.io/badge/WINDOWS%2011-0B5FFF?style=flat-square&logo=windows&logoColor=white" alt="Windows 11">
<img src="https://img.shields.io/badge/ENDPOINT%20SECURITY-00B8D9?style=flat-square" alt="Endpoint Security">
<img src="https://img.shields.io/badge/SOC%20INVESTIGATION-263238?style=flat-square" alt="SOC Investigation">
<img src="https://img.shields.io/badge/POWERSHELL-0078D4?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell">

</div>


# Windows Endpoint Security Baseline

A practical Windows endpoint security baseline assessment focused on identifying normal system configuration, security controls, processes, services, persistence mechanisms, event activity, and network exposure.

## Objective

The objective of this project was to establish a security baseline for a Windows 11 endpoint and perform basic SOC-style investigation of selected system and network components.

The assessment followed the approach:

**Observe → Investigate → Correlate → Assess → Document → Recommend**

The project focuses on understanding what is normal on an endpoint rather than assuming that unfamiliar activity is malicious.

## Environment

| Item             | Details                                                    |
| ---------------- | ---------------------------------------------------------- |
| Operating System | Windows 11 Home                                            |
| Architecture     | 64-bit                                                     |
| CPU              | Intel Core i5-13420 @ 2.61 GHz                             |
| RAM              | ~6 GB                                                      |
| Environment      | Windows 11 virtual machine                                 |
| Tools            | Windows Security, Task Manager, PowerShell, Command Prompt |

## Assessment Areas

### 1. System Overview

Reviewed the operating system, hardware architecture, CPU, and available memory to establish the endpoint's basic configuration.

**Evidence:** `01-system-overview-1.png`, `02-system-overview-2.png`

### 2. User Accounts and Privileges

Reviewed local user accounts and members of the local Administrators group.

**Commands used:**

```cmd
net user
net localgroup administrators
```

The primary lab user was identified as a member of the local Administrators group.

**Security observation:** Excessive administrative privileges can increase the impact of account compromise.

**Evidence:** `03-user-accounts-and-privileges.png`

### 3. Process Analysis

Reviewed `ApplicationFrameHost.exe` as a representative Windows process.

The process was located under `C:\Windows\System32`, associated with Microsoft, and had a valid digital signature.

**Process investigation:**

```powershell
Get-Process -Name ApplicationFrameHost
```

Parent process analysis identified:

**ApplicationFrameHost.exe → PID 4700 → svchost.exe**

**Parent-process investigation:**

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=4700" |
Select-Object Name, ProcessId, ParentProcessId
```

The parent process was then investigated:

```powershell
Get-Process -Id 308
```

No obvious anomaly was identified based on the available evidence.

**Evidence:** `04-process-analysis.png`, `05-process-parent-analysis.png`

### 4. Windows Service Analysis

Reviewed the Windows Defender Firewall service (`MpsSvc`).

The service was running with automatic startup and was hosted by `svchost.exe`.

**Service investigation:**

```powershell
Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" |
Select-Object Name,State,StartMode,ProcessId,PathName
```

Further investigation identified:

**MpsSvc → PID 3056 → svchost.exe**

The associated process was investigated using:

```powershell
Get-Process -Id 3056
```

The services hosted by the process were then checked:

```cmd
tasklist /svc /FI "PID eq 3056"
```

The same process also hosted the Windows Base Filtering Engine (`BFE`), which is consistent with normal Windows service architecture.

**Evidence:** `06-windows-defender-firewall-service.png`, `07-firewall-service-process.png`

### 5. Startup Applications

Reviewed Windows startup applications including Microsoft Teams, OneDrive, Security Health Systray, and Windows Terminal.

The identified entries appeared to be legitimate Windows/Microsoft components, with no obvious suspicious startup application observed.

**Evidence:** `08-startup-apps.png`

### 6. Startup Persistence

Reviewed Windows Registry Run keys and both user-level and system-level Startup folders.

**Registry Run key investigation:**

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

The identified Run entries belonged to Microsoft components including OneDrive, Microsoft Edge, Microsoft Copilot, and Windows Security.

**Startup folder investigation:**

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

```powershell
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

Both Startup folders were empty.

No obvious suspicious startup persistence entry was identified.

**Evidence:** `09-startup-persistence.png`

### 7. Security Controls

Reviewed Windows Security protections including:

* Real-time protection
* Cloud-delivered protection
* Automatic sample submission
* Tamper Protection
* Windows Firewall

All reviewed protection controls were enabled.

**Evidence:** `10-security-controls.png`, `11-firewall-status.png`

### 8. Windows Update Status

The endpoint had pending Microsoft Defender and Windows security updates.

Updates were intentionally not completed during the baseline assessment to preserve the freshly installed lab state.

**Security observation:** A production endpoint should receive applicable security updates in accordance with the organization's patch-management process.

**Evidence:** `12-windows-update-status.png`

### 9. Windows Event Log Analysis

Reviewed selected Windows Security and System events to establish a basic activity baseline.

A representative Event ID 4625 showed a failed interactive logon caused by an incorrect password.

The observed failed-logon activity was low in volume and did not indicate a clear brute-force pattern.

Other reviewed events included successful logon, logoff, Credential Manager activity, and normal Windows Event Log startup/shutdown events.

No obvious malicious event pattern was identified from the selected events.

**Evidence:** `13-event-log-analysis.png`

### 10. Network Baseline

Used `netstat -ano` to identify listening ports and active network connections on the endpoint.

**Command used:**

```cmd
netstat -ano
```

The baseline included Windows listening ports such as:

* TCP 135
* TCP 445
* TCP 5040
* Dynamic Windows RPC ports

Most observed established outbound connections used HTTP/HTTPS.

Two representative ports were investigated further.

**Evidence:** `14-network-baseline.png`

### 11. Representative Network Investigation

#### Port 135

The investigation established:

**Port 135 → PID 564 → svchost.exe → RpcEptMapper / RpcSs**

**Process investigation:**

```cmd
tasklist /FI "PID eq 564"
```

**Service investigation:**

```cmd
tasklist /svc /FI "PID eq 564"
```

These services are associated with normal Windows RPC functionality.

#### Port 445

The investigation established:

**Port 445 → PID 4 → System**

**Process investigation:**

```cmd
tasklist /FI "PID eq 4"
```

The Windows Server service (`LanmanServer`) was confirmed to be running:

```powershell
Get-Service LanmanServer
```

The Server service was also checked using:

```powershell
Get-Service | Where-Object {$_.DisplayName -eq "Server"}
```

This supported the expected SMB/Windows networking functionality associated with port 445.

No obvious anomalous network listener was identified from these representative checks.

**Evidence:** `14-network-port-analysis.png`

## Key Findings

### Normal / Expected

* Microsoft Windows system components were identified during process analysis.
* Windows Defender and Firewall protections were enabled.
* Startup applications and Registry Run entries appeared to be legitimate Microsoft components.
* Both Windows Startup folders were empty.
* Representative network ports were associated with expected Windows functionality.
* Selected event logs did not show an obvious malicious pattern.

### Security Observations

1. **Local administrative privileges**

   * The primary lab user was a member of the local Administrators group.
   * Standard-user access should be preferred for routine activity where practical.

2. **Pending security updates**

   * Windows and Microsoft Defender updates were available in the lab VM.
   * Production endpoints should follow an appropriate patch-management process.

3. **Failed authentication event**

   * A failed interactive logon caused by an incorrect password was observed.
   * The observed volume did not indicate a brute-force pattern.

## Investigation Methodology

The project used basic endpoint investigation techniques commonly useful in SOC and security operations work:

* Process identification using PIDs
* Parent-process investigation using PPIDs
* Windows service-to-process correlation
* Startup persistence review
* Registry Run key analysis
* Windows Security control verification
* Event log analysis
* Network port and PID correlation
* Basic assessment of normal versus potentially suspicious activity

## Conclusion

The Windows endpoint showed a generally normal baseline based on the selected configuration, process, service, persistence, event-log, and network checks.

No obvious malicious process, service, startup persistence mechanism, network listener, or suspicious event pattern was identified during the assessment.

The main security observations were the presence of local administrative privileges and pending Windows security updates.

This project demonstrates a practical endpoint-baselining workflow and provides a foundation for deeper SOC investigations involving SIEM platforms, Sysmon, detection rules, and alert investigation.

## Evidence

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
