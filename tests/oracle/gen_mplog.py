"""Writes tests/fixtures/written/MPLog-20231219-093000.log: a protection log
as Defender writes them (UTF-16LE with a byte order mark, CRLF), with one
or more entries of every kind read, in the shapes documented by
CrowdStrike, Intrinsec and artefacts.help, among lines that aren't read.
All names, paths and hashes are made up. The machine is at UTC+1: the
blocks' month-first times are local (artefacts.help's example telemetry has
its CreationTime an hour after its UTC ProcessCreationTime).

Run: python3 -I gen_mplog.py ../fixtures/written/MPLog-20231219-093000.log
"""

import sys

LINES = r"""
2023-12-19T09:30:00.001Z Service started (MsMpEng.exe pid 3120)
2023-12-19T09:30:00.120Z [Cloud] Engine is requesting config to do cloud query [regular network].
2023-12-19T09:31:02.472Z ProcessImageName: powershell.exe, Pid: 7968, TotalTime: 6070, Count: 24, MaxTime: 828, MaxTimeFile: \Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\stage, one.ps1, EstimatedImpact: 100%
2023-12-19T09:31:05.010Z ProcessImageName: explorer.exe, Pid: 4104, TotalTime: 30, Count: 11, MaxTime: 9, MaxTimeFile: \Device\HarddiskVolume3\Windows\explorer.exe, EstimatedImpact: 9%
2023-12-19T09:32:10.554Z Engine:command line reported as lowfi: C:\Windows\System32\reg.exe(reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f)
2023-12-19T09:32:11.580Z Engine:command line reported as threat: C:\Windows\System32\rundll32.exe(rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 700 C:\Users\Public\l.dmp full)
2023-12-19T09:33:18.854Z DETECTIONEVENT MPSOURCE_SYSTEM HackTool:Win32/Example!MSR file:C:\Users\alice\Videos\tool.exe;
2023-12-19T09:33:18.855Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Example!MSR file:C:\Users\alice\Videos\tool.exe;
2023-12-19T09:33:18.856Z DETECTION_ADD#1 HackTool:Win32/Example!MSR file:C:\Users\alice\Videos\tool.exe PropBag [length: 0, data: (null)]
2023-12-19T09:33:19.001Z DETECTION_ADD Behavior:Win32/Example.A process:pid:7968,ProcessStart:133474519288037348
2023-12-19T09:33:29.026Z [Mini-filter] Blocked file: \Device\HarddiskVolume3\Users\alice\Videos\tool.exe Process: \Device\HarddiskVolume3\Windows\explorer.exe, Status: 0x0, State: 16, ScanRequest #2241, FileId: 0x5000000012a3c, Reason: OnOpen, IoStatusBlockForNewFile: 0x1, DesiredAccess:0x120089, FileAttributes:0x20, ScanAttributes:0x10, AccessStateFlags:0x800, BackingFileInfo: 0x0, 0x0, 0x0:0\0x0:0
2023-12-19T09:33:29.027Z [RTP] [Mini-filter] Blocked file(#74): \Device\HarddiskVolume3\Users\alice\Videos\tool.exe. Process: \Device\HarddiskVolume3\Windows\explorer.exe, Status: 0x0, State: 16
2023-12-19T09:33:30.100Z [Mini-filter] Unsuccessful scan status: \Device\HarddiskVolume3\Users\alice\Downloads\big.iso Process: \Device\HarddiskVolume3\Windows\System32\svchost.exe, Status: 0xc0000043, State: 0, ScanRequest #2242, FileId: 0x6000000012a3d, Reason: OnClose, IoStatusBlockForNewFile: 0x2, DesiredAccess:0x0, FileAttributes:0x0, ScanAttributes:0x0, AccessStateFlags:0x0, BackingFileInfo: 0x0, 0x0, 0x0:0\0x0:0
Begin Resource Scan
Scan ID:{C343E826-0000-4000-8000-000000000001}
Scan Source:6
Start Time:12-19-2023 10:33:33
End Time:12-19-2023 10:33:45
Explicit resource to scan
Resource Schema:file
Resource Path:C:\Users\alice\Videos\tool.exe
Result Count:1
Threat Name:HackTool:Win32/Example!MSR
ID:2147805916
Severity:4
Number of Resources:1
Resource Schema:file
Resource Path:C:\Users\alice\Videos\tool.exe
Extended Info - SigSeq:00001667a6e4976b
Extended Info - SigSha:3de04872ea8ce2ceea7d0787abe0000000000001
End Scan
************************************************************
Beginning threat actions
Start time:12-19-2023 10:34:46
Threat Name:HackTool:Win32/Example!MSR
Threat ID:2147805916
Action:quarantine
Resource action complete:Quarantine
Path:\\?\C:\Users\alice\Videos\tool.exe
File to act on SHA1:343051CC1B3F33201D076478EA9BADC700000001
File owner:EXAMPLE\alice
Resource action complete:Removal
Finished threat actions
2023-12-19T09:35:01.549Z DETECTION_CLEANEVENT MPSOURCE_REALTIME MP_THREAT_ACTION_QUARANTINE 0x80508033 HackTool:Win32/Example!MSR file:C:\Users\alice\Videos\tool.exe;
BEGIN BM telemetry
GUID:{12345678-ACEA-905D-0234-000000000001}
SignatureID:119519209161905
SigSha:9dd373682d5f42cfff1504fe09e860ed00000001
ThreatLevel:0
ProcessID:7968
ProcessCreationTime:133474519288037348
SessionID:0
CreationTime:12-19-2023 10:32:08
ImagePath:C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
Taint Info:Friendly: Y; Reason: ; Modules: ; Parents: C:\Program Files\Example Agent\agent.exe:2504:3,
Operations:None
END BM telemetry
2023-12-19T09:36:32.600Z Filter caching disabled for \Device\HarddiskVolume3\Users\alice\Documents\PsExec.exe (runtime MpDisableCaching from 0x0)
2023-12-19T09:36:34.869Z SDN:Issuing SDN query for \Device\HarddiskVolume3\inetpub\wwwroot\shell.aspx (\Device\HarddiskVolume3\inetpub\wwwroot\shell.aspx) (sha1=12345678900b1a36ee0e7f932386ca0000000001, sha2=1234567899876543215059e9780f802a2f75b432b0d87a0000000000000001)
2023-12-19T09:36:40.100Z SDN:SDN query completed: 00000000
2023-12-19T09:37:18.140Z Engine:Setting original file name "psexec.c" for "c:\users\alice\videos\svc.exe", hr=0x0
2023-12-19T09:38:53.270Z Engine:EMS scan for process: lsass pid: 700, sigseq: 0x0000123456789B73, sendMemoryScanReport: 0, source: 1
2023-12-19T09:38:53.271Z Engine:EMS scan for process: notepad.exe pid: 5120, sigseq: 0x0000123456789B74, sendMemoryScanReport: 1, source: 2
2023-12-19T09:38:53.272Z Engine:EMS detection: HackTool:Win64/Example.A!!Example.A64, sigseq=0x0000C0C53E1F0B73, pid=6108
2023-12-19T11:40:00.000+02:00 [RTP] [Exclusion] C:\Tools\ -> \Device\HarddiskVolume3\Tools\
2023-12-19T09:41:00.000Z [RTP] [Exclusion] T:\ is discarded due to error 0x80070002
****************************RTP Perf Log***************************
RTP Start:N/A
Last Perf:(null)
First RTP Scan:N/A
Plugin States:  AV:2  AS:2  RTP:2  OA:2  BM:2
Process Exclusions:
  C:\Tools\agent.exe
Path Exclusions:
  C:\Tools\*
  %windir%\Temp\*.ps1
Ext Exclusions:
  .ps1
  .dll
Worker Threads:4
**************************END RTP Perf Log*************************
2023-12-19T09:42:00.000Z Service stopping
"""

body = LINES.strip("\n").replace("\n", "\r\n") + "\r\n"
with open(sys.argv[1], "wb") as out:
    out.write(b"\xff\xfe" + body.encode("utf-16-le"))
