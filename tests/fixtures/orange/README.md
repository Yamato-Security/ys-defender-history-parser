# Orange Cyberdefense's WDDH samples

Four detection history files of [wddh-parser](https://github.com/cert-orangecyberdefense/wddh-parser)
(Orange Cyberdefense CERT, Apache License 2.0, `LICENSE` in this directory), commit
0d7ff1efcb21f722f3465cc0a4916d5ab4b5fde2, `samples/<folder>/94BBE9CF-CDEB-4885-9178-CC93FB10822D`,
unmodified here:

| Folder | What Orange changed | SHA-256 |
| --- | --- | --- |
| `original/` | nothing (also its `tests/data/` file) | 84cf9c51ee6435e9d7814c8d9ac7477cc538b69ccafaab0d002ddbde593a437b |
| `action_id/` | section 4's error code 0 → 7 and execution status 1 → 5, section 6's first value 2 → 3 | 2a79f6379a7b336c27140ab62d248e32a48f220ad75bb788b1d4aa23e6603302 |
| `search_threat_id/` | section 2's action 4 → 16 and status 3 → 18 | 11737faa63372baf5c1ef561a83fc403c60c6500a0fd5113e834397e6375a8be |
| `ts_modified/` | section 6's last FILETIME | 368adfd492bacffc26a761258ac6e83704893e0747091963aedbdbc41b0ee9f0 |

After each change Orange put the file back on the machine (Windows 10, Defender 4.18.24090.11) and
asked Defender through WMI (`Get-WmiObject -Namespace root\Microsoft\Windows\Defender -Class
MSFT_MpThreatDetection`; its `doc.md` and `samples/*/note.md`). What WMI gave:

| Property | `original/` | `action_id/` | `search_threat_id/` | `ts_modified/` |
| --- | --- | --- | --- | --- |
| ActionSuccess | True | **False** | True | True |
| CleaningActionID | 2 | 2 | **9** | 2 |
| CurrentThreatExecutionStatusID | 1 | **5** | 1 | 1 |
| ThreatStatusErrorCode | 0 | **7** | 0 | 0 |
| ThreatStatusID | 3 | 3 | **18** | 3 |
| RemediationTime | 20250128164506.220000+000 | same | same | **20250128165216.241000+000** |

and for all four: AdditionalActionsBitMask 0, AMProductVersion 4.18.24090.11, DetectionID
{94BBE9CF-CDEB-4885-9178-CC93FB10822D}, DetectionSourceTypeID 3, DomainUser
DESKTOP-O8964S4\RaptorSniper, InitialDetectionTime 20250128164451.243000+000,
LastThreatStatusChangeTime 20250128164506.220000+000, ProcessName
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe, Resources
{file:_C:\Users\RaptorSniper\Downloads\a.zip}, ThreatID 2147686744. `tests/wmi.rs` checks them.
