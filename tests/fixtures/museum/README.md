# DFIRArtifactMuseum's Defender files

Microsoft Defender files of [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
(MIT License, `LICENSE` in this directory), commit 7d16ff39c9efc0ddd7307fcb3d30ff5c6e8d99f3, under
`Windows/WindowsDefender/`. The detection history files are unmodified; the logs are stored
gzip-compressed (`gzip -9n`), otherwise unmodified. SHA-256 of each file (uncompressed):

| File | Source |
| --- | --- |
| `apt-simulator-vm/DetectionHistory/<nn>/<GUID>` (14 files) | `APTSimulatorVM/Windows Defender/APTSimulatorVM_WindowsDefenderArtifacts.zip`, `Scans/History/Service/DetectionHistory/` |
| `apt-simulator-vm/Support/MPLog-20220310-113238.log.gz` | the same zip, `Support/` |
| `apt-simulator-vm/Support/MPDetection-20220310-113238.log.gz` | the same zip, `Support/` (empty: its byte order mark only) |
| `belkasoft-ctf/MPLog-20200801-144809.log.gz` | `BelkasoftCTF_InsiderThreat/` |
| `belkasoft-ctf/MPDetection-20210213-115635.log.gz` | `BelkasoftCTF_InsiderThreat/` |
| `server2022-apt-simulator-vm/MPLog-20231017-224350.log.gz` | `Server2022/APTSimulatorVM/` |

```
176520ad4b28b197ea31d3818967f6593d140e38b0df1ebb64355c6812280f1c  apt-simulator-vm/DetectionHistory/00/513F108E-C674-4D19-AE23-79C9AD68A0E6
8d092f1094aa3ead7525be66daff3ed1bce07e9729aa8e1d5fe7bffbcd1daa59  apt-simulator-vm/DetectionHistory/02/0F3D5CDF-677A-4AF9-BDE9-54E0ACD9900D
8bea4412a9a17f47b84c83eb4bc83311705bdd824f1853f258eaefcb1b4bb862  apt-simulator-vm/DetectionHistory/06/9E32E01D-CD43-43F0-8CAA-B3CDD510DE46
4d0af564c03a56055418edfd70bf4750d82e60670749d822969084f85d01d95e  apt-simulator-vm/DetectionHistory/07/954F8207-88D2-445F-8B53-5FD17757E16C
d16ce38c0e259d6168f7f000bf121c3e03a40405e4b0dfe75cbaf1e7b20a2d4e  apt-simulator-vm/DetectionHistory/09/E36FC3A2-3409-4121-BA72-C495E2B33F75
ec942f3e0c264134a15ff122cd0cb26f7d09084206876e85bcdba072b462c913  apt-simulator-vm/DetectionHistory/09/FDC89D27-9486-452A-AACC-DA003DE0327D
0963f8e1a76eb361f403e51fd75e3b7acdc4d4786d61784d3b54bbfd378750c0  apt-simulator-vm/DetectionHistory/10/7A1AAF2D-54D6-401D-B2B6-654FF236A602
c9148141840daaa37903a72a2ed96b1b26be16d47eeb81d7271f6a98ed9a2451  apt-simulator-vm/DetectionHistory/11/D28F6999-A792-49B2-A426-F27CCF487969
ced457977bee4324a4a2c2ddb964141793749662b203ad27c31148fdd6e5dee8  apt-simulator-vm/DetectionHistory/12/4565EB79-8AE0-4C7D-9CBD-25E244ACE78F
11e671ae8b7a2ed396d8836cdd0eabbffc73322278376d768afb40d1019fb6e6  apt-simulator-vm/DetectionHistory/13/DEAD4CDD-57BA-4E73-BEE0-6368EAE6D05D
1f9072de0115c3e1c744a6196606f0d49121bf6d15ee6ee168135a058c049d92  apt-simulator-vm/DetectionHistory/17/22685A5C-1579-496A-8845-00EE5D5E3602
45500a55e129baf7bf612f24ca17225c5c2a97122ee077d2f4c5ccf0b156d909  apt-simulator-vm/DetectionHistory/18/DC244D4E-9802-4EBB-99B0-9DCB63F4E8DF
ba5994d42fc96d462d2561fc6dbc9022e9fa6a40b1adc98a41999ebf5e2df8b9  apt-simulator-vm/DetectionHistory/19/5FF32066-BADC-4665-940A-0A22C83B2981
d04bb546ec93f7a78fc57539613ba04737cb78cfde6c92a71bdbe41814b8ad63  apt-simulator-vm/DetectionHistory/20/2E020CDD-FE3C-494C-905B-2943F112A836
b303433ae20181fa10f3027ed611e0ca27e628bf5736985129af1d63d0b1b947  apt-simulator-vm/Support/MPLog-20220310-113238.log
b3d510ef04275ca8e698e5b3cbb0ece3949ef9252f0cdc839e9ee347409a2209  apt-simulator-vm/Support/MPDetection-20220310-113238.log
0a9029a100b8d536cfa47022a2e9c61ea30ceb920c1b72f3f9c6a004ad732603  belkasoft-ctf/MPLog-20200801-144809.log
88bd85d04650b7c3db23118bfa0c9e00fa643961d9be809529c8a79d4e6bb46d  belkasoft-ctf/MPDetection-20210213-115635.log
7a1529a65ec67bb2f8b349edcd44307af4ced54ed02e1c802987c6e247f8133c  server2022-apt-simulator-vm/MPLog-20231017-224350.log
```
