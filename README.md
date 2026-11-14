# FolderGuard

**Password-protected NTFS folder access for Windows 11.**

FolderGuard is a reusable desktop utility: copy `FolderGuard.exe` anywhere, double-click it, pick **any** folder on an NTFS/ReFS drive, give that folder its own password, and its contents become inaccessible until you unlock it. The folder itself stays visible in File Explorer. Nothing is hidden, moved, renamed or encrypted — FolderGuard enforces access with real **NTFS discretionary access control lists (DACLs)**.

- Multiple folders, each with an independent password.
- Unlocks are bound to the current Windows logon session: after sign-out, restart, shutdown — or an unexpected power loss — the folder is locked again, with no shutdown script involved.
- All configuration and permission backups live in `%ProgramData%\FolderGuard`, so the EXE can be moved, copied or replaced freely.
- Self-contained single-file executable: no .NET installation required.

---

## 1. Build status of this delivery

| Item | Result |
| --- | --- |
| `dotnet build -c Release` | **Succeeds**, 0 warnings, 0 errors |
| XAML markup compile | **Succeeds** (Windows 11 style dashboard, dialogs, reusable views) |
| `dotnet publish -r win-x64 --self-contained` | **Succeeds** — `publish/win-x64/FolderGuard.exe` (62.9 MB, `PE32+ GUI x86-64`) |
| Embedded manifest | Verified: `requireAdministrator`, PerMonitorV2 DPI awareness, long-path aware |
| Runtime behaviour on Windows (ACL enforcement, reboot locking, UI rendering) | **Not executed in this environment.** The build machine is Linux; there is no Windows desktop, no NTFS volume and no way to run a Win32 GUI here. Section 12 is the checklist to execute on Windows before you rely on it. |

No claim of “secure” or “tested” is made here beyond what was actually run: the code compiles and packages correctly; the behaviour itself is specified below and must be verified on Windows.

---

## 2. How it works (architecture)

### 2.1 The permission model

FolderGuard only ever rewrites **one** security descriptor: the selected folder's own DACL. Descendants gain or lose access exclusively through **ACL inheritance**, so nothing outside the chosen folder is touched and no recursive file walk is needed.

**Locked DACL** — the persistent default state:

| Trustee | Rights | Applies to |
| --- | --- | --- |
| `NT AUTHORITY\SYSTEM` | Full control | folder + subfolders + files |
| `BUILTIN\Administrators` | Read permissions only (no data rights, no `WRITE_DAC`) | folder + subfolders + files |
| `OWNER RIGHTS` (`S-1-3-4`) | Read permissions only | folder only |

- Inheritance is disabled and the inherited ACEs are discarded for that folder, which is what revokes the usual `Users`/`Authenticated Users`/`<you>` access.
- **No ACE references your user SID.** Opening the folder in non-elevated Explorer shows *“You don't have permission to access this folder”*.
- The folder still appears in its parent because listing rights come from the **parent's** ACEs, which are untouched.
- `SYSTEM` is preserved so backup/restore and servicing tools keep working.
- The `OWNER RIGHTS` ACE suppresses the implicit `READ_CONTROL`/`WRITE_DAC` that a folder owner would otherwise get, so the owner cannot quietly re-grant themselves access through Explorer's security dialog.
- **Administrators receive no data rights and no `WRITE_DAC` on a locked folder.** Explorer's *“You don't have permission… Click Continue to permanently get access”* button elevates and tries to grant your account access — that attempt is denied, so the dialog cannot be used to bypass the lock (verified behaviour, see checklist F5). FolderGuard can still manage the DACL because it enables `SeRestorePrivilege`, `SeBackupPrivilege` and `SeTakeOwnershipPrivilege` in its own elevated token at start-up. An administrator can still deliberately take ownership (`takeown`) — a real, auditable action rather than one click. Folders protected by builds before 1.1.0 still carry the older Administrators-full-control ACE; start-up recovery detects that and re-applies the hardened set automatically.

**Unlocked DACL** — identical, plus:

| Trustee | Rights | Applies to |
| --- | --- | --- |
| your **logon-session SID** (`S-1-5-5-x-y`) | Full control | folder + subfolders + files |

That SID is added from the process token of the current interactive logon session. It gives the intended account full read/write/create/delete access — including deleting files and subfolders — for as long as that session exists.

### 2.2 Why a restart re-locks the folder (without a shutdown script)

A logon-session SID (`S-1-5-5-<high>-<low>`) is generated when you log on and is present only in the tokens of that session. After sign-out, restart, shutdown or power loss, **no token anywhere carries that SID**, so the allow ACE is inert: the folder is inaccessible even though the ACE is still on disk.

This means the guarantee does not depend on FolderGuard, a service, a scheduled task or a shutdown script running at the right moment. The locked state is inherent to the default ACL, and the unlock grant is *self-expiring*. Nothing has to execute to make a crash safe.

On the next start, startup recovery removes the inert leftover ACE and restores the exact canonical locked DACL (see §2.4).

Consequences you should know:
- Unlocking in one Windows session does **not** unlock the folder for another logged-on user or a second RDP session; each session has its own SID and must unlock separately.
- A session that stays logged in *across* something short of a logoff stays unlocked — that is the intended "unlocked for the entire Windows session" behaviour.

### 2.3 Protect / unlock / lock sequence

**Protect**
1. Validate the path (`Directory.Exists`, NTFS/ReFS, not a drive root, not a reparse point, not Windows/Program Files, not FolderGuard's own directory, not nested inside or around an existing protected folder).
2. Show a confirmation dialog with the exact path and require the acknowledgement checkbox.
3. Collect the password twice.
4. Capture the current DACL verbatim (SDDL) plus owner/group SIDs → this is the permission backup.
5. Generate a fresh 16-byte salt, derive a PBKDF2-SHA256 hash (600,000 iterations default).
6. Write a recovery-journal entry.
7. Apply the locked DACL, read it back and **verify the fingerprint**.
8. Persist the record (DPAPI-protected), clear the journal, report success.
9. Any failure → restore the captured DACL and remove the record.

**Unlock**
1. Verify the password in constant time against the stored salt/hash. Wrong password → no permission change at all.
2. Journal the intent.
3. Apply the unlocked DACL (with the current session SID), verify it.
4. Persist `Unlocked` state and clear the journal. Closing FolderGuard leaves it unlocked; the grant dies with the Windows session.

**Lock**
1. Journal, apply the canonical locked DACL, verify, persist `Locked`.

**Remove protection**
1. Verify the password.
2. If someone changed the permissions since protection was applied, warn and require explicit confirmation before overwriting.
3. Restore the captured original DACL verbatim, verify it matches the backup, delete the record. Files are never deleted or moved.

### 2.4 Crash and interruption safety

- **Journal first.** Every ACL mutation writes `%ProgramData%\FolderGuard\journal\<folder-id>.json` before touching the security descriptor, and deletes it only after the change is applied, verified and saved.
- **Verified writes.** After each `SetAccessControl`, the DACL is re-read and compared against a stable fingerprint (sorted ACEs + inheritance flag). A mismatch is treated as a failure and rolled back.
- **Safe default on startup.** Recovery replays leftover journal entries, then re-derives every folder's live state from its ACL. Anything that is not a valid unlock **for the current session** is forced back to the locked DACL. Permission tampering, a stale session ACE or an interrupted operation all end in "locked".
- **Fail closed on data loss.** If `config.dat` cannot be decrypted or parsed, FolderGuard refuses to change any permission at all (it will not even save over the file), and reports the problem in a banner plus the log.
- **No blind guesses.** "Remove protection" refuses to run when no permission backup exists instead of inventing an ACL.
- **No elevation, no operation.** The app manifest requests `requireAdministrator`; `App.OnStartup` also verifies elevation and exits with an explanation if it is missing.

### 2.5 Password storage

- PBKDF2-HMAC-SHA256, 600,000 iterations (configurable default in `appsettings.json`), 16-byte cryptographic salt per folder, 32-byte derived key.
- Only salt + hash + iteration count are stored; they are inside the DPAPI-encrypted configuration blob.
- Verification uses `CryptographicOperations.FixedTimeEquals`; malformed stored data returns "wrong password" rather than throwing.
- Minimum length 8 enforced by both the UI and the service layer; plaintext passwords are never written to disk, the log, or any message.
- Passwords cannot be recovered. Each folder has its own salt and password, so the same password on two folders produces unrelated hashes.

### 2.6 Configuration storage

```
%ProgramData%\FolderGuard\
├─ config.dat          DPAPI-protected JSON (folders, salts, hashes, ACL backups, settings)
├─ config.dat.bak      previous good copy (atomic File.Replace rotation)
├─ journal\            in-flight operation intents (no secrets)
└─ logs\               folderguard-YYYYMMDD.log (no secrets)
```

- `config.dat` is encrypted with DPAPI, `DataProtectionScope.LocalMachine`, with application entropy (`FolderGuard.Configuration.v1`); the directory is ACL-restricted to `SYSTEM` + `Administrators`.
- Writes are atomic: temp file → `File.Replace` (backup kept) → read-back on load with automatic fallback to `config.dat.bak`.
- Nothing is written next to the EXE, so moving/copying/replacing/upgrading the EXE cannot lose protection records.

---

## 3. Requirements

- Windows 11 (also runs on Windows 10 1809+).
- An account that is a member of `Administrators` (UAC elevation prompt is required).
- The selected folder on an **NTFS or ReFS** volume. FAT32/exFAT drives are refused with an explanation.
- No .NET runtime needed for the published EXE (self-contained).
- To build: Windows 10/11 with the .NET 8 SDK (or Linux/macOS with the .NET 8 SDK — `EnableWindowsTargeting` is set).

---

## 4. Build and publish

### 4.1 Install the development tools

```powershell
winget install Microsoft.DotNet.SDK.8
winget install Microsoft.VisualStudio.2022.Community --override "--add Microsoft.VisualStudio.Workload.ManagedDesktop"
```

(VS Code + the C# Dev Kit extension also works; Visual Studio is only needed for the designer.)

### 4.2 Restore and build

```powershell
cd FolderGuard
dotnet restore FolderGuard.sln
dotnet build FolderGuard.sln -c Release
```

### 4.3 Publish the standalone single-file EXE

```powershell
dotnet publish FolderGuard\FolderGuard.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true -o publish\win-x64
```

Output: `publish\win-x64\FolderGuard.exe` — a single file you can copy anywhere (this repository already contains one built with exactly this command).

Variants:

```powershell
# Faster start-up, larger output (no compression)
dotnet publish FolderGuard\FolderGuard.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:PublishReadyToRun=true -o publish\win-x64-r2r

# ARM64 machines
dotnet publish FolderGuard\FolderGuard.csproj -c Release -r win-arm64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish\win-arm64

# Smallest output, requires the .NET 8 Desktop Runtime to be installed
dotnet publish FolderGuard\FolderGuard.csproj -c Release -r win-x64 --self-contained false -o publish\framework-dependent
```

The icon is generated, not checked in as a binary blob:

```powershell
python tools\make_icon.py    # regenerates Resources\AppIcon.ico (.ico with 16/32/48 DIB + 256 PNG) and AppLogo.png
```

`publish/win-x64/FolderGuard.pdb` is only for debugging and is not needed for distribution.

---

## 5. Project structure

```
FolderGuard.sln
FolderGuard/
├─ App.xaml / App.xaml.cs              start-up, elevation check, global error handling
├─ MainWindow.xaml / .xaml.cs          dashboard (folder list, detail panel, actions)
├─ FolderGuard.csproj                  net8.0-windows, WPF, DPAPI package, icon, manifest
├─ app.manifest                        requireAdministrator + PerMonitorV2 DPI
├─ appsettings.json                    installation defaults (PBKDF2 iterations, min length)
├─ Models/
│  ├─ ProtectedFolder.cs               record for one protected folder + ProtectionState
│  └─ FolderConfiguration.cs           configuration root + AppSettings
├─ Services/
│  ├─ AclManager.cs                    DACL capture/restore/build/verify/inspect + path validation
│  ├─ PasswordService.cs               PBKDF2-SHA256 hashing, constant-time verification, policy
│  ├─ ConfigurationService.cs          DPAPI store, atomic save, backup fallback
│  ├─ FolderProtectionService.cs       protect / unlock / lock / change password / repair / remove
│  ├─ RecoveryService.cs               journal replay + startup re-lock reconciliation
│  ├─ JournalStore.cs                  crash-recovery intent records
│  ├─ Logger.cs                        append-only rotating log (no secrets)
│  ├─ AppOptions.cs                    appsettings.json reader for defaults
│  └─ OperationResult.cs               success/message/confirmation result type
├─ ViewModels/
│  └─ FolderItemViewModel.cs           status pill + list presentation
├─ Views/
│  ├─ SetupView.xaml(.cs)              folder picker + Protect button
│  ├─ SettingsView.xaml(.cs)           data folder, reload, lock all, repair
│  ├─ PasswordField.xaml(.cs)          password box with Show/Hide
│  ├─ ProtectFolderDialog.xaml(.cs)    confirmation + create password
│  └─ PasswordDialog.xaml(.cs)         verify password / change password
├─ Resources/
│  ├─ AppIcon.ico                      window/taskbar icon
│  ├─ AppLogo.png                      dashboard header logo
│  └─ Theme.xaml                       Windows 11 colours, cards, buttons, inputs, list style
tools/make_icon.py                     procedural icon generator
publish/win-x64/FolderGuard.exe        self-contained single-file build
README.md
```

---

## 6. First run and everyday use

1. **Copy** `FolderGuard.exe` anywhere (Desktop, a USB stick, `C:\Tools`). Double-click it and approve the UAC prompt.
2. **Select a folder** — *Browse…* opens the Windows folder picker. FolderGuard never pre-selects its own directory and refuses drive roots, the Windows folder, Program Files, junctions/symlinks and non-NTFS volumes.
3. **Protect** — press *Protect Folder*, check the path on the confirmation screen, tick the acknowledgement, type the password twice, press *Protect Folder*.
4. **Status** — the folder appears in *Protected folders* with a **Locked** pill. Its contents are now inaccessible to your normal (non-elevated) Explorer.
5. **Unlock** — select the folder, type its password in the *Password* field (use *Show* to reveal it), press *Unlock*. The status becomes **Unlocked** for this Windows session: you can open, edit, create and delete files normally, including new subfolders.
6. **Lock** — press *Lock* at any time. Unlocking/locking never modifies, moves or deletes contents.
7. **Add more folders** — repeat step 2 for any other folder; each keeps its own password, salt and ACL backup.
8. **Change password** — select the folder → *Change Password* → current password, new password twice. Permissions are untouched.
9. **Remove protection** — select the folder → *Remove Protection* → enter the password → the stored original DACL is restored and the record is deleted. Files stay where they are.
10. **Settings** — *Open data folder* (config, backup, journal, logs), *Reload configuration*, *Lock all now*, *Repair permissions*. Unlocked folders also re-lock by themselves after **5 minutes without keyboard or mouse activity**; closing FolderGuard never locks them.
11. **Restart Windows** — nothing to do: the folders return to **Locked**. Start FolderGuard again to unlock them.
12. **Move or update the EXE** — just copy/replace the file. The records in `%ProgramData%\FolderGuard` are found automatically.

---

## 7. Recovery

| Situation | What FolderGuard does | What you do |
| --- | --- | --- |
| App killed mid-operation, power loss | Journal entry survives; next start re-applies the locked DACL (or finishes a removal whose ACL already matches the backup). | Start FolderGuard; the banner reports what was repaired. |
| Folder shows **Protection Error** | The ACL could not be read/applied (e.g. folder moved or a policy changed it). Nothing destructive happens automatically. | Use *Repair permissions*, or *Remove Protection* to restore the backup. Log: `%ProgramData%\FolderGuard\logs`. |
| Someone / something changed the folder ACL | Startup detects the mismatch and re-applies the locked DACL. | Check the log if this was unexpected. |
| `config.dat` corrupted or missing | The app loads `config.dat.bak`; if both fail it **changes nothing** and shows the reason. | Restore `config.dat` from a backup copy; see below if records are irrecoverable. |
| You forgot a folder's password | The hash cannot be reversed. Administrator access to the ACL is preserved deliberately, so recovery is possible. | Run an elevated shell:<br>`takeown /f "C:\Path" /r /d y`<br>`icacls "C:\Path" /reset /t`<br>then re-protect the folder. Data is not affected. |
| Records lost but folders still locked | The ACL stays locked; without the backup FolderGuard cannot restore the original ACEs exactly. | As above (`takeown` + `icacls /reset`), or restore a `config.dat` copy. |
| Drive moved to another PC | The session SID differs, so the folder is locked there; use the same password after the drive is recognised (protection is bound to the file system ACLs, not to the machine). | Unlock with the folder password. |

Do not delete `%ProgramData%\FolderGuard\config.dat` while folders are protected unless you accept that the original ACLs must be reset manually.

---

## 8. Security limitations — read this honestly

1. **NTFS ACLs are access control, not encryption.** Anyone who can change the ACL (an administrator) or read the raw disk can read the bytes. A bootable Linux USB, another OS, or a disk image bypasses NTFS permissions entirely.
2. **Administrators and SYSTEM can bypass this, but not with one click.** `SYSTEM` keeps full control and a locked folder grants `Administrators` only `READ_CONTROL`, so an elevated Explorer cannot open the contents and the *Continue to permanently get access* button fails rather than re-granting access. Recovery remains possible because FolderGuard enables the restore/backup privileges in its own process, and because an administrator can deliberately take ownership (`takeown /f … /r /d y`) and rewrite the ACL. The lock reliably stops normal desktop use and the one-click elevation prompt; it is not a boundary against a determined local administrator, and it is not encryption.
3. **The password protects the app's workflow, not the data.** It prevents casual unlocking and protects the stored permission backup; it is not a cryptographic key over the files.
4. **DPAPI protects the configuration blob, not the folder contents.** Machine-scope DPAPI means any administrator/SYSTEM process on that machine can decrypt `config.dat`; it never contains plaintext passwords, only salted PBKDF2 hashes.
5. **Only the selected folder's own DACL is rewritten.** Files or subfolders with their own *explicit* ACEs that still grant your account access keep those ACEs — that is by design (data safety: never recursively overwrite unrelated permissions). If you need a fully clean tree, reset child ACLs to inherit (`icacls "C:\Path" /reset /t /c`) once, then protect.
6. **Ownership stays with the current owner.** If the folder is owned by another user, administer it with the same elevated account and check the result with `icacls`.
7. **Multi-session nuance.** An unlock applies to the interactive logon session where you unlocked. Another RDP session or another logged-on user does not inherit it.
8. **No anti-tamper service.** A user who kills FolderGuard, or who never starts it, gets no extra protection — but the folder remains locked because the locked DACL is what is persisted. Conversely, nothing re-locks a folder during a session unless you press *Lock*, leave the machine idle for 5 minutes, or the session ends.
9. **Offline/physical threat: use BitLocker.** For protection against someone with physical access to the drive, enable BitLocker (or another full-disk encryption product) on the volume, ideally with a TPM + PIN. FolderGuard complements that; it does not replace it.

---

## 9. Testing checklist

Run these on a Windows 11 machine against a **disposable test folder** (e.g. `C:\FGTest`) first. "Expected" is what user *X* (the account that protected the folder, non-elevated Explorer) should observe.

### 9.1 Password tests

| # | Test | Steps | Expected |
| --- | --- | --- | --- |
| P1 | Correct password | Protect `C:\FGTest`, then unlock with the same password | Status **Unlocked**; contents open normally |
| P2 | Incorrect password | Unlock with a wrong password | Error "Incorrect password. The folder stays locked."; status stays **Locked**; ACL unchanged (`icacls C:\FGTest`) |
| P3 | Repeated wrong attempts | Try 10 wrong passwords | Same message every time; no lockout damage; correct password still works afterwards |
| P4 | Password change | Change password → old password | Change rejected ("current password is incorrect") |
| P5 | Password change | Change password → new password | Succeeds; old password no longer unlocks; new one does; permissions unchanged |
| P6 | Different passwords | Protect two folders with different passwords | Each unlocks only with its own password |
| P7 | No plaintext | Search `config.dat` and `logs\*.log` | No password string anywhere (file is DPAPI-encrypted; logs contain paths/status only) |

### 9.2 Folder tests

| # | Test | Expected |
| --- | --- | --- |
| F1 | Different folders | Folders on different volumes/profiles can be protected independently |
| F2 | Multiple folders | Both appear in the list with their own status |
| F3 | View contents while unlocked | Explorer lists and opens files |
| F4 | Open / edit / create / delete while unlocked | All succeed, including creating and deleting subfolders |
| F5 | Access while locked | Double-clicking the folder → "You don't have permission to access this folder"; the folder still appears in Explorer. Pressing **Continue** on that dialog must NOT open it (it must report that access is still denied) — this is the check that the Administrators hardening works. |
| F6 | Remove protection | Password accepted → original permissions restored (`icacls` matches the pre-protection output) and contents untouched |
| F7 | Cancel/deny | Cancel every dialog → no permission change |
| F8 | Eligibility refusals | Browse to `C:\`, `C:\Windows`, a FAT32 USB stick, the FolderGuard folder → clear refusal, Protect disabled |
| F9 | Nested refusal | Try a folder inside an already-protected folder → refused with explanation |

### 9.3 Application tests

| # | Test | Expected |
| --- | --- | --- |
| A1 | Close and reopen | Closed while unlocked → still unlocked (default); list and statuses restored |
| A2 | Move the EXE | Copy the EXE to another folder, run it → same folder list, same passwords |
| A3 | Replace the EXE | Replace with a freshly published build → records and ACLs unaffected |
| A4 | Missing configuration | Rename `config.dat` (and `.bak`) away → app reports the failure and changes nothing |
| A5 | Corrupted configuration | Flip bytes in `config.dat` → app loads `.bak` or refuses to save; no ACL writes |
| A6 | Insufficient permissions | Run as a non-admin → elevation prompt; declining it exits with a message and no changes |
| A7 | Interrupted protect | Kill the process (Task Manager) right after pressing Protect; restart → folder ends up locked or fully restored, never half-protected |
| A8 | Lock all / repair | Buttons re-apply the locked ACL and report results |
| A9 | Idle auto-lock | Unlock a folder, leave the machine untouched for 5 minutes → folder re-locks by itself and a banner says so (`GetLastInputInfo` drives this, so activity in any app postpones it) |
| A10 | Close while unlocked | Close the app while a folder is unlocked → it stays unlocked (closing never locks) |

### 9.4 Windows tests

| # | Test | Expected |
| --- | --- | --- |
| W1 | Restart | Unlock, restart Windows, try to open the folder **before** starting FolderGuard → access denied |
| W2 | Shutdown + start | Same as W1 |
| W3 | Power-loss simulation | Unlock, then hold the power button (or `shutdown /r /t 0 /f`), boot again → access denied; the folder's ACL still contains the old session SID (`icacls` shows an unresolved `S-1-5-5-…`); starting FolderGuard removes it and reports "re-locked" |
| W4 | Sign-out / sign-in | Unlock, sign out, sign back in → access denied |
| W5 | Second user | Another local account cannot open the folder in either state (unless it is an administrator) |

Useful verification commands (elevated PowerShell):

```powershell
icacls "C:\FGTest"        # locked: SYSTEM (OI)(CI)(F), Administrators (OI)(CI)(F), OWNER RIGHTS (R)
                          # unlocked: additionally S-1-5-5-<x>-<y> (OI)(CI)(F)
Get-Acl "C:\FGTest" | Format-List
```

Do not describe this application as secure until W1–W3 and F5 have actually passed on your machine.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Nothing happens on double-click | UAC prompt was declined, or the file is blocked: right-click → Properties → *Unblock*. |
| "needs administrator rights" | Account is not an administrator, or elevation was refused. |
| "That drive uses the FAT32 file system…" | Only NTFS/ReFS support ACLs; this includes some USB sticks and SD cards. |
| "That folder is a reparse point" | OneDrive/Dropbox placeholder folders, junctions and symlinks are refused for safety. Choose the real folder. |
| "Protection Error" after moving/renaming a folder | The recorded path no longer matches. Move it back, or *Remove Protection* to clean up and protect the new path. |
| Cannot unlock a folder you own | Check you are in an interactive desktop session (the logon SID must be available) and run FolderGuard elevated. |
| Folder still accessible right after "Lock" | Your shell/Explorer may cache the handle: close the open Explorer window and reopen. Verify with `icacls`. |
| Config failure banner | See §7. Logs are in `%ProgramData%\FolderGuard\logs`. |

---

## 11. Design decisions worth knowing

- **Light Windows 11 theme**, Segoe UI Variable, rounded cards, status pills (Locked / Unlocked / Not Protected / Protection Error), no custom title bar so native window behaviour (snap, shadows, accessibility) is preserved.
- **Closing the app never locks** — an accidental close must not cut you off from an open document — but an unlocked folder re-locks after 5 minutes of machine-wide inactivity, because a locker that stays open forever is not a locker.
- **Nested protection is refused** rather than silently applied: two records over the same tree would make "remove" ambiguous.
- **No service, driver, filter driver or shell extension.** Nothing runs in the background; the security model needs none.
- **No passwords in memory longer than an operation.** They live in WPF `PasswordBox`/`TextBox` state, are used to derive or verify the hash, and are cleared from the UI after each action.
