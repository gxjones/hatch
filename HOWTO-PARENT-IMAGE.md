# Build the parent image

`scripts\parent\build.ps1` builds a sealed Windows 11 parent in one unattended pass and points `hatch` at it. Clones of it cold-boot in about five seconds, sign in as `User` / `Rdp-test-1`, and accept Remote Desktop.

## Before you run it

- The ISO: `C:\Users\grant\Downloads\Windows11_Client_x64_en-us_26300_9457.iso` (or pass `-Iso`). The script uses the `Windows 11 Pro` edition; Home cannot host inbound Remote Desktop.
- Headless `wstoudp` at `dist\wstoudp.exe`. Build it from `miwigu\wstoudp` in [miwigu-bridge](https://github.com/gxjones/miwigu-bridge):

  ```powershell
  $env:CGO_ENABLED = "0"
  & "$env:LOCALAPPDATA\Programs\go-sdk\go\bin\go.exe" build -tags cli -trimpath -ldflags="-H windowsgui" -o C:\Users\grant\dev\hyper-v-sandbox\dist\wstoudp.exe .
  ```

- The tunnel key at `C:\ProgramData\hyper-v-sandbox\wireguard-gold.json`, with `privateKey`, `address`, `peerPublicKey`, `peerAllowedIPs`, `endpoint`, and `persistentKeepalive`. The private key is the one in `miwigu/wg_host/windows-dummy.conf`.
- `hatch.exe` at the repo root, for the proof clone at the end (`go build -o hatch.exe ./cmd/hatch`). Without it the build still finishes and skips the proof.

The WireGuard 1.1.1 MSI and the Windows Desktop Optimization Tool (WDOT) zip are downloaded into `C:\ProgramData\hyper-v-sandbox\staging` if they are not already there.

## Run it

From an elevated PowerShell in the repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\parent\build.ps1
```

It takes 20 to 40 minutes. A console window opens on the build VM so you can watch it; you do not need to click anything. Progress lines from inside the guest are printed in the PowerShell window and saved to `%TEMP%\hatch-parent-win11-gold.log`.

The result is `C:\ProgramData\hyper-v-sandbox\parents\win11-gold.vhdx`, read-only. `%LOCALAPPDATA%\hyper-v-sandbox\config.json` now points at it, and the previous config is saved next to it as `config.json.<time>.bak`. Older parent disks are left in place, and clones that still use them keep working.

Useful options:

| Option | Effect |
| --- | --- |
| `-Name win11-gold2` | Different VM and disk name. The script refuses to overwrite either. |
| `-NoConfig` | Build and seal the disk without changing `config.json`. The firmware identity is printed instead. |
| `-SkipWdot` | No WDOT. |
| `-SkipProof` | No proof clone. |

## What it does

1. Applies Windows 11 Pro from the ISO to a new 64 GB dynamic VHDX (GPT: 260 MB EFI, 16 MB MSR, NTFS), and runs `bcdboot`.
2. Writes everything the guest needs onto that disk before it boots: `scripts\parent\unattend.xml` with the user and password filled in, `C:\Setup\guest-setup.ps1`, the WireGuard MSI, the WDOT zip, `C:\Program Files\wstoudp\wstoudp.exe`, and `C:\ProgramData\WireGuard\wg0.conf`.
3. Boots it on a Generation 2 VM with 4 GB, 4 processors, Secure Boot, and no network adapter. Without an adapter, OOBE skips the Microsoft account and Windows Update pages. The unattend sets the locale in the `oobeSystem` pass, which skips the region and keyboard pages.
4. Inside the guest, `guest-setup.ps1` runs in three steps:
   - At first sign-in, it only schedules itself for later sign-ins and reboots. Remote Desktop does not listen until Windows setup has fully finished (`HKLM\SYSTEM\Setup\OOBEInProgress` = 0), so nothing that needs it runs during that first sign-in.
   - Install: turns off Windows Update, enables Remote Desktop and its firewall rules, pins automatic sign-in to `User`, installs WireGuard and the `WireGuardTunnel$wg0` service, and applies WDOT. Then it reboots.
   - Verify: checks that setup has finished, port 3389 is listening, the tunnel is running, `wstoudp.exe` is present, and `User` is on the console. Then it deletes the installers and the files that hold the password in plain text, and shuts down from inside so every write is flushed.
5. The host reads the build VM's firmware identity (BIOS GUID and serial numbers), writes `config.json`, removes the VM, and marks the VHDX read-only. Clones copy that identity, so Windows treats each one as the same PC and skips device setup. Do not sysprep.
6. Proof: `hatch hv up --network default --wait-ready`, a TCP check of port 3389 on the clone, then `hatch hv down`.

The guest reports progress through the Hyper-V key-value exchange (value `HatchBuild`), and the full log is `C:\Windows\Temp\hatch-build.log` in the guest. Nothing is pushed into the guest while it runs, so the host needs no PowerShell Direct or `Copy-VMFile`.

## WDOT profile

The profile is named `sandbox`. Every template item ships as `Skip`. The script sets Services, ScheduledTasks, AppxPackages, LocalPolicy, and Autologgers to `Apply`, and adds `WSearch` and `Microsoft.BingSearch`. These AppX packages are kept: `Microsoft.DesktopAppInstaller`, `Microsoft.WindowsTerminal`, `Microsoft.WindowsNotepad`, `Microsoft.Winget.Platform.Source`, `Microsoft.Copilot`, `MicrosoftWindows.Client.WebExperience`, and `Microsoft.Getstarted`. Removal matches with `-like`, so dropping `Copilot` or `WebExperience` would take shell packages with it. Default-user settings, network optimizations, disk cleanup, `RemoveOneDrive`, and `RemoveLegacyIE` are off.

The profile JSON is written with `JavaScriptSerializer`. PowerShell 5.1 `ConvertTo-Json` wraps those files, and WDOT then ignores them.

## If it fails

The build VM is left registered and running (or off), and the script prints the last guest step. Open it with `vmconnect localhost win11-gold` and read `C:\Windows\Temp\hatch-build.log`. `config.json` is only changed after the guest reports `DONE`.

To try again, delete the VM and its disk:

```powershell
Stop-VM -Name win11-gold -TurnOff -Force
Remove-VM -Name win11-gold -Force
Remove-Item C:\ProgramData\hyper-v-sandbox\parents\win11-gold.vhdx
```
