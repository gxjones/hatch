# Hyper-V throwaway clones

One Windows disk is prepared once. After that, each clone is a differencing disk that cold-boots in about five seconds and accepts Remote Desktop.

Hyper-V rejects a filtered Administrators token. The Hyper-V Administrators group is not filtered, so a normal terminal can manage Hyper-V once that membership is in the logon token. This tool accepts that group or an elevated token. On this PC the group membership is already done; see "This PC right now".

## What you get

| | |
| --- | --- |
| Boot | About 5 seconds to the guest heartbeat after the image is sealed |
| RAM | 2048 MB at boot, idle guests can shrink toward 1536 MB |
| How many | On this 32 GB PC, four clones are comfortable. A fifth fits. A sixth leaves the host as tight as four clones did at 3 GB |
| Sign-in | `User` / `Rdp-test-1` |
| Network | No adapter, unless you pass `--network default` or `--network allow --allow-host name` |

The first boot of a new Windows disk is slow. Windows is installing devices for a machine it has not seen, and the console stays on the Hyper-V logo the whole time. `hv seal` keeps that finished disk and the firmware identity. Later clones are created with the same BIOS identifiers, so Windows treats them as the same PC and skips that setup.

Guest hibernate does not work on this hypervisor (`shutdown /h` returns "The request is not supported"). Do not use it.

## Build

Go is installed at `%LOCALAPPDATA%\Programs\go-sdk\go\bin\go.exe` and is not on `PATH`.

```powershell
cd C:\Users\grant\dev\hyper-v-sandbox
& "$env:LOCALAPPDATA\Programs\go-sdk\go\bin\go.exe" build -o hatch.exe ./cmd/hatch
.\hatch.exe doctor
```

`doctor` should show `vmms` running, the Hyper-V module installed, and Hyper-V access allowed.

## 1. Build a replacement parent

`hatch hv up` uses the parent saved in `%LOCALAPPDATA%\hyper-v-sandbox\config.json`. On this PC that is `C:\ProgramData\hyper-v-sandbox\parents\win11-26300-wdot.vhdx`. `scripts\parent\build.ps1` builds a replacement as one disk in one unattended pass; see [HOWTO-PARENT-IMAGE.md](HOWTO-PARENT-IMAGE.md). Day-to-day commands are in section 5. This section and the next three replace that saved parent.

A replacement parent has to be a frozen base, a VHD no running VM writes. The dev-environment disk is one of those, and the dev VM's checkpoint chain still depends on it:

```text
C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\Windows 11 dev environment.vhdx
```

```powershell
.\hatch.exe hv parent set "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\Windows 11 dev environment.vhdx"
```

Do not boot that file itself, merge checkpoints into it, or mark it read-only. The existing dev VM's checkpoint chain depends on it. Clones only read it through a differencing disk.

## 2. Let one clone finish its first boot

```powershell
.\hatch.exe hv up --connect --wait-ready --ready-timeout 600
```

Wait until the desktop is actually usable, not just past the logo. This boot is the slow one. Leave the VM on the default 2048 MB.

## 3. Turn on Remote Desktop in that guest

The dev image signs in automatically as `User` with a blank password. Remote Desktop rejects a blank password, so set one and keep automatic sign-in pointed at it. In an elevated PowerShell inside the guest:

```powershell
net user User Rdp-test-1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d User /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d Rdp-test-1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
shutdown /s /t 0
```

Wait until Hyper-V shows the VM as Off. Shutting down from inside the guest writes these settings onto the clone disk. Turning the VM off from Hyper-V Manager can skip that flush.

## 4. Seal that disk

```powershell
.\hatch.exe hv seal sbx-XXXXXXXX
```

`seal` moves the clone disk to `C:\ProgramData\hyper-v-sandbox\parents\boot.vhdx`, marks it read-only, and saves the firmware identity in `%LOCALAPPDATA%\hyper-v-sandbox\config.json`. A second argument chooses a different destination file. The VM entry is removed. The sealed disk stays a differencing disk whose parent is the Windows 11 base, so the base file is still required.

`seal` refuses to overwrite `boot.vhdx`. If a sealed parent from an earlier boot is already there, and it does not have Remote Desktop on it, rename it aside only after every clone that uses it is Off and its disks have been deleted. A running differencing disk stores that parent path inside the VHDX.

```powershell
Rename-Item C:\ProgramData\hyper-v-sandbox\parents\boot.vhdx boot-before-rdp.vhdx
.\hatch.exe hv seal sbx-XXXXXXXX
```

## 5. Clone it

```powershell
.\hatch.exe hv up --network default --wait-ready
```

`--network default` attaches the Hyper-V Default Switch, which is how the host reaches the guest. Without it, the clone has no adapter and `mstsc` has nowhere to connect.

The address shows up after the integration services start:

```powershell
(Get-VMNetworkAdapter -VMName sbx-XXXXXXXX).IPAddresses
```

```text
mstsc /v:<ip>
```

Sign in as `User` with `Rdp-test-1`.

```powershell
.\hatch.exe hv up --network allow --allow-host example.com
```

`--network allow` attaches an internal switch, `sbx-allow`, and NATs it through the host. The guest gets a static address on `172.29.248.0/24` and uses the host as its DNS server. TCP port 443 is allowed to the IPv4 addresses of `--allow-host`, `www` on that name, and its subdomains. When the guest looks one of those names up, new addresses are allowed before the answer is returned. UDP and TCP port 53 reach only that DNS proxy. Replies to those sessions are allowed. Use `hatch hv connect` for the console. The switch, NAT, and host gateway stay after the last clone is destroyed. A Hyper-V Administrators token can use them, but only a full administrator token can assign `172.29.248.1` if it is missing.

Other day-to-day commands:

```powershell
.\hatch.exe hv list
.\hatch.exe hv connect sbx-XXXXXXXX
.\hatch.exe hv run sbx-XXXXXXXX --exe C:\lab\feed.exe --arg-file C:\lab\payload.txt
.\hatch.exe hv run sbx-XXXXXXXX --ws-url wss://example/ --ws-token TOKEN
.\hatch.exe hv down sbx-XXXXXXXX
.\hatch.exe hv down --all
```

`down` only deletes VMs this tool created. It turns them off, deletes their differencing disks, and leaves the sealed parent in place.

`hv run` starts a program that is already on the guest disk. PowerShell Direct carries the command, so the clone can stay on `--network none`. `--arg-file` is one UTF-8 argument, which is how to pass a payload of several kilobytes. Windows limits the whole command line to 32766 characters. The program keeps running after the command returns. It runs as `User`. The same `--exe` and `--arg-file` flags on `hv up` start it as soon as the guest accepts a command.

```powershell
.\hatch.exe hv up --exe C:\lab\feed.exe --arg-file C:\lab\payload.txt
.\hatch.exe hv up --network default --ws-url wss://example/ --ws-token TOKEN --wait-ready
```

`--ws-url` and `--ws-token` start `C:\Program Files\wstoudp\wstoudp.exe` in the guest. That program listens on UDP `127.0.0.1:51820` and carries each WireGuard datagram over the WebSocket. The URL and token are not stored in the image. `--ws-url` needs `--network default`, or `--network allow --allow-host` set to the WebSocket host. The process has no window. It appends status lines to `%LOCALAPPDATA%\wstoudp\wstoudp.log` inside the guest.

## Worker

`hatch worker` polls the queue at `https://t6.staticlightlabs.com` and boots a clone for each Windows claim. Pass the worker key at startup. It is not written to the guest disk or the worker state file.

```powershell
.\hatch.exe worker --token $env:WORKER_API_KEY
```

`WORKER_API_KEY` is used when `--token` is omitted. `--server` changes the origin. `--os` defaults to `windows`.

A claim carries a WebSocket URL and token. The worker allows TCP 443 only to that host and starts `wstoudp` with that URL and token. When the proxy is running it reports `success`, the guest address as `host`, and the clone name as `id`. A boot failure is reported as `failure` and that clone is removed. The WebSocket token is not included in the report.

Every few seconds the worker sends the uids of the clones it is running. Any uid in the deleted pile is destroyed. `--poll` changes that interval (default 5s). `--max` is how many clones run at once (default 4). Clones boot in parallel, so a slow boot does not hold up the next claim or a delete. A second worker on the same PC refuses to start.

Once a minute the worker checks its clones against Hyper-V. A clone that is gone or turned off, for example after the host restarts, is reported as `failure` and removed, which frees its slot. The same check restarts the DNS proxy if it is not listening. Each Hyper-V step has a time limit (15 minutes for a boot), so a hung step fails that claim instead of stalling the worker. A clone that cannot be removed, or a report the queue rejects, is logged and retried without holding up other clones. A report the queue rejects with a 4xx other than 401, 403, 408, or 429 is not retried.

State is kept in `%LOCALAPPDATA%\hyper-v-sandbox\worker.json`. The worker key and the WebSocket token are not stored there. The clone name is saved before the boot starts. A restarted worker keeps watching its clones. If it stopped during a boot, the next start reports that claim as a failure and removes the half-built clone. Ctrl+C waits for boots in progress to finish, then leaves the running clones in place. A second Ctrl+C exits immediately.

## This PC right now

Windows Defender's machine-learning detection quarantined the previous binary name `sandbox.exe` as `Trojan:Win32/Bearfoos.A!ml` and killed the running worker. The repo folder and `%LOCALAPPDATA%\Programs\hyper-v-sandbox` are excluded from Defender scanning on this PC. `GOTMPDIR` is set to `.gotmp` in the repo so the linker writes inside the exclusion. Run the worker from the install folder.

`DESKTOP-1B592VD\grant` was added to the local Hyper-V Administrators group on 2026-10-25. `hatch hv` accepts that group in the current logon token, so those commands do not need a full administrator token. Sign out and back in once. Group membership is fixed at logon, and terminals that were already open keep the old token.

The default parent is `parents\win11-26300-wdot.vhdx`, a read-only differencing disk whose parent is `parents\win11-26300-wstoudp-key.vhdx`, whose parent is `parents\win11-26300-wstoudp.vhdx`, whose parent is `parents\win11-26300-wg.vhdx`, whose parent is `parents\win11-26300.vhdx`. That base is a full Windows 11 Pro disk applied from `Windows11_Client_x64_en-us_26300_9457.iso`, so clones do not depend on the dev-environment VHD. `%LOCALAPPDATA%\hyper-v-sandbox\config.json` points at the WDOT disk and stores the firmware identity from the install VM. Remote Desktop is on. Sign in as `User` / `Rdp-test-1`.

`C:\Program Files\wstoudp\wstoudp.exe` is the headless build of [miwigu-bridge](https://github.com/gxjones/miwigu-bridge) `wstoudp` (`go build -tags cli -ldflags="-H windowsgui"`). It does not start until `hv up` or `hv run` passes `--ws-url` and `--ws-token`.

WireGuard 1.1.1 starts with Windows as the `WireGuardTunnel$wg0` service. The guest address is `10.200.99.2/32`. Its peer is `10.200.99.1/32` with public key `mWbVAoXHBA73K0xxqyK8zJW62nzG4J3cx8uUhebulk0=`, endpoint `127.0.0.1:51820`, and a 25 second keepalive. That endpoint is wstoudp, so WireGuard does not bind UDP `51820` itself. This image's public key is `GHhBnw7IqG3OcOcjH7lE3xXVOsNLH64SWpofim1wkE8=`. The private key is in the guest at `C:\ProgramData\WireGuard\wg0.conf` and a copy is in `C:\ProgramData\hyper-v-sandbox\wireguard-gold.json`.

The first sign-in (region, second keyboard, and the Windows Update check) is already finished on that disk, and Windows Update is disabled there so a clone does not sit on that check. Windows Desktop Optimization Tool 1.1.0.0 has also been applied: Windows Search, SysMain, and telemetry services are disabled, the consumer Store apps are removed, and Windows Terminal, Notepad, and the App Installer are still there. A proof clone's guest heartbeat was 5.1 seconds, `User` was already signed in, and port 3389 was listening. That clone has been removed.

`parents\win11-26300-wstoudp-key.vhdx`, `parents\win11-26300-wstoudp.vhdx`, `parents\win11-26300.vhdx`, `parents\win11-26300-wg.vhdx`, `parents\boot.vhdx`, and `parents\boot-before-rdp.vhdx` are still on disk and read-only. The key disk is the parent of the current disk. `sbx-f89d020e` is an older clone that still uses the key disk; leave that parent in place until that clone is gone. New clones use `win11-26300-wdot.vhdx` unless you point `hv parent set` at another disk.
