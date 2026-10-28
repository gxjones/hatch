#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds a sealed Windows 11 parent disk for hatch in one unattended pass.

.DESCRIPTION
Applies Windows from the ISO to a new VHDX, puts everything the guest needs on
that disk before it first boots, and boots it once on a VM with no network
adapter. Inside the guest, scripts\parent\guest-setup.ps1 installs WireGuard,
headless wstoudp, and the Windows Desktop Optimization Tool, reboots, checks
Remote Desktop, and shuts the guest down. This script then records the VM's
firmware identity, points hatch at the new disk, removes the build VM, marks the
disk read-only, and boots one proof clone.

Nothing in the guest is driven from the host, so no PowerShell Direct or
Copy-VMFile is needed. Expect 20 to 40 minutes, mostly DISM and WDOT.

On failure the build VM is left registered so you can open it with vmconnect.
Remove the VM and the VHDX before running again.

.EXAMPLE
.\scripts\parent\build.ps1

.EXAMPLE
.\scripts\parent\build.ps1 -Name win11-gold2 -NoConfig
#>
[CmdletBinding()]
param(
    [string]$Iso = "$env:USERPROFILE\Downloads\Windows11_Client_x64_en-us_26300_9457.iso",
    [string]$Edition = 'Windows 11 Pro',
    [string]$Name = 'win11-gold',
    [string]$Vhd,
    [int]$SizeGB = 64,
    [string]$ComputerName = 'sandbox',
    [string]$User = 'User',
    [string]$Password = 'Rdp-test-1',
    [string]$Wstoudp,
    [string]$WireGuardJson = "$env:ProgramData\hyper-v-sandbox\wireguard-gold.json",
    [string]$Hatch,
    [int]$TimeoutMinutes = 90,
    # Leave config.json alone. The disk is still built, sealed, and read-only.
    [switch]$NoConfig,
    [switch]$SkipWdot,
    [switch]$SkipProof
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dataRoot = Join-Path $env:ProgramData 'hyper-v-sandbox'
$staging = Join-Path $dataRoot 'staging'
$configPath = Join-Path $env:LOCALAPPDATA 'hyper-v-sandbox\config.json'
if (-not $Vhd) { $Vhd = Join-Path $dataRoot "parents\$Name.vhdx" }
if (-not $Wstoudp) { $Wstoudp = Join-Path $repo 'dist\wstoudp.exe' }
if (-not $Hatch) { $Hatch = Join-Path $repo 'hatch.exe' }

$wireGuardMsi = 'wireguard-amd64-1.1.1.msi'
$wireGuardUrl = "https://download.wireguard.com/windows-client/$wireGuardMsi"
$wdotUrl = 'https://github.com/The-Virtual-Desktop-Team/Windows-Desktop-Optimization-Tool/archive/refs/heads/main.zip'

$logPath = Join-Path $env:TEMP "hatch-parent-$Name.log"
$started = Get-Date
function Step([string]$text) {
    $line = '{0} [{1:mm\:ss}] {2}' -f (Get-Date -Format 'HH:mm:ss'), ((Get-Date) - $started), $text
    Add-Content -LiteralPath $logPath -Value $line -Encoding ascii
    Write-Host $line
}

function Get-GuestStatus([string]$vmName) {
    $vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$vmName'"
    if (-not $vm) { return $null }
    $kvp = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_KvpExchangeComponent -ErrorAction SilentlyContinue
    foreach ($raw in @($kvp.GuestExchangeItems)) {
        if (-not $raw) { continue }
        $props = ([xml]$raw).INSTANCE.PROPERTY
        if (($props | Where-Object Name -eq 'Name').InnerText -eq 'HatchBuild') {
            return ($props | Where-Object Name -eq 'Data').InnerText
        }
    }
    return $null
}

function Get-Firmware([string]$vmName) {
    $vm = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$vmName'"
    $s = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData |
        Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' | Select-Object -First 1
    if (-not $s -or -not $s.BIOSGUID) { throw "could not read firmware identity of $vmName" }
    return [ordered]@{
        biosGuid      = ([string]$s.BIOSGUID).Trim('{', '}')
        biosSerial    = [string]$s.BIOSSerialNumber
        boardSerial   = [string]$s.BaseBoardSerialNumber
        chassisSerial = [string]$s.ChassisSerialNumber
        chassisAsset  = [string]$s.ChassisAssetTag
    }
}

function Write-Utf8([string]$path, [string]$text) {
    # Set-Content -Encoding utf8 writes a BOM; Go's JSON decoder rejects it.
    [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding $false))
}

# ---- preflight -------------------------------------------------------------

Import-Module Hyper-V
Import-Module Dism
Step "log: $logPath"

foreach ($f in @($Iso, $Wstoudp, $WireGuardJson, (Join-Path $PSScriptRoot 'unattend.xml'), (Join-Path $PSScriptRoot 'guest-setup.ps1'))) {
    if (-not (Test-Path -LiteralPath $f)) { throw "missing: $f" }
}
if (Test-Path -LiteralPath $Vhd) { throw "$Vhd already exists. Pick another -Name, or delete it if nothing uses it." }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM $Name already exists" }
$free = (Get-PSDrive -Name ($Vhd.Substring(0, 1))).Free
if ($free -lt 40GB) { throw ("only {0:N0} GB free for $Vhd" -f ($free / 1GB)) }

$wg = Get-Content -LiteralPath $WireGuardJson -Raw | ConvertFrom-Json
foreach ($k in @('privateKey', 'address', 'peerPublicKey', 'peerAllowedIPs', 'endpoint')) {
    if (-not $wg.$k) { throw "$WireGuardJson has no $k" }
}

New-Item -ItemType Directory -Force -Path $staging, (Split-Path $Vhd) | Out-Null
$msiPath = Join-Path $staging $wireGuardMsi
$wdotZip = Join-Path $staging 'wdot.zip'
if (-not (Test-Path -LiteralPath $msiPath)) {
    Step "downloading $wireGuardMsi"
    & curl.exe -fsSL -o $msiPath $wireGuardUrl
    if ($LASTEXITCODE -ne 0) { throw "download failed: $wireGuardUrl" }
}
if (-not $SkipWdot -and -not (Test-Path -LiteralPath $wdotZip)) {
    Step 'downloading Windows Desktop Optimization Tool'
    & curl.exe -fsSL -o $wdotZip $wdotUrl
    if ($LASTEXITCODE -ne 0) { throw "download failed: $wdotUrl" }
}

# ---- apply Windows and stage the guest files -------------------------------

Step "mounting $Iso"
Get-DiskImage -ImagePath $Iso -ErrorAction SilentlyContinue | Where-Object Attached | Dismount-DiskImage | Out-Null
$isoImage = Mount-DiskImage -ImagePath $Iso -PassThru
$vhdMounted = $false
try {
    $isoLetter = ($isoImage | Get-Volume).DriveLetter
    $wim = "${isoLetter}:\sources\install.wim"
    if (-not (Test-Path -LiteralPath $wim)) { $wim = "${isoLetter}:\sources\install.esd" }
    if (-not (Test-Path -LiteralPath $wim)) { throw 'ISO has no install.wim or install.esd' }
    $image = Get-WindowsImage -ImagePath $wim | Where-Object ImageName -eq $Edition | Select-Object -First 1
    if (-not $image) { throw "edition '$Edition' not in $wim" }
    Step "edition: $($image.ImageName) (index $($image.ImageIndex))"

    New-VHD -Path $Vhd -SizeBytes ($SizeGB * 1GB) -Dynamic | Out-Null
    $disk = Mount-VHD -Path $Vhd -Passthru | Get-Disk
    $vhdMounted = $true
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
    $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter
    Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel SYSTEM -Confirm:$false | Out-Null
    New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
    $os = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -AssignDriveLetter
    Format-Volume -Partition $os -FileSystem NTFS -NewFileSystemLabel Windows -Confirm:$false | Out-Null
    $efiLetter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber).DriveLetter
    $osLetter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $os.PartitionNumber).DriveLetter
    if (-not $efiLetter -or -not $osLetter) { throw 'new partitions did not get drive letters' }
    $root = "${osLetter}:\"

    Step 'applying Windows image (DISM, several minutes)'
    & dism.exe /Apply-Image "/ImageFile:$wim" "/Index:$($image.ImageIndex)" "/ApplyDir:$root" /Quiet
    if ($LASTEXITCODE -ne 0) { throw "dism /Apply-Image exit $LASTEXITCODE" }
    & bcdboot.exe "${root}Windows" /s "${efiLetter}:" /f UEFI | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "bcdboot exit $LASTEXITCODE" }

    Step 'staging guest files on the new disk'
    $esc = { param($s) [Security.SecurityElement]::Escape($s) }
    $unattend = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'unattend.xml'))
    $unattend = $unattend.Replace('{{COMPUTER_NAME}}', (& $esc $ComputerName)).Replace('{{USER}}', (& $esc $User)).Replace('{{PASSWORD}}', (& $esc $Password))
    New-Item -ItemType Directory -Force -Path "${root}Windows\Panther", "${root}Setup", "${root}Program Files\wstoudp", "${root}ProgramData\WireGuard" | Out-Null
    Write-Utf8 "${root}Windows\Panther\unattend.xml" $unattend

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest-setup.ps1') -Destination "${root}Setup\guest-setup.ps1"
    Copy-Item -LiteralPath $msiPath -Destination "${root}Setup\$wireGuardMsi"
    if (-not $SkipWdot) { Copy-Item -LiteralPath $wdotZip -Destination "${root}Setup\wdot.zip" }
    Copy-Item -LiteralPath $Wstoudp -Destination "${root}Program Files\wstoudp\wstoudp.exe"
    Write-Utf8 "${root}Setup\build.json" (@{ user = $User; password = $Password; skipWdot = [bool]$SkipWdot } | ConvertTo-Json)

    $keepalive = if ($wg.persistentKeepalive) { $wg.persistentKeepalive } else { 25 }
    $conf = @(
        '[Interface]'
        "PrivateKey = $($wg.privateKey)"
        "Address = $($wg.address)"
        ''
        '[Peer]'
        "PublicKey = $($wg.peerPublicKey)"
        "AllowedIPs = $($wg.peerAllowedIPs)"
        "Endpoint = $($wg.endpoint)"
        "PersistentKeepalive = $keepalive"
    ) -join "`r`n"
    Write-Utf8 "${root}ProgramData\WireGuard\wg0.conf" ($conf + "`r`n")
} finally {
    if ($vhdMounted) { Dismount-VHD -Path $Vhd }
    Dismount-DiskImage -ImagePath $Iso | Out-Null
}

# ---- boot it once ----------------------------------------------------------

Step "creating VM $Name"
New-VM -Name $Name -Generation 2 -MemoryStartupBytes 4GB -VHDPath $Vhd | Out-Null
Set-VM -Name $Name -ProcessorCount 4 -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Disabled `
    -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -Notes 'hyper-v-sandbox install'
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows `
    -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name | Select-Object -First 1)
# No adapter: OOBE skips the Microsoft account and Windows Update pages.
Get-VMNetworkAdapter -VMName $Name | Remove-VMNetworkAdapter
Enable-VMIntegrationService -VMName $Name -Name 'Key-Value Pair Exchange'

Start-VM -Name $Name
Start-Process -FilePath "$env:SystemRoot\System32\vmconnect.exe" -ArgumentList 'localhost', $Name | Out-Null
Step 'guest booting. Progress below comes from inside the guest; the console window is only for watching.'

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$last = $null
while ($true) {
    Start-Sleep -Seconds 10
    $vm = Get-VM -Name $Name
    $status = Get-GuestStatus $Name
    if ($status -and $status -ne $last) {
        Step "guest: $status"
        $last = $status
    }
    if ($status -match ' FAILED: ') { throw "guest setup failed. VM $Name is left running; see C:\Windows\Temp\hatch-build.log inside it." }
    if ($vm.State -eq 'Off') { break }
    if ((Get-Date) -gt $deadline) { throw "VM $Name still running after $TimeoutMinutes minutes. Open vmconnect to see where it stopped." }
}
if ($last -notmatch ' DONE$') {
    # KVP goes away with the VM; the log on the disk is the record.
    $guestLog = $null
    $ro = Mount-VHD -Path $Vhd -ReadOnly -Passthru
    try {
        Start-Sleep -Seconds 2
        foreach ($v in ($ro | Get-Disk | Get-Partition | Get-Volume | Where-Object DriveLetter)) {
            $p = "$($v.DriveLetter):\Windows\Temp\hatch-build.log"
            if (Test-Path -LiteralPath $p) { $guestLog = @(Get-Content -LiteralPath $p) }
        }
    } finally {
        Dismount-VHD -Path $Vhd
    }
    if ($guestLog) { $last = $guestLog[-1]; Step "guest log ends: $last" }
    if ($last -notmatch ' DONE$') { throw "VM $Name turned off before guest setup reported DONE (last: '$last')" }
}

# ---- freeze ------------------------------------------------------------------

$firmware = Get-Firmware $Name
Step "firmware: BIOS GUID $($firmware.biosGuid)"

if (-not $NoConfig) {
    $memoryMB = 2048
    $cpus = 2
    if (Test-Path -LiteralPath $configPath) {
        $backup = "$configPath.{0:yyyyMMdd-HHmmss}.bak" -f (Get-Date)
        Copy-Item -LiteralPath $configPath -Destination $backup
        Step "old config saved to $backup"
        $old = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        if ($old.memoryMB) { $memoryMB = [int]$old.memoryMB }
        if ($old.cpus) { $cpus = [int]$old.cpus }
    } else {
        New-Item -ItemType Directory -Force -Path (Split-Path $configPath) | Out-Null
    }
    $config = [ordered]@{ parentVhd = $Vhd; memoryMB = $memoryMB; cpus = $cpus; sealed = $true }
    foreach ($k in $firmware.Keys) { $config[$k] = $firmware[$k] }
    Write-Utf8 $configPath (($config | ConvertTo-Json) + "`n")
    Step "config.json now points at $Vhd"
}

Remove-VM -Name $Name -Force
Set-ItemProperty -LiteralPath $Vhd -Name IsReadOnly -Value $true
Step "sealed: $Vhd (read-only, build VM removed)"

if ($NoConfig) {
    Step 'firmware identity (needed if you point config.json at this disk later):'
    $firmware.GetEnumerator() | ForEach-Object { Step "  $($_.Key) = $($_.Value)" }
}

# ---- proof clone -------------------------------------------------------------

if ($SkipProof -or $NoConfig) { Step 'build finished'; return }
if (-not (Test-Path -LiteralPath $Hatch)) {
    Step "build finished. No proof clone: $Hatch not found (go build -o hatch.exe ./cmd/hatch)."
    return
}

Step 'proof clone: hatch hv up --network default --wait-ready'
$up = & $Hatch hv up --network default --wait-ready 2>&1 | ForEach-Object { "$_" }
$up | ForEach-Object { Write-Host "  $_" }
$clone = ($up | Select-String -Pattern 'hatch hv down (\S+)' | Select-Object -First 1).Matches.Groups[1].Value
if (-not $clone) { throw 'proof clone did not start; see output above' }
try {
    $ip = $null
    $rdp = $false
    $until = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $until -and -not $rdp) {
        $ip = Get-VMNetworkAdapter -VMName $clone | ForEach-Object IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        if ($ip) {
            $tcp = New-Object Net.Sockets.TcpClient
            try { $rdp = $tcp.ConnectAsync($ip, 3389).Wait(2000) -and $tcp.Connected } catch {} finally { $tcp.Dispose() }
        }
        if (-not $rdp) { Start-Sleep -Seconds 3 }
    }
    if ($rdp) { Step "proof clone $clone answers Remote Desktop at ${ip}:3389" }
    else { Step "warning: proof clone $clone did not answer on port 3389 (ip: $ip)" }
} finally {
    & $Hatch hv down $clone | Out-Null
    Step "proof clone $clone removed"
}
Step 'build finished'
