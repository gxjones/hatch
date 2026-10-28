# Runs inside the guest. build.ps1 copies it to C:\Setup before first boot.
#
# First sign-in (FirstLogonCommands) calls it with -Register. That only
# schedules this script for every sign-in and reboots, so the real work runs
# after OOBE has finished. Remote Desktop does not listen while
# HKLM\SYSTEM\Setup\OOBEInProgress is 1.
#
#   phase install  WireGuard, wstoudp, WDOT, then reboot
#   phase verify   check the result, clean up, shut down
#
# Progress goes to C:\Windows\Temp\hatch-build.log and to the Hyper-V KVP value
# HatchBuild, which build.ps1 polls from the host.
param([switch]$Register)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$setupDir = 'C:\Setup'
$logPath = 'C:\Windows\Temp\hatch-build.log'
$phaseFile = Join-Path $setupDir 'phase.txt'
$taskName = 'hatch-build'

function Status([string]$text) {
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $text
    Add-Content -LiteralPath $logPath -Value $line -Encoding ascii
    try {
        $kvp = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
        if (-not (Test-Path $kvp)) { New-Item -Path $kvp -Force | Out-Null }
        New-ItemProperty -Path $kvp -Name HatchBuild -Value $line -PropertyType String -Force | Out-Null
    } catch {}
}

function Reboot([string]$why) {
    Status $why
    & shutdown.exe /r /t 5 /f
}

function Register-Phases {
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -ExecutionPolicy Bypass -File $setupDir\guest-setup.ps1"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    # Interactive, not a background logon: AppX removal fails with "a user was logged off" otherwise.
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    [IO.File]::WriteAllText($phaseFile, 'install')
    Reboot 'first sign-in done, rebooting into install'
}

function Read-Json([string]$path) {
    $obj = $script:json.DeserializeObject([IO.File]::ReadAllText($path))
    # A JSON array comes back as a fixed-size object[]; WDOT lists need Add().
    if ($obj -is [Array]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $obj) { [void]$list.Add($item) }
        return , $list
    }
    return , $obj
}

function Save-Json([string]$path, $obj) {
    # PowerShell 5.1 ConvertTo-Json wraps these files and WDOT then ignores them.
    [IO.File]::WriteAllText($path, $script:json.Serialize($obj))
}

function New-JsonItem([hashtable]$values) {
    $item = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    foreach ($k in $values.Keys) { $item[$k] = $values[$k] }
    return $item
}

function Install-WireGuard {
    if (Get-Service -Name 'WireGuardTunnel$wg0' -ErrorAction SilentlyContinue) {
        Status 'wireguard already installed'
    } else {
        $msi = Get-ChildItem -LiteralPath $setupDir -Filter 'wireguard-*.msi' | Select-Object -First 1
        if (-not $msi) { throw 'WireGuard MSI missing from C:\Setup' }
        $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/i', $msi.FullName, '/quiet', '/norestart', 'DO_NOT_LAUNCH=1') -Wait -PassThru
        if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec exit $($p.ExitCode)" }
        $wg = 'C:\Program Files\WireGuard\wireguard.exe'
        if (-not (Test-Path -LiteralPath $wg)) { throw 'wireguard.exe missing after install' }
        $p = Start-Process -FilePath $wg -ArgumentList @('/installtunnelservice', 'C:\ProgramData\WireGuard\wg0.conf') -Wait -PassThru -NoNewWindow
        if ($p.ExitCode -ne 0) { throw "wireguard /installtunnelservice exit $($p.ExitCode)" }
    }
    Set-Service -Name 'WireGuardTunnel$wg0' -StartupType Automatic
    if ((Get-Service -Name 'WireGuardTunnel$wg0').Status -ne 'Running') { Start-Service -Name 'WireGuardTunnel$wg0' }
    Status 'wireguard running'
}

function Invoke-Wdot {
    $root = 'C:\WDOT\Windows-Desktop-Optimization-Tool-main'
    if (-not (Test-Path -LiteralPath $root)) {
        Expand-Archive -LiteralPath (Join-Path $setupDir 'wdot.zip') -DestinationPath 'C:\WDOT' -Force
    }
    if (-not (Test-Path -LiteralPath $root)) { throw "WDOT zip did not contain $root" }
    Push-Location $root
    try {
        $cfg = Join-Path $root 'Configurations\sandbox'
        if (-not (Test-Path -LiteralPath $cfg)) { & .\New-WVDConfigurationFiles.ps1 -FolderName sandbox | Out-Null }
        if (-not (Test-Path -LiteralPath $cfg)) { throw 'WDOT did not create the sandbox profile' }

        Add-Type -AssemblyName System.Web.Extensions
        $script:json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $script:json.MaxJsonLength = 64MB

        # Every template item ships as Skip.
        foreach ($name in @('Services.json', 'ScheduledTasks.json', 'AppxPackages.json', 'PolicyRegSettings.json', 'Autologgers.Json')) {
            $path = Join-Path $cfg $name
            $list = Read-Json $path
            foreach ($item in $list) {
                if ($item.ContainsKey('OptimizationState')) { $item['OptimizationState'] = 'Apply' }
            }
            Save-Json $path $list
        }

        # Removal matches with -like, so keep anything a shell package name contains.
        # "Bing Search" in the template matches nothing; Microsoft.BingSearch is the real package.
        $keep = @(
            'Microsoft.DesktopAppInstaller', 'Microsoft.WindowsTerminal', 'Microsoft.WindowsNotepad',
            'Microsoft.Winget.Platform.Source', 'Microsoft.Copilot', 'MicrosoftWindows.Client.WebExperience',
            'Microsoft.Getstarted', 'Bing Search'
        )
        $appxPath = Join-Path $cfg 'AppxPackages.json'
        $appx = Read-Json $appxPath
        $hasBing = $false
        foreach ($item in $appx) {
            $name = ([string]$item['AppxPackage']).Trim()
            $item['AppxPackage'] = $name
            if ($keep -contains $name) { $item['OptimizationState'] = 'Skip' }
            if ($name -eq 'Microsoft.BingSearch') { $hasBing = $true }
        }
        if (-not $hasBing) {
            [void]$appx.Add((New-JsonItem @{ AppxPackage = 'Microsoft.BingSearch'; OptimizationState = 'Apply'; Description = 'Bing search' }))
        }
        Save-Json $appxPath $appx

        $svcPath = Join-Path $cfg 'Services.json'
        $svc = Read-Json $svcPath
        if (-not ($svc | Where-Object { $_['Name'] -eq 'WSearch' })) {
            [void]$svc.Add((New-JsonItem @{ Name = 'WSearch'; OptimizationState = 'Apply'; Description = 'Windows Search' }))
        }
        Save-Json $svcPath $svc
        Status 'wdot profile written'

        & .\Windows_Optimization.ps1 -ConfigProfile sandbox -Optimizations @('Services', 'ScheduledTasks', 'AppxPackages', 'LocalPolicy', 'Autologgers') -AcceptEULA *> 'C:\Windows\Temp\wdot-run.log'
        Status 'wdot applied'
    } finally {
        Pop-Location
    }
}

function Install-Phase {
    $build = Get-Content -LiteralPath (Join-Path $setupDir 'build.json') -Raw | ConvertFrom-Json
    Status 'install started'

    reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
    Stop-Service -Name bits, usosvc, wuauserv -Force -ErrorAction SilentlyContinue

    reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication /t REG_DWORD /d 0 /f | Out-Null
    netsh.exe advfirewall firewall set rule group="remote desktop" new enable=yes | Out-Null

    # Pin autologon so clones sign in on every boot, not just the unattend count.
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '1'
    Set-ItemProperty -Path $winlogon -Name DefaultUserName -Value $build.user
    Set-ItemProperty -Path $winlogon -Name DefaultDomainName -Value $env:COMPUTERNAME
    Set-ItemProperty -Path $winlogon -Name DefaultPassword -Value $build.password
    Remove-ItemProperty -Path $winlogon -Name AutoLogonCount -ErrorAction SilentlyContinue
    Status 'remote desktop, autologon and update policy set'

    if (-not (Test-Path -LiteralPath 'C:\Program Files\wstoudp\wstoudp.exe')) { throw 'wstoudp.exe missing' }
    Install-WireGuard
    if (-not $build.skipWdot) { Invoke-Wdot }

    [IO.File]::WriteAllText($phaseFile, 'verify')
    Reboot 'install done, rebooting to verify'
}

function Verify-Phase {
    Status 'verify started'
    $problems = New-Object System.Collections.Generic.List[string]

    $oobe = (Get-ItemProperty -Path 'HKLM:\SYSTEM\Setup' -Name OOBEInProgress -ErrorAction SilentlyContinue).OOBEInProgress
    if ($oobe -eq 1) { $problems.Add('Windows setup is still in progress (OOBEInProgress=1)') }

    $listening = $false
    for ($i = 0; $i -lt 24 -and -not $listening; $i++) {
        if ($i -eq 6) { Start-Service -Name TermService -ErrorAction SilentlyContinue }
        $listening = @(Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue).Count -gt 0
        if (-not $listening) { Start-Sleep -Seconds 5 }
    }
    if (-not $listening) { $problems.Add('port 3389 is not listening') }

    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    if ($deny -ne 0) { $problems.Add("fDenyTSConnections=$deny") }
    $wg = Get-Service -Name 'WireGuardTunnel$wg0' -ErrorAction SilentlyContinue
    if (-not $wg -or $wg.Status -ne 'Running') { $problems.Add('WireGuardTunnel$wg0 is not running') }
    if (-not (Test-Path -LiteralPath 'C:\Program Files\wstoudp\wstoudp.exe')) { $problems.Add('wstoudp.exe missing') }
    $who = (Get-CimInstance Win32_ComputerSystem).UserName
    if ($who -notmatch '\\User$') { $problems.Add("console user is '$who'") }
    if (Test-Path 'HKLM:\WDOT_TEMP') { & reg.exe unload 'HKLM\WDOT_TEMP' | Out-Null }

    if ($problems.Count -gt 0) { throw ($problems -join '; ') }

    $leftover = @('Microsoft.BingSearch', 'Microsoft.XboxGamingOverlay', 'Microsoft.ZuneMusic') |
        Where-Object { Get-AppxPackage -AllUsers -Name $_ -ErrorAction SilentlyContinue }
    if ($leftover) { Status "warning: still installed: $($leftover -join ', ')" }

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($f in @('build.json', 'phase.txt', 'wdot.zip')) {
        Remove-Item -LiteralPath (Join-Path $setupDir $f) -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem -LiteralPath $setupDir -Filter 'wireguard-*.msi' | Remove-Item -Force
    Remove-Item -LiteralPath 'C:\Windows\Panther\unattend.xml' -Force -ErrorAction SilentlyContinue

    Status 'DONE'
    # build.ps1 polls every 10 seconds; give it time to read DONE.
    & shutdown.exe /s /t 30 /f
}

try {
    if ($Register) {
        Register-Phases
        return
    }
    $phase = ''
    if (Test-Path -LiteralPath $phaseFile) { $phase = ([IO.File]::ReadAllText($phaseFile)).Trim() }
    switch ($phase) {
        'install' { Install-Phase }
        'verify' { Verify-Phase }
        default { throw "unknown phase '$phase'" }
    }
} catch {
    Status "FAILED: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 1
}
