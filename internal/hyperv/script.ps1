$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

function Emit($obj) {
    $json = $obj | ConvertTo-Json -Compress -Depth 6
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Write-Output ([Convert]::ToBase64String($bytes))
}

function Require-Name([string]$name) {
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'VM name is empty' }
}

function Assert-UnderRoot([string]$path) {
    $root = [System.IO.Path]::GetFullPath($env:SBX_ROOT)
    if (-not $root.EndsWith('\')) { $root += '\' }
    $full = [System.IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to delete $full because it is outside $root"
    }
}

function Set-SandboxNetwork([string]$name, [string]$network) {
    switch ($network) {
        'none' {
            Get-VMNetworkAdapter -VMName $name | Remove-VMNetworkAdapter
        }
        'private' {
            $swName = 'sbx-private'
            if (-not (Get-VMSwitch -Name $swName -ErrorAction SilentlyContinue)) {
                New-VMSwitch -Name $swName -SwitchType Private | Out-Null
            }
            if (-not @(Get-VMNetworkAdapter -VMName $name)) {
                Add-VMNetworkAdapter -VMName $name | Out-Null
            }
            Get-VMNetworkAdapter -VMName $name | Connect-VMNetworkAdapter -SwitchName $swName
        }
        'default' {
            if (-not (Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue)) {
                throw "Default Switch was not found. Pass --network none or --network private."
            }
            if (-not @(Get-VMNetworkAdapter -VMName $name)) {
                Add-VMNetworkAdapter -VMName $name | Out-Null
            }
            Get-VMNetworkAdapter -VMName $name | Connect-VMNetworkAdapter -SwitchName 'Default Switch'
        }
        'allow' {
            $script:AllowPlan = Initialize-AllowNetwork $name $env:SBX_ALLOW_HOST
        }
        default { throw "unknown network '$network' (use none, private, default, or allow)" }
    }
}

$script:AllowSwitch = 'sbx-allow'
$script:AllowAlias = 'vEthernet (sbx-allow)'
$script:AllowGateway = '172.29.248.1'
$script:AllowPrefix = '172.29.248.0/24'
$script:AllowPrefixLength = 24
$script:AllowPlan = $null

function Get-AllowTablePath {
    Join-Path $env:SBX_ROOT 'allow-net.json'
}

function Invoke-AllowLocked([scriptblock]$Body) {
    $mutex = New-Object System.Threading.Mutex($false, 'Global\hyper-v-sandbox-allow')
    $owned = $false
    try {
        try {
            $owned = $mutex.WaitOne(30000)
        } catch {
            $abandoned = $_.Exception -is [System.Threading.AbandonedMutexException] -or $_.Exception.InnerException -is [System.Threading.AbandonedMutexException]
            if (-not $abandoned) { throw }
            $owned = $true
        }
        if (-not $owned) { throw 'timed out waiting for the allow-network lock' }
        & $Body
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Read-AllowTable {
    $path = Get-AllowTablePath
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            gateway      = $script:AllowGateway
            prefix       = $script:AllowPrefix
            prefixLength = $script:AllowPrefixLength
            hosts        = [pscustomobject]@{}
        }
    }
    $table = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if (-not $table.hosts) {
        $table | Add-Member -NotePropertyName hosts -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    return $table
}

function Save-AllowTable($table) {
    $path = Get-AllowTablePath
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    $tmp = $path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, ($table | ConvertTo-Json -Depth 6))
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Grant-HyperVAdminDelete $path
}

function Update-AllowHosts($table) {
    $alive = @{}
    foreach ($vm in @(Get-VM -ErrorAction SilentlyContinue)) { $alive[$vm.Name] = $true }
    foreach ($prop in @($table.hosts.PSObject.Properties)) {
        if (-not $alive.ContainsKey($prop.Name)) {
            $table.hosts.PSObject.Properties.Remove($prop.Name)
        }
    }
}

function Get-AllowEntryIP($value) {
    if ($null -eq $value) { return '' }
    if ($value -is [string]) { return [string]$value }
    return [string]$value.ip
}

function Add-AllowAddress([string]$name, [string]$allowHost) {
    $table = Read-AllowTable
    Update-AllowHosts $table
    $existing = $table.hosts.PSObject.Properties[$name]
    if ($existing) {
        $ip = Get-AllowEntryIP $existing.Value
        $table.hosts.PSObject.Properties.Remove($name)
        $entry = [pscustomobject]@{ ip = $ip; allowHost = $allowHost }
        $table.hosts | Add-Member -NotePropertyName $name -NotePropertyValue $entry -Force
        Save-AllowTable $table
        return $ip
    }
    $used = @{}
    foreach ($prop in @($table.hosts.PSObject.Properties)) { $used[(Get-AllowEntryIP $prop.Value)] = $true }
    $ip = $null
    for ($i = 10; $i -le 250; $i++) {
        $candidate = "172.29.248.$i"
        if (-not $used.ContainsKey($candidate)) { $ip = $candidate; break }
    }
    if (-not $ip) { throw 'allow network has no free guest addresses' }
    $entry = [pscustomobject]@{ ip = $ip; allowHost = $allowHost }
    $table.hosts | Add-Member -NotePropertyName $name -NotePropertyValue $entry -Force
    Save-AllowTable $table
    return $ip
}

function Resolve-OneAllowIPv4([string]$allowHost) {
    $parsed = $null
    $isIP = [System.Net.IPAddress]::TryParse($allowHost, [ref]$parsed)
    if ($isIP) {
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw '--allow-host must be an IPv4 address or a DNS name'
        }
        return @($parsed.IPAddressToString)
    }
    $recs = @(Resolve-DnsName -Name $allowHost -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' -and $_.IPAddress })
    $ips = @($recs | ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
    if ($ips.Count -eq 0) { throw "no IPv4 address for $allowHost" }
    return $ips
}

function Resolve-AllowIPv4([string]$allowHost) {
    $ips = @(Resolve-OneAllowIPv4 $allowHost)
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($allowHost, [ref]$parsed)) { return $ips }
    $extra = @()
    if ($allowHost.StartsWith('www.')) {
        $apex = $allowHost.Substring(4)
        if ($apex) { $extra += $apex }
    } else {
        $extra += ('www.' + $allowHost)
    }
    foreach ($name in $extra) {
        try { $ips += @(Resolve-OneAllowIPv4 $name) } catch { }
    }
    return @($ips | Select-Object -Unique)
}

function Get-AllowDnsServers {
    $servers = @()
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if ($route) {
        $servers = @(Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ServerAddresses })
    }
    $clean = @()
    foreach ($server in $servers) {
        if ([string]::IsNullOrWhiteSpace($server)) { continue }
        if ($server -eq '127.0.0.1') { continue }
        if ($server -like '172.29.248.*') { continue }
        if ($clean -notcontains $server) { $clean += $server }
    }
    if ($clean.Count -eq 0) { $clean = @('1.1.1.1', '8.8.8.8') }
    return $clean
}

function Ensure-AllowSwitch {
    $alias = $script:AllowAlias
    $overlap = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -like '172.29.248.*' -and $_.InterfaceAlias -ne $alias
    })
    if ($overlap.Count -gt 0) {
        throw "172.29.248.0/24 is already used by $($overlap[0].InterfaceAlias)"
    }
    if (-not (Get-VMSwitch -Name $script:AllowSwitch -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $script:AllowSwitch -SwitchType Internal | Out-Null
    }
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        if (Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue) { $up = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $up) { throw "host adapter $alias did not appear" }
    $have = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $script:AllowGateway })
    if ($have.Count -eq 0) {
        try {
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $script:AllowGateway -PrefixLength $script:AllowPrefixLength -ErrorAction Stop | Out-Null
        } catch {
            throw "host gateway $($script:AllowGateway) is not assigned on $alias, and this token cannot add it: $($_.Exception.Message)"
        }
    }
    $nat = Get-NetNat -Name $script:AllowSwitch -ErrorAction SilentlyContinue
    if (-not $nat) {
        New-NetNat -Name $script:AllowSwitch -InternalIPInterfaceAddressPrefix $script:AllowPrefix | Out-Null
    } elseif ($nat.InternalIPInterfaceAddressPrefix -ne $script:AllowPrefix) {
        throw "NAT $($script:AllowSwitch) already exists for $($nat.InternalIPInterfaceAddressPrefix)"
    }
    Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Forwarding Enabled | Out-Null
}

function Set-AllowAcls([string]$name, [string[]]$destIPs, [string[]]$dnsIPs) {
    # The switch stores each extended ACL by weight. A repeated weight fails VM
    # start with 0x800700B7. Higher weight is checked first, so allows sit above the denies.
    Get-VMNetworkAdapterExtendedAcl -VMName $name -ErrorAction SilentlyContinue | Remove-VMNetworkAdapterExtendedAcl | Out-Null
    $weight = 1000
    foreach ($ip in $destIPs) {
        Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Allow -Direction Outbound -Protocol TCP -RemoteIPAddress $ip -RemotePort '443' -Weight $weight -Stateful $true -IdleSessionTimeout 3600 | Out-Null
        $weight--
    }
    foreach ($ip in $dnsIPs) {
        Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Allow -Direction Outbound -Protocol UDP -RemoteIPAddress $ip -RemotePort '53' -Weight $weight -Stateful $true -IdleSessionTimeout 3600 | Out-Null
        $weight--
        Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Allow -Direction Outbound -Protocol TCP -RemoteIPAddress $ip -RemotePort '53' -Weight $weight -Stateful $true -IdleSessionTimeout 3600 | Out-Null
        $weight--
    }
    if ($weight -le 2) { throw 'too many allow rules to assign unique ACL weights' }
    Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Deny -Direction Inbound -Weight 1 | Out-Null
    Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Deny -Direction Outbound -Weight 2 | Out-Null
}

function Add-AllowHostIPs([string]$name, [string[]]$ips) {
    $used = @{}
    foreach ($acl in @(Get-VMNetworkAdapterExtendedAcl -VMName $name -ErrorAction SilentlyContinue)) {
        $used[[int]$acl.Weight] = $true
    }
    $weight = 3
    foreach ($ip in $ips) {
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        $have = @(Get-VMNetworkAdapterExtendedAcl -VMName $name -ErrorAction SilentlyContinue | Where-Object {
            $_.Direction.ToString() -eq 'Outbound' -and ($_.Protocol.ToString() -eq 'TCP' -or $_.Protocol.ToString() -eq '6') -and [string]$_.RemotePort -eq '443' -and $_.RemoteIPAddress -eq $ip
        })
        if ($have.Count -gt 0) { continue }
        while ($used.ContainsKey($weight)) { $weight++ }
        if ($weight -gt 65500) { throw 'too many allow rules to assign unique ACL weights' }
        Add-VMNetworkAdapterExtendedAcl -VMName $name -Action Allow -Direction Outbound -Protocol TCP -RemoteIPAddress $ip -RemotePort '443' -Weight $weight -Stateful $true -IdleSessionTimeout 3600 | Out-Null
        $used[$weight] = $true
        $weight++
    }
}

function Get-AllowDnsStateDir {
    $dir = Join-Path $env:LOCALAPPDATA 'hyper-v-sandbox'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

function Start-AllowDns {
    $exe = $env:SBX_EXE
    if ([string]::IsNullOrWhiteSpace($exe) -or -not (Test-Path -LiteralPath $exe)) {
        throw 'allow DNS proxy requires the hatch executable path'
    }
    foreach ($spec in @(
        @{ Name = 'sbx-allow-dns-udp'; Protocol = 'UDP' },
        @{ Name = 'sbx-allow-dns-tcp'; Protocol = 'TCP' }
    )) {
        if (-not (Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $spec.Name -DisplayName $spec.Name -Direction Inbound -Action Allow -Protocol $spec.Protocol -LocalPort 53 -InterfaceAlias $script:AllowAlias -Profile Any | Out-Null
        }
    }
    $pidFile = Join-Path (Get-AllowDnsStateDir) 'allow-dns.pid'
    if (Test-Path -LiteralPath $pidFile) {
        $existingId = 0
        [void][int]::TryParse((Get-Content -Raw -LiteralPath $pidFile).Trim(), [ref]$existingId)
        $running = Get-Process -Id $existingId -ErrorAction SilentlyContinue
        if ($running -and -not $running.HasExited) {
            $ep = Get-NetUDPEndpoint -OwningProcess $existingId -LocalPort 53 -ErrorAction SilentlyContinue
            if ($ep) { return }
        }
    }
    # No console, and no inherited output handles. The proxy outlives the
    # PowerShell that starts it. An inherited stdout pipe keeps that command
    # from finishing, so the worker never gets past boot.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = 'allow-dns'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    if (-not $proc) { throw 'allow DNS proxy did not start' }
    $proc.BeginOutputReadLine() | Out-Null
    $proc.BeginErrorReadLine() | Out-Null
    $deadline = (Get-Date).AddSeconds(15)
    do {
        if ($proc.HasExited) { throw "allow DNS proxy exited ($($proc.ExitCode)). See allow-dns.log in $env:LOCALAPPDATA\hyper-v-sandbox." }
        $ep = Get-NetUDPEndpoint -OwningProcess $proc.Id -LocalPort 53 -ErrorAction SilentlyContinue
        if ($ep) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'allow DNS proxy did not listen on port 53'
}

function Stop-AllowDns {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { return }
    $pidFile = Join-Path (Get-AllowDnsStateDir) 'allow-dns.pid'
    if (Test-Path -LiteralPath $pidFile) {
        $procId = 0
        [void][int]::TryParse((Get-Content -Raw -LiteralPath $pidFile).Trim(), [ref]$procId)
        if ($procId -gt 0) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }
    # Leave sbx-allow-dns-udp and sbx-allow-dns-tcp. Creating those rules
    # returns "Access is denied" for a Hyper-V Administrators token.
}

function Remove-AllowSwitchIfIdle {
    # Leave the host switch, NAT, and 172.29.248.1 gateway in place. A Hyper-V
    # Administrators token can attach clones to them, but Windows only lets a
    # full administrator token assign that gateway address. Removing it with
    # the last clone makes the next start fail with "Access is denied."
}

function Unregister-AllowVM([string]$name) {
    if ([string]::IsNullOrWhiteSpace($env:SBX_ROOT)) { return }
    Invoke-AllowLocked {
        $path = Get-AllowTablePath
        if (Test-Path -LiteralPath $path) {
            $table = Read-AllowTable
            Update-AllowHosts $table
            if ($name -and $table.hosts.PSObject.Properties[$name]) {
                $table.hosts.PSObject.Properties.Remove($name)
            }
            Save-AllowTable $table
            if (@($table.hosts.PSObject.Properties).Count -eq 0) { Stop-AllowDns }
        }
        Remove-AllowSwitchIfIdle
    } | Out-Null
}

function Initialize-AllowNetwork([string]$name, [string]$allowHost) {
    if ([string]::IsNullOrWhiteSpace($allowHost)) { throw '--network allow requires --allow-host' }
    $ips = @(Resolve-AllowIPv4 $allowHost.Trim())
    $dns = @($script:AllowGateway)
    return Invoke-AllowLocked {
        Ensure-AllowSwitch | Out-Null
        $guestIP = Add-AllowAddress $name $allowHost.Trim()
        if (-not @(Get-VMNetworkAdapter -VMName $name)) {
            Add-VMNetworkAdapter -VMName $name | Out-Null
        }
        $null = Get-VMNetworkAdapter -VMName $name | Connect-VMNetworkAdapter -SwitchName $script:AllowSwitch
        Set-AllowAcls $name $ips $dns
        foreach ($svcName in @('Heartbeat', 'Key-Value Pair Exchange', 'Guest Service Interface')) {
            Enable-VMIntegrationService -VMName $name -Name $svcName -ErrorAction SilentlyContinue | Out-Null
        }
        # Inside the lock so two clones booting at once do not both start a
        # proxy; the second would fail to bind port 53 and fail its boot.
        Start-AllowDns | Out-Null
        return @{
            host    = $allowHost.Trim()
            ips     = @($ips)
            dns     = @($dns)
            guestIP = [string]$guestIP
            gateway = $script:AllowGateway
            error   = ''
        }
    }
}

function Set-GuestStaticIPv4([string]$name, [string]$ip, [string]$mask, [string]$gateway, [string[]]$dns) {
    $ns = 'root\virtualization\v2'
    $safe = $name.Replace("'", "''")
    $vm = Get-WmiObject -Namespace $ns -Class Msvm_ComputerSystem -Filter "ElementName='$safe'"
    if (-not $vm) { throw "VM not found: $name" }
    $settings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
    $port = $settings.GetRelated('Msvm_SyntheticEthernetPortSettingData') | Select-Object -First 1
    if (-not $port) { throw "VM $name has no synthetic network adapter" }
    $cfg = $port.GetRelated('Msvm_GuestNetworkAdapterConfiguration') | Select-Object -First 1
    if (-not $cfg) { throw "VM $name has no guest network configuration" }
    $cfg.DHCPEnabled = $false
    $cfg.IPAddresses = [string[]]@($ip)
    $cfg.Subnets = [string[]]@($mask)
    $cfg.DefaultGateways = [string[]]@($gateway)
    $cfg.DNSServers = [string[]]@($dns)
    $cfg.ProtocolIFType = 4096
    $svc = Get-WmiObject -Namespace $ns -Class Msvm_VirtualSystemManagementService
    $result = $svc.SetGuestNetworkAdapterConfiguration($vm, $cfg.GetText(1))
    if ($result.ReturnValue -eq 0) { return }
    if ($result.ReturnValue -ne 4096) { throw "guest network configuration failed: $($result.ReturnValue)" }
    $job = [wmi]$result.Job
    $spins = 0
    while (($job.JobState -eq 3 -or $job.JobState -eq 4) -and $spins -lt 200) {
        Start-Sleep -Milliseconds 300
        $job = [wmi]$job.__PATH
        $spins++
    }
    if ($job.JobState -ne 7) {
        $why = [string]$job.ErrorDescription
        if ([string]::IsNullOrWhiteSpace($why)) { $why = "job state $($job.JobState)" }
        throw "guest network configuration failed: $why"
    }
}

function Set-AllowGuestAddress([string]$name, $plan) {
    $deadline = (Get-Date).AddSeconds(90)
    $last = 'guest network service did not answer'
    while ((Get-Date) -lt $deadline) {
        try {
            Set-GuestStaticIPv4 $name $plan.guestIP '255.255.255.0' $plan.gateway @($plan.dns)
            $until = (Get-Date).AddSeconds(20)
            if ($until -gt $deadline) { $until = $deadline }
            while ((Get-Date) -lt $until) {
                $have = @((Get-VMNetworkAdapter -VMName $name).IPAddresses)
                if ($have -contains $plan.guestIP) { return }
                Start-Sleep -Seconds 1
            }
            $last = "guest did not report $($plan.guestIP)"
        } catch {
            $last = $_.Exception.Message
            Start-Sleep -Seconds 2
        }
    }
    throw $last
}

function Set-GuestIdentity([string]$name) {
    if ([string]::IsNullOrWhiteSpace($env:SBX_BIOS_GUID)) { return }
    $guid = $env:SBX_BIOS_GUID.Trim()
    $guid = '{' + $guid.Trim('{}') + '}'
    $vmms = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$name'"
    $settings = $vm.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
    # A full settings dump is rejected. Send only the identity fields.
    $patch = ([wmiclass]'root\virtualization\v2:Msvm_VirtualSystemSettingData').CreateInstance()
    $patch.InstanceID = $settings.InstanceID
    $patch.BIOSGUID = $guid
    if ($env:SBX_BIOS_SERIAL) { $patch.BIOSSerialNumber = $env:SBX_BIOS_SERIAL }
    if ($env:SBX_BOARD_SERIAL) { $patch.BaseBoardSerialNumber = $env:SBX_BOARD_SERIAL }
    if ($env:SBX_CHASSIS_SERIAL) { $patch.ChassisSerialNumber = $env:SBX_CHASSIS_SERIAL }
    if ($env:SBX_CHASSIS_ASSET) { $patch.ChassisAssetTag = $env:SBX_CHASSIS_ASSET }
    $result = $vmms.ModifySystemSettings($patch.GetText(1))
    if ($result.ReturnValue -eq 4096) {
        $job = [wmi]$result.Job
        while ($job.JobState -eq 4) {
            Start-Sleep -Milliseconds 200
            $job = [wmi]$job.__PATH
        }
        if ($job.JobState -ne 7) { throw "firmware identity update failed: $($job.ErrorDescription)" }
    } elseif ($result.ReturnValue -ne 0) {
        throw "firmware identity update failed: $($result.ReturnValue)"
    }
}

function Start-GuestProgram {
    # WMI creates the process outside the PowerShell Direct session, so it keeps
    # running after Invoke-Command returns. The command line arrives as a
    # parameter because it can be kilobytes long.
    $ProgressPreference = 'SilentlyContinue'
    Require-Name $env:SBX_NAME
    $name = $env:SBX_NAME
    $exe = $env:SBX_GUEST_EXE
    if ([string]::IsNullOrWhiteSpace($exe)) { throw 'guest program path is empty' }
    if ([string]::IsNullOrWhiteSpace($env:SBX_CMDLINE_FILE)) { throw 'command line file is empty' }
    if (-not (Test-Path -LiteralPath $env:SBX_CMDLINE_FILE)) { throw "command line file not found: $($env:SBX_CMDLINE_FILE)" }
    $user = $env:SBX_GUEST_USER
    if ([string]::IsNullOrWhiteSpace($user)) { throw 'guest user is empty' }
    $commandLine = [System.IO.File]::ReadAllText($env:SBX_CMDLINE_FILE, [System.Text.UTF8Encoding]::new($false))
    if ([string]::IsNullOrEmpty($commandLine)) { throw 'command line is empty' }
    $workDir = [string]$env:SBX_WORK_DIR
    Import-Module Hyper-V
    $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
    if (-not $vm) { throw "VM not found: $name" }
    if ($vm.State -ne 'Running') { throw "VM $name is $($vm.State); start it before running a program" }
    $secure = ConvertTo-SecureString -String $env:SBX_GUEST_PASSWORD -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($user, $secure)
    $timeout = 180
    if ($env:SBX_RUN_TIMEOUT) { $timeout = [int]$env:SBX_RUN_TIMEOUT }
    if ($timeout -le 0) { $timeout = 180 }
    $guestIP = [string]$env:SBX_GUEST_IP
    $guestPrefix = 24
    if ($env:SBX_GUEST_PREFIX) { $guestPrefix = [int]$env:SBX_GUEST_PREFIX }
    $guestGW = [string]$env:SBX_GUEST_GATEWAY
    $guestDNS = [string]$env:SBX_GUEST_DNS
    if (-not [string]::IsNullOrWhiteSpace($guestIP)) {
        if ([string]::IsNullOrWhiteSpace($guestGW) -or [string]::IsNullOrWhiteSpace($guestDNS)) {
            throw 'guest network settings are incomplete'
        }
        if ($guestPrefix -ne 24) { throw "guest prefix $guestPrefix is not supported" }
    }
    $deadline = (Get-Date).AddSeconds($timeout)
    $last = 'guest did not accept a command'
    $swCmd = [System.Diagnostics.Stopwatch]::StartNew()
    $attempts = 0
    while ($true) {
        $attempts++
        try {
            $started = Invoke-Command -VMName $name -Credential $cred -ScriptBlock {
                param($commandLine, $workDir, $guestIP, $guestPrefix, $guestGW, $guestDNS)
                $ErrorActionPreference = 'Stop'
                $netMs = 0
                if (-not [string]::IsNullOrWhiteSpace($guestIP)) {
                    $netSw = [System.Diagnostics.Stopwatch]::StartNew()
                    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } | Select-Object -First 1
                    if (-not $adapter) { throw 'guest has no connected network adapter' }
                    $idx = $adapter.ifIndex
                    $have = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $guestIP })
                    if ($have.Count -eq 0) {
                        try {
                            New-NetIPAddress -InterfaceIndex $idx -IPAddress $guestIP -PrefixLength $guestPrefix -DefaultGateway $guestGW | Out-Null
                        } catch {
                            New-NetIPAddress -InterfaceIndex $idx -IPAddress $guestIP -PrefixLength $guestPrefix | Out-Null
                            $route = @(Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $guestGW })
                            if ($route.Count -eq 0) {
                                New-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -NextHop $guestGW | Out-Null
                            }
                        }
                    }
                    Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -ne $guestIP } |
                        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $guestDNS
                    $netSw.Stop()
                    $netMs = [int]$netSw.ElapsedMilliseconds
                }
                $create = @{ CommandLine = $commandLine }
                if (-not [string]::IsNullOrWhiteSpace($workDir)) {
                    $create.CurrentDirectory = $workDir
                }
                $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments $create
                if ($null -eq $created) { throw 'Win32_Process.Create returned nothing' }
                $code = [int]$created.ReturnValue
                if ($code -ne 0) {
                    $why = switch ($code) {
                        2 { 'access denied' }
                        3 { 'insufficient privilege' }
                        8 { 'unknown failure' }
                        9 { 'file not found' }
                        21 { 'invalid parameter' }
                        default { "code $code" }
                    }
                    throw "Win32_Process.Create failed: $why"
                }
                $createdPid = [int]$created.ProcessId
                if ($createdPid -le 0) { throw 'Win32_Process.Create did not return a process id' }
                return @{ pid = $createdPid; net_ms = $netMs }
            } -ArgumentList $commandLine, $workDir, $guestIP, $guestPrefix, $guestGW, $guestDNS
            $swCmd.Stop()
            return @{
                pid      = [int]$started.pid
                net_ms   = [int]$started.net_ms
                attempts = $attempts
                cmd_ms   = [int]$swCmd.ElapsedMilliseconds
            }
        } catch {
            $last = $_.Exception.Message
            if ($last -match 'Win32_Process|credential is invalid|bad password|unknown user name|logon failure|password is incorrect') {
                throw $last
            }
            if ((Get-Date) -ge $deadline) {
                throw "guest did not accept a command within ${timeout}s: $last"
            }
            Start-Sleep -Milliseconds 500
        }
    }
}

function Assert-ThrowawayDisks($paths) {
    foreach ($disk in @($paths)) {
        if ([string]::IsNullOrWhiteSpace($disk)) { continue }
        if (-not (Test-Path -LiteralPath $disk)) { continue }
        Assert-UnderRoot $disk
        $vhd = Get-VHD -Path $disk
        if ($vhd.VhdType -ne 'Differencing' -or [string]::IsNullOrWhiteSpace($vhd.ParentPath)) {
            throw "refusing to delete $disk because it is not a differencing disk"
        }
        if ($vhd.Attached) { throw "refusing to delete $disk because it is still attached" }
    }
}

function Get-VhdChain([string]$path) {
    $chain = @()
    $seen = @{}
    $current = $path
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $key = $current.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { break }
        $seen[$key] = $true
        if (-not (Test-Path -LiteralPath $current)) { break }
        $chain += $current
        $current = [string](Get-VHD -Path $current).ParentPath
    }
    return $chain
}

function Get-AceSid($ace) {
    $id = $ace.IdentityReference
    if ($id -is [System.Security.Principal.SecurityIdentifier]) { return $id.Value }
    try { return $id.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return [string]$id }
}

function Test-CanChangeVhdAcl($acl) {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    try {
        if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -eq $me) { return $true }
    } catch { }
    $want = @($me, 'S-1-5-32-578')
    $change = [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions
    $full = [int][System.Security.AccessControl.FileSystemRights]::FullControl
    foreach ($ace in @($acl.Access)) {
        if ($ace.AccessControlType.ToString() -ne 'Allow') { continue }
        if ($want -notcontains (Get-AceSid $ace)) { continue }
        $rights = [int]$ace.FileSystemRights
        if (($rights -band $full) -eq $full -or ($rights -band $change) -eq $change) { return $true }
    }
    return $false
}

function Add-VhdSecurityAce([string]$path) {
    $item = Get-Item -LiteralPath $path
    $ro = $item.IsReadOnly
    if ($ro) { $item.IsReadOnly = $false }
    try {
        $acl = Get-Acl -LiteralPath $path
        $hv = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-578'
        $vms = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-83-0'
        $change = [System.Security.AccessControl.FileSystemRights]'ReadAndExecute, ChangePermissions, WriteAttributes'
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($hv, $change, 'Allow')))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($vms, 'ReadAndExecute', 'Allow')))
        Set-Acl -LiteralPath $path -AclObject $acl
    } finally {
        if ($ro) { (Get-Item -LiteralPath $path).IsReadOnly = $true }
    }
}

function Ensure-VhdChainSecurity([string]$parent) {
    foreach ($path in @(Get-VhdChain $parent)) {
        if (Test-CanChangeVhdAcl (Get-Acl -LiteralPath $path)) { continue }
        try {
            Add-VhdSecurityAce $path
        } catch {
            $owner = (Get-Acl -LiteralPath $path).Owner
            throw "Hyper-V Administrators cannot update permissions on $path (owner $owner)."
        }
    }
}

# An elevated hv up owns the disk as Administrators. A normal Hyper-V admin
# token has that group deny-only and Users can only read the file, so down
# removes the VM and then fails to delete it. Grant the group access while
# the creating process can still change the ACL.
function Grant-HyperVAdminDelete([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-578'
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'Modify', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
}

function Remove-DifferencingDisk([string]$disk) {
    if (-not (Test-Path -LiteralPath $disk)) { return }
    Assert-ThrowawayDisks @($disk)
    $last = 'delete failed'
    foreach ($wait in @(0, 300, 600, 1000, 1500)) {
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
        try {
            Remove-Item -LiteralPath $disk -Force -ErrorAction Stop
            return
        } catch {
            $last = $_.Exception.Message
            if ($last -match 'denied') { break }
            if ($last -notmatch 'being used by another process|cannot access the file') { throw }
        }
    }
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated -or $last -notmatch 'denied') {
        throw "could not delete ${disk}: $last"
    }
    $script = Join-Path $env:TEMP ("sbx-del-" + [guid]::NewGuid().ToString('n') + ".ps1")
    $literal = $disk.Replace("'", "''")
    Set-Content -LiteralPath $script -Value "Remove-Item -LiteralPath '$literal' -Force" -Encoding ASCII
    try {
        [Console]::Error.WriteLine("Administrator approval is required to delete $disk")
        $null = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script) -Verb RunAs -Wait -PassThru
    } catch {
        throw "could not delete ${disk}: $last. Approve the administrator prompt, or rerun this command in an elevated terminal."
    } finally {
        Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $disk) {
        throw "could not delete ${disk}: $last. Approve the administrator prompt, or rerun this command in an elevated terminal."
    }
}

try {
    switch ($env:SBX_ACTION) {
        'doctor' {
            $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $vmms = Get-Service vmms -ErrorAction SilentlyContinue
            $vmcompute = Get-Service vmcompute -ErrorAction SilentlyContinue
            $module = @(Get-Module -ListAvailable Hyper-V | Select-Object -First 1)
            $canHV = $false
            $hvError = ''
            $switchNames = @()
            try {
                Import-Module Hyper-V -ErrorAction Stop
                Get-VM | Out-Null
                $canHV = $true
                $switchNames = @(Get-VMSwitch | ForEach-Object { $_.Name })
            } catch {
                $hvError = $_.Exception.Message
            }
            $vmmsState = 'missing'
            if ($vmms) { $vmmsState = $vmms.Status.ToString() }
            $computeState = 'missing'
            if ($vmcompute) { $computeState = $vmcompute.Status.ToString() }
            Emit @{
                elevated       = [bool]$elevated
                vmms           = $vmmsState
                vmcompute      = $computeState
                hypervModule   = ($module.Count -gt 0)
                hypervAccess   = [bool]$canHV
                hypervError    = $hvError
                windowsSandbox = (Test-Path -LiteralPath "$env:SystemRoot\System32\WindowsSandbox.exe")
                vmconnect      = (Test-Path -LiteralPath "$env:SystemRoot\System32\vmconnect.exe")
                switches       = @($switchNames)
            }
        }

        'list' {
            Import-Module Hyper-V
            $vms = @(Get-VM | Where-Object {
                $_.Notes -eq 'hyper-v-sandbox throwaway' -or $_.Notes -eq 'hyper-v-sandbox parent-builder'
            })
            $items = @()
            foreach ($vm in $vms) {
                $disk = ''
                $drives = @($vm.HardDrives)
                if ($drives.Count -gt 0) { $disk = [string]$drives[0].Path }
                $items += @{
                    name     = [string]$vm.Name
                    state    = $vm.State.ToString()
                    memoryMB = [int]($vm.MemoryStartup / 1MB)
                    cpus     = [int]$vm.ProcessorCount
                    disk     = $disk
                    notes    = [string]$vm.Notes
                }
            }
            Emit @{ instances = @($items) }
        }

        'up' {
            Import-Module Hyper-V
            $name = $env:SBX_NAME
            $parent = $env:SBX_PARENT
            $diff = $env:SBX_DIFF
            $memMB = [int64]$env:SBX_MEM_MB
            $cpus = [int]$env:SBX_CPUS
            $network = $env:SBX_NETWORK
            $generation = [int]$env:SBX_GENERATION
            Require-Name $name
            if (-not $parent) { throw 'parent VHD is empty' }
            if (-not (Test-Path -LiteralPath $parent)) { throw "parent VHD not found: $parent" }
            if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw "VM already exists: $name" }
            if ($generation -ne 1 -and $generation -ne 2) { throw 'generation must be 1 or 2' }

            $null = Get-VHD -Path $parent
            $active = @(Get-VM | Where-Object {
                @($_.HardDrives | Where-Object { $_.Path -eq $parent }).Count -gt 0
            })
            if ($active.Count -gt 0) {
                $names = ($active | ForEach-Object { $_.Name }) -join ', '
                throw "parent VHD is the active disk of VM $names. Booting that VM writes the parent and breaks every differencing clone. Checkpoint that VM first, or choose the frozen base disk those checkpoints already use."
            }

            $dir = Split-Path -Parent $diff
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            if (Test-Path -LiteralPath $diff) { throw "differencing disk already exists: $diff" }
            # Hyper-V adds this VM's identity to every disk in the chain at start.
            # Hyper-V Administrators can do that when the group is allowed to
            # change the permissions. An elevated creator would otherwise leave
            # the disk owned by Administrators, and a later normal start fails.
            Ensure-VhdChainSecurity $parent

            $timings = @{}
            $sw = [Diagnostics.Stopwatch]::StartNew()
            New-VHD -Path $diff -ParentPath $parent -Differencing | Out-Null
            Grant-HyperVAdminDelete $diff
            Add-VhdSecurityAce $diff
            $sw.Stop()
            $timings['differencing_disk_ms'] = [int]$sw.ElapsedMilliseconds

            try {
                $sw.Restart()
                New-VM -Name $name -Generation $generation -MemoryStartupBytes ($memMB * 1MB) -VHDPath $diff | Out-Null
                Set-VMProcessor -VMName $name -Count $cpus | Out-Null
                $minMB = [int64]1536
                if ($memMB -lt $minMB) { $minMB = $memMB }
                Set-VMMemory -VMName $name -DynamicMemoryEnabled $true -MinimumBytes ($minMB * 1MB) -StartupBytes ($memMB * 1MB) -MaximumBytes ($memMB * 1MB) -Buffer 5 | Out-Null
                Set-VM -Name $name -AutomaticCheckpointsEnabled $false | Out-Null
                Set-VM -Name $name -CheckpointType Disabled -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -Notes 'hyper-v-sandbox throwaway' | Out-Null
                if ($generation -eq 2) {
                    Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows | Out-Null
                    $hdd = Get-VMHardDiskDrive -VMName $name | Select-Object -First 1
                    if ($hdd) { Set-VMFirmware -VMName $name -FirstBootDevice $hdd | Out-Null }
                }
                Set-GuestIdentity $name
                Set-SandboxNetwork $name $network
                $sw.Stop()
                $timings['create_vm_ms'] = [int]$sw.ElapsedMilliseconds

                $sw.Restart()
                Start-VM -Name $name
                $sw.Stop()
                $timings['start_vm_ms'] = [int]$sw.ElapsedMilliseconds
            } catch {
                $createErr = $_
                $existing = Get-VM -Name $name -ErrorAction SilentlyContinue
                if ($existing) {
                    if ($existing.State -ne 'Off') {
                        Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue
                    }
                    Remove-VM -Name $name -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path -LiteralPath $diff) {
                    Remove-Item -LiteralPath $diff -Force -ErrorAction SilentlyContinue
                }
                try { Unregister-AllowVM $name } catch { }
                $why = [string]$createErr.Exception.Message
                $line = ([string]$createErr.InvocationInfo.Line).Trim()
                if ($line -and $why -notlike "*$line*") { throw "$why ($line)" }
                throw $createErr
            }

            $heartbeat = ''
            $wantReady = ($env:SBX_WAIT_READY -eq '1') -or ($network -eq 'allow')
            if ($wantReady) {
                $readySec = [int]$env:SBX_READY_TIMEOUT
                if ($readySec -le 0) { $readySec = 180 }
                try {
                    $sw.Restart()
                    Wait-VM -Name $name -For Heartbeat -Timeout $readySec
                    $sw.Stop()
                    $timings['heartbeat_ms'] = [int]$sw.ElapsedMilliseconds
                    $heartbeat = 'ok'
                } catch {
                    $sw.Stop()
                    $timings['heartbeat_ms'] = [int]$sw.ElapsedMilliseconds
                    $heartbeat = $_.Exception.Message
                }
            }
            if ($script:AllowPlan) {
                if ($heartbeat -ne 'ok') {
                    $why = $heartbeat
                    if ([string]::IsNullOrWhiteSpace($why)) { $why = 'heartbeat was not requested' }
                    $script:AllowPlan.error = "guest heartbeat was not ready: $why. The VM is still running. hatch hv down $name removes it. Raise --ready-timeout on a first boot."
                } elseif ($env:SBX_DEFER_GUEST_NET -eq '1') {
                    # The address is set in the PowerShell Direct session that starts the guest program.
                } else {
                    try {
                        $sw.Restart()
                        Set-AllowGuestAddress $name $script:AllowPlan
                        $sw.Stop()
                        $timings['guest_net_ms'] = [int]$sw.ElapsedMilliseconds
                    } catch {
                        $sw.Stop()
                        $timings['guest_net_ms'] = [int]$sw.ElapsedMilliseconds
                        $script:AllowPlan.error = "$($_.Exception.Message). The VM is still running. hatch hv down $name removes it."
                    }
                }
            }

            $vm = Get-VM -Name $name
            $result = @{
                name           = $name
                id             = $vm.Id.Guid
                state          = $vm.State.ToString()
                parent         = $parent
                disk           = $diff
                memoryMB       = [int]$memMB
                cpus           = $cpus
                network        = $network
                generation     = $generation
                parentReadOnly = [bool](Get-Item -LiteralPath $parent).IsReadOnly
                heartbeat      = $heartbeat
                timings        = $timings
            }
            if ($script:AllowPlan) {
                $result.allowHost = [string]$script:AllowPlan.host
                $result.allowIPs = @($script:AllowPlan.ips)
                $result.dns = @($script:AllowPlan.dns)
                $result.guestIP = [string]$script:AllowPlan.guestIP
                $result.gateway = [string]$script:AllowPlan.gateway
                $result.allowError = [string]$script:AllowPlan.error
            }
            Emit $result
        }

        'down' {
            Import-Module Hyper-V
            if ($env:SBX_ALL -eq '1') {
                $targets = @(Get-VM | Where-Object { $_.Notes -eq 'hyper-v-sandbox throwaway' })
            } else {
                Require-Name $env:SBX_NAME
                $one = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
                if (-not $one) {
                    $orphan = Join-Path $env:SBX_ROOT ("disks\" + $env:SBX_NAME + ".vhdx")
                    if (Test-Path -LiteralPath $orphan) {
                        Remove-DifferencingDisk $orphan
                        try { Unregister-AllowVM $env:SBX_NAME } catch { }
                        Emit @{ removed = @(@{ name = $env:SBX_NAME; disks = @($orphan) }) }
                        return
                    }
                    throw "VM not found: $($env:SBX_NAME)"
                }
                $targets = @($one)
            }
            $removed = @()
            foreach ($vm in @($targets)) {
                if ($vm.Notes -ne 'hyper-v-sandbox throwaway') {
                    throw "VM $($vm.Name) is not a hyper-v-sandbox throwaway. Refusing to delete it."
                }
                if ($vm.State -ne 'Off') {
                    Stop-VM -Name $vm.Name -TurnOff -Force
                    $vm = Get-VM -Name $vm.Name
                }
                $cps = @(Get-VMCheckpoint -VMName $vm.Name -ErrorAction SilentlyContinue)
                if ($cps.Count -gt 0) {
                    $cps | Remove-VMCheckpoint -Confirm:$false
                    $vm = Get-VM -Name $vm.Name
                }
                $paths = @()
                foreach ($drive in @($vm.HardDrives)) {
                    if ($drive.Path) { $paths += [string]$drive.Path }
                }
                Assert-ThrowawayDisks $paths
                Remove-VM -Name $vm.Name -Force
                try { Unregister-AllowVM ([string]$vm.Name) } catch { }
                $deleted = @()
                foreach ($disk in @($paths)) {
                    if ([string]::IsNullOrWhiteSpace($disk)) { continue }
                    if (Test-Path -LiteralPath $disk) {
                        Remove-DifferencingDisk $disk
                        $deleted += $disk
                    }
                }
                $removed += @{ name = [string]$vm.Name; disks = @($deleted) }
            }
            Emit @{ removed = @($removed) }
        }

        'bootstrap' {
            Import-Module Hyper-V
            $name = $env:SBX_NAME
            $vhd = $env:SBX_PARENT
            $iso = $env:SBX_ISO
            $memMB = [int64]$env:SBX_MEM_MB
            $cpus = [int]$env:SBX_CPUS
            $sizeGB = [int64]$env:SBX_SIZE_GB
            $network = $env:SBX_NETWORK
            Require-Name $name
            if (-not $iso -or -not (Test-Path -LiteralPath $iso)) { throw "ISO not found: $iso" }
            if (Test-Path -LiteralPath $vhd) { throw "refusing to overwrite existing VHD: $vhd" }
            if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw "VM already exists: $name" }
            if ($sizeGB -lt 20) { throw 'size must be at least 20 GB' }

            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $vhd) | Out-Null
            New-VHD -Path $vhd -SizeBytes ($sizeGB * 1GB) -Dynamic | Out-Null
            try {
                New-VM -Name $name -Generation 2 -MemoryStartupBytes ($memMB * 1MB) -VHDPath $vhd | Out-Null
                Set-VMProcessor -VMName $name -Count $cpus | Out-Null
                Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes ($memMB * 1MB) | Out-Null
                Set-VM -Name $name -AutomaticCheckpointsEnabled $false | Out-Null
                Set-VM -Name $name -CheckpointType Disabled -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -Notes 'hyper-v-sandbox parent-builder' | Out-Null
                Add-VMDvdDrive -VMName $name -Path $iso | Out-Null
                $dvd = Get-VMDvdDrive -VMName $name | Select-Object -First 1
                Set-VMFirmware -VMName $name -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows | Out-Null
                Set-VMFirmware -VMName $name -FirstBootDevice $dvd | Out-Null
                Set-SandboxNetwork $name $network
                Start-VM -Name $name
            } catch {
                $bootErr = $_
                $existing = Get-VM -Name $name -ErrorAction SilentlyContinue
                if ($existing) {
                    if ($existing.State -ne 'Off') { Stop-VM -Name $name -TurnOff -Force -ErrorAction SilentlyContinue }
                    Remove-VM -Name $name -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path -LiteralPath $vhd) { Remove-Item -LiteralPath $vhd -Force -ErrorAction SilentlyContinue }
                throw $bootErr
            }
            Emit @{
                name  = $name
                vhd   = $vhd
                iso   = $iso
                state = (Get-VM -Name $name).State.ToString()
            }
        }

        'retire' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $vm = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
            if (-not $vm) { throw "VM not found: $($env:SBX_NAME)" }
            if ($vm.Notes -ne 'hyper-v-sandbox parent-builder') {
                throw "VM $($vm.Name) is not a parent-builder. Refusing to retire it."
            }
            if ($vm.State -ne 'Off') {
                throw "VM $($vm.Name) is $($vm.State). Inside the guest run: C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /mode:vm"
            }
            $drives = @($vm.HardDrives)
            if ($drives.Count -lt 1 -or [string]::IsNullOrWhiteSpace($drives[0].Path)) {
                throw 'builder VM has no VHD path'
            }
            $vhd = [string]$drives[0].Path
            $vhdInfo = Get-VHD -Path $vhd
            if ($vhdInfo.VhdType -eq 'Differencing') {
                throw "refusing to retire onto a differencing disk: $vhd"
            }
            Get-VMDvdDrive -VMName $vm.Name | Remove-VMDvdDrive
            Remove-VM -Name $vm.Name -Force
            Add-VhdSecurityAce $vhd
            $item = Get-Item -LiteralPath $vhd
            $item.IsReadOnly = $true
            Emit @{
                name     = $env:SBX_NAME
                parent   = $vhd
                readOnly = $true
            }
        }

        'seal' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $dest = $env:SBX_PARENT
            if (-not $dest) { throw 'destination VHD is empty' }
            if (Test-Path -LiteralPath $dest) { throw "refusing to overwrite $dest" }
            $vm = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
            if (-not $vm) { throw "VM not found: $($env:SBX_NAME)" }
            if ($vm.Notes -ne 'hyper-v-sandbox throwaway') {
                throw "VM $($vm.Name) is not a hyper-v-sandbox throwaway."
            }
            if ($vm.State -eq 'Running' -or $vm.State -eq 'Paused') {
                Stop-VM -Name $vm.Name -Force
                $vm = Get-VM -Name $vm.Name
            }
            if ($vm.State -ne 'Off') {
                throw "VM $($vm.Name) is $($vm.State). Seal needs a shut-down VM."
            }
            $cps = @(Get-VMCheckpoint -VMName $vm.Name -ErrorAction SilentlyContinue)
            if ($cps.Count -gt 0) {
                $cps | Remove-VMCheckpoint -Confirm:$false
                $vm = Get-VM -Name $vm.Name
            }
            $drives = @($vm.HardDrives)
            if ($drives.Count -lt 1 -or [string]::IsNullOrWhiteSpace($drives[0].Path)) { throw 'VM has no disk' }
            $disk = [string]$drives[0].Path
            Assert-UnderRoot $disk
            $vhdInfo = Get-VHD -Path $disk
            if ($vhdInfo.VhdType -ne 'Differencing') { throw "refusing to seal a non-differencing disk: $disk" }

            $cs = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$($vm.Name)'"
            $id = $cs | Get-CimAssociatedInstance -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
            $biosGuid = [string]$id.BIOSGUID
            $biosSerial = [string]$id.BIOSSerialNumber
            $boardSerial = [string]$id.BaseBoardSerialNumber
            $chassisSerial = [string]$id.ChassisSerialNumber
            $chassisAsset = [string]$id.ChassisAssetTag
            $mem = [int]($vm.MemoryStartup / 1MB)
            $cpus = [int]$vm.ProcessorCount

            $mount = Mount-VHD -Path $disk -Passthru
            try {
                $parts = @(Get-Disk -Number $mount.Number | Get-Partition)
                foreach ($part in $parts) {
                    if (-not $part.DriveLetter) {
                        try { Add-PartitionAccessPath -DiskNumber $mount.Number -PartitionNumber $part.PartitionNumber -AssignDriveLetter | Out-Null } catch {}
                    }
                }
                $parts = @(Get-Disk -Number $mount.Number | Get-Partition)
                $winLetter = ''
                $efiLetter = ''
                $winSize = [int64]0
                foreach ($part in $parts) {
                    if (-not $part.DriveLetter) { continue }
                    $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
                    if (-not $vol) { continue }
                    if ($vol.FileSystem -eq 'NTFS' -and $vol.Size -gt $winSize) {
                        $winSize = [int64]$vol.Size
                        $winLetter = [string]$part.DriveLetter
                    }
                    if ($vol.FileSystem -eq 'FAT32' -and -not $efiLetter) { $efiLetter = [string]$part.DriveLetter }
                }
                if (-not $winLetter -or -not (Test-Path -LiteralPath "${winLetter}:\Windows")) {
                    throw "Windows volume not found on $disk"
                }
                $hive = "${winLetter}:\Windows\System32\config\SYSTEM"
                & reg.exe load HKLM\SBXSOFT $hive | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "could not load the guest SYSTEM hive" }
                try {
                    & reg.exe add "HKLM\SBXSOFT\ControlSet001\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f | Out-Null
                } finally {
                    & reg.exe unload HKLM\SBXSOFT | Out-Null
                }
                if ($efiLetter) {
                    $store = "${efiLetter}:\EFI\Microsoft\Boot\BCD"
                    if (Test-Path -LiteralPath $store) {
                        & bcdedit.exe /store $store /timeout 0 | Out-Null
                        & bcdedit.exe /store $store /set '{default}' bootstatuspolicy ignoreallfailures | Out-Null
                        & bcdedit.exe /store $store /set '{default}' recoveryenabled No | Out-Null
                    }
                }
            } finally {
                Dismount-VHD -Path $disk
            }

            Remove-VM -Name $vm.Name -Force
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            Move-Item -LiteralPath $disk -Destination $dest
            Add-VhdSecurityAce $dest
            (Get-Item -LiteralPath $dest).IsReadOnly = $true
            Emit @{
                name          = $env:SBX_NAME
                parent        = $dest
                memoryMB      = $mem
                cpus          = $cpus
                biosGuid      = $biosGuid
                biosSerial    = $biosSerial
                boardSerial   = $boardSerial
                chassisSerial = $chassisSerial
                chassisAsset  = $chassisAsset
                readOnly      = $true
            }
        }

        'save' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $vm = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
            if (-not $vm) { throw "VM not found: $($env:SBX_NAME)" }
            if ($vm.Notes -ne 'hyper-v-sandbox throwaway') {
                throw "VM $($vm.Name) is not a hyper-v-sandbox throwaway."
            }
            if ($vm.State -ne 'Running') {
                throw "VM $($vm.Name) is $($vm.State). Save when the desktop is up and the VM is Running."
            }
            Set-VM -Name $vm.Name -CheckpointType Standard | Out-Null
            $old = @(Get-VMCheckpoint -VMName $vm.Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'ready' })
            if ($old.Count -gt 0) {
                $old | Remove-VMCheckpoint -Confirm:$false
            }
            Checkpoint-VM -Name $vm.Name -SnapshotName 'ready'
            $vm = Get-VM -Name $vm.Name
            Emit @{
                name       = [string]$vm.Name
                checkpoint = 'ready'
                state      = $vm.State.ToString()
                resumed    = $false
            }
        }

        'reset' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $vm = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
            if (-not $vm) { throw "VM not found: $($env:SBX_NAME)" }
            if ($vm.Notes -ne 'hyper-v-sandbox throwaway') {
                throw "VM $($vm.Name) is not a hyper-v-sandbox throwaway."
            }
            $ready = @(Get-VMCheckpoint -VMName $vm.Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'ready' })
            if ($ready.Count -lt 1) {
                throw "VM $($vm.Name) has no saved desktop. When the desktop is up, run: hatch hv save $($vm.Name)"
            }
            if ($vm.State -ne 'Off') {
                Stop-VM -Name $vm.Name -TurnOff -Force
            }
            Restore-VMCheckpoint -VMName $vm.Name -Name 'ready' -Confirm:$false
            $vm = Get-VM -Name $vm.Name
            $resumed = $vm.State.ToString() -eq 'Saved'
            if ($vm.State -eq 'Off' -or $vm.State -eq 'Saved') {
                Start-VM -Name $vm.Name
                $vm = Get-VM -Name $vm.Name
            }
            Emit @{
                name       = [string]$vm.Name
                checkpoint = 'ready'
                state      = $vm.State.ToString()
                resumed    = [bool]$resumed
            }
        }

        'adopt' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $dest = $env:SBX_PARENT
            if (-not $dest) { throw 'destination VHD is empty' }
            if (Test-Path -LiteralPath $dest) { throw "refusing to overwrite $dest" }
            $vm = Get-VM -Name $env:SBX_NAME -ErrorAction SilentlyContinue
            if (-not $vm) { throw "VM not found: $($env:SBX_NAME)" }
            if ($vm.Notes -ne 'hyper-v-sandbox throwaway') {
                throw "VM $($vm.Name) is not a hyper-v-sandbox throwaway."
            }
            if ($vm.State -ne 'Off') {
                throw "VM $($vm.Name) is $($vm.State). Inside the guest run shutdown /h so Windows saves the desktop and the VM turns off. Turning it off from Hyper-V discards that session."
            }
            $drives = @($vm.HardDrives)
            if ($drives.Count -lt 1 -or [string]::IsNullOrWhiteSpace($drives[0].Path)) {
                throw 'VM has no disk'
            }
            $disk = [string]$drives[0].Path
            Assert-UnderRoot $disk
            $vhdInfo = Get-VHD -Path $disk
            if ($vhdInfo.VhdType -ne 'Differencing') {
                throw "refusing to adopt a non-differencing disk: $disk"
            }

            $found = $false
            $mount = Mount-VHD -Path $disk -ReadOnly -Passthru
            try {
                $parts = @(Get-Disk -Number $mount.Number | Get-Partition | Where-Object { $_.DriveLetter })
                foreach ($part in $parts) {
                    $hiber = '{0}:\hiberfil.sys' -f $part.DriveLetter
                    if (Test-Path -LiteralPath $hiber) { $found = $true }
                }
            } finally {
                Dismount-VHD -Path $disk
            }
            if (-not $found) {
                throw "no hiberfil.sys on $disk. A normal Shut down does not save the desktop. Start the VM, sign in, and run: powercfg /hibernate on; shutdown /h"
            }

            $mem = [int]($vm.MemoryStartup / 1MB)
            $cpus = [int]$vm.ProcessorCount
            Remove-VM -Name $vm.Name -Force
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            Move-Item -LiteralPath $disk -Destination $dest
            Add-VhdSecurityAce $dest
            (Get-Item -LiteralPath $dest).IsReadOnly = $true
            Emit @{
                name     = $env:SBX_NAME
                parent   = $dest
                memoryMB = $mem
                cpus     = $cpus
                readOnly = $true
            }
        }

        'run' {
            $started = Start-GuestProgram
            Emit @{
                name    = [string]$env:SBX_NAME
                pid     = [int]$started.pid
                exe     = [string]$env:SBX_GUEST_EXE
                timings = @{
                    guest_cmd_ms       = [int]$started.cmd_ms
                    guest_net_ms       = [int]$started.net_ms
                    guest_cmd_attempts = [int]$started.attempts
                }
            }
        }

        'allow-acl' {
            Import-Module Hyper-V
            Require-Name $env:SBX_NAME
            $ips = @($env:SBX_ALLOW_IPS -split ',' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Add-AllowHostIPs $env:SBX_NAME $ips
            Emit @{ added = @($ips) }
        }

        default { throw "unknown action: $($env:SBX_ACTION)" }
    }
} catch {
    $msg = $_.Exception.Message -replace "(`r|`n)", ' '
    Write-Output ("ERR:" + $msg)
    exit 1
}
