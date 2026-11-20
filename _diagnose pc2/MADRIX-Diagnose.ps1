#Requires -Version 5.1
param([switch]$SelfTest)
<#
  MADRIX-Diagnose  (NUR LESEND)

  Sammelt in eine Textdatei:
    - System / MADRIX-Prozess
    - Netzwerkadapter, Routen, ARP-Tabelle, UDP-Statistik
    - Erreichbarkeit + Latenz der Art-Net-Knoten
    - ArtPollReply aller Knoten  -> welche Universen liegen auf welchem Port
    - Webseiten der Controller (PixLite / NEBULA) als Rohdatei
    - MADRIX-Konfigurationsordner (neueste Geraetedatei wird mitkopiert)

  Es wird NICHTS veraendert. Gesendet wird nur ein Standard-ArtPoll
  (das ist die normale Geraete-Erkennung, die MADRIX selbst staendig macht).
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$machine   = $env:COMPUTERNAME
$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$outFile   = Join-Path $scriptDir ("MADRIX-Diagnose_{0}_{1}.txt" -f $machine, $stamp)
$httpDir   = Join-Path $scriptDir ("MADRIX-Diagnose_{0}_{1}_http" -f $machine, $stamp)
New-Item -ItemType Directory -Path $httpDir -Force | Out-Null

$Nodes = @('10.3.96.10','10.3.96.13','10.3.96.14','10.3.96.15','10.3.96.20','10.3.96.21')

$sb = New-Object System.Text.StringBuilder
function W([string]$t) { [void]$sb.AppendLine($t) }
function P([string]$t) { Write-Host ("  " + $t) -ForegroundColor Gray }
function Section([string]$t) { W ""; W ("=" * 78); W ("## " + $t); W ("=" * 78) }
function TryBlock([string]$label, [scriptblock]$block) {
    try { $r = (& $block) 2>&1 | Out-String; W $r.TrimEnd() }
    catch { W ("[Fehler] " + $label + ": " + $_.Exception.Message) }
}

# Liest ein ArtPollReply-Paket (239 Bytes) und gibt ein Objekt zurueck
function Convert-ArtPollReply {
    param([byte[]]$Data)
    $d = $Data
    if ($d.Length -lt 207) { return $null }
    for ($i = 0; $i -lt 7; $i++) { if ($d[$i] -ne [byte]("Art-Net"[$i])) { return $null } }
    if ($d[7] -ne 0) { return $null }
    if (($d[8] + $d[9]*256) -ne 0x2100) { return $null }

    $ip = "{0}.{1}.{2}.{3}" -f $d[10],$d[11],$d[12],$d[13]
    $netSwitch = $d[18]
    $subSwitch = $d[19]
    $shortName = ([System.Text.Encoding]::ASCII.GetString($d, 26, 18)).Trim([char]0).Trim()
    $longName  = ([System.Text.Encoding]::ASCII.GetString($d, 44, 64)).Trim([char]0).Trim()
    $report    = ([System.Text.Encoding]::ASCII.GetString($d, 108, 64)).Trim([char]0).Trim()
    $numPorts  = ($d[172] * 256) + $d[173]
    $bindIdx   = $d[211]
    $mac       = ("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}" -f $d[201],$d[202],$d[203],$d[204],$d[205],$d[206])

    $ports = @()
    $good  = @()
    for ($p = 0; $p -lt 4; $p++) {
        $addr  = ($netSwitch * 256) + ($subSwitch * 16) + ($d[190+$p] -band 0x0F)
        $ports += $addr
        $good  += ("0x{0:X2}" -f $d[182+$p])
    }

    return [pscustomobject]@{
        IP = $ip; Bind = $bindIdx; Ports = $numPorts; MAC = $mac
        Name = $longName; Short = $shortName; Report = $report
        Addr = $ports; Good = $good
    }
}

# ---------------------------------------------------------------- Selbsttest
if ($SelfTest) {
    $t = New-Object byte[] 239
    $idb = [System.Text.Encoding]::ASCII.GetBytes("Art-Net")
    [Array]::Copy($idb, 0, $t, 0, 7)
    $t[7] = 0; $t[8] = 0x00; $t[9] = 0x21
    $t[10] = 10; $t[11] = 3; $t[12] = 96; $t[13] = 21
    $t[18] = 0; $t[19] = 0
    $sn = [System.Text.Encoding]::ASCII.GetBytes("PixLite Mk3")
    $ln = [System.Text.Encoding]::ASCII.GetBytes("PixLite 16 Garderobe 2. Floor")
    $rp = [System.Text.Encoding]::ASCII.GetBytes("OK")
    [Array]::Copy($sn, 0, $t, 26, $sn.Length)
    [Array]::Copy($ln, 0, $t, 44, $ln.Length)
    [Array]::Copy($rp, 0, $t, 108, $rp.Length)
    $t[172] = 0; $t[173] = 4
    $t[182] = 0x80; $t[183] = 0x80; $t[184] = 0x80; $t[185] = 0x80
    $t[190] = 9; $t[191] = 10; $t[192] = 11; $t[193] = 12
    $t[201] = 0xE0; $t[202] = 0xB6; $t[203] = 0xF5; $t[204] = 0xE0; $t[205] = 0xDF; $t[206] = 0xA2
    $t[211] = 5
    $o = Convert-ArtPollReply -Data $t
    if (-not $o) { Write-Host "SELFTEST FEHLGESCHLAGEN: kein Objekt"; exit 1 }
    $ok = ($o.IP -eq '10.3.96.21') -and ($o.Bind -eq 5) -and ($o.Ports -eq 4) -and
          ($o.Addr[0] -eq 9) -and ($o.Addr[3] -eq 12) -and ($o.MAC -eq 'E0:B6:F5:E0:DF:A2') -and
          ($o.Name -eq 'PixLite 16 Garderobe 2. Floor')
    Write-Host ("IP      : " + $o.IP)
    Write-Host ("Bind    : " + $o.Bind)
    Write-Host ("Ports   : " + $o.Ports)
    Write-Host ("Addr    : " + ($o.Addr -join ', '))
    Write-Host ("MAC     : " + $o.MAC)
    Write-Host ("Name    : " + $o.Name)
    Write-Host ("Good    : " + ($o.Good -join ', '))
    if ($ok) { Write-Host "SELFTEST OK"; exit 0 } else { Write-Host "SELFTEST FEHLGESCHLAGEN: Werte falsch"; exit 1 }
}

# ---------------------------------------------------------------- Kopf
$os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'unbekannt' }
W ("MADRIX-Diagnose  " + (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'))
W ("Rechner : " + $machine)
W ("Benutzer: " + $env:USERNAME)
W ("System  : " + $os + "  /  PowerShell " + $PSVersionTable.PSVersion.ToString())
W ("Ausgabe : " + $outFile)

# ---------------------------------------------------------------- MADRIX-Prozess
P "MADRIX-Prozess..."
Section "MADRIX-Prozess"
TryBlock "Prozess" {
    $p = Get-Process -Name MADRIX -ErrorAction SilentlyContinue
    if (-not $p) { W "MADRIX.exe laeuft NICHT (oder anderer Benutzer)."; return }
    foreach ($x in $p) {
        $ver = ''
        try { $ver = $x.MainModule.FileVersionInfo.FileVersion } catch { }
        W ("PID {0} | gestartet {1} | CPU {2:n1}s | RAM {3:n0} MB | Version {4}" -f `
            $x.Id, $x.StartTime, $x.TotalProcessorTime.TotalSeconds, ($x.WorkingSet64/1MB), $ver)
    }
}

# ---------------------------------------------------------------- Netzwerk
P "Netzwerk..."
Section "Netzwerkadapter"
TryBlock "Get-NetAdapter" {
    Get-NetAdapter -ErrorAction Stop | Sort-Object ifIndex |
        Format-Table -AutoSize Name, InterfaceDescription, Status, LinkSpeed, MacAddress | Out-String -Width 200
}
Section "IPv4-Adressen"
TryBlock "Get-NetIPAddress" {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne '127.0.0.1' } |
        Format-Table -AutoSize InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin | Out-String -Width 200
}
Section "ipconfig /all"
TryBlock "ipconfig" { ipconfig /all }
Section "Routen (IPv4)"
TryBlock "route" { route print -4 }
Section "ARP-Tabelle"
TryBlock "arp" { arp -a }
Section "UDP-Statistik"
TryBlock "netstat" { netstat -e -s | Select-String -Pattern 'UDP|Fehler|Errors|Empfangen|Received|Gesendet|Sent' }

# ---------------------------------------------------------------- Ping
P "Ping zu den Knoten (ca. 20 s)..."
Section "Erreichbarkeit der Art-Net-Knoten (10 Pings je Knoten)"
$ping = New-Object System.Net.NetworkInformation.Ping
foreach ($ip in $Nodes) {
    $ok = 0; $times = @()
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $r = $ping.Send($ip, 300)
            if ($r.Status -eq 'Success') { $ok++; $times += [int]$r.RoundtripTime }
        } catch { }
        Start-Sleep -Milliseconds 30
    }
    if ($ok -gt 0) {
        $min = ($times | Measure-Object -Minimum).Minimum
        $max = ($times | Measure-Object -Maximum).Maximum
        $avg = [math]::Round((($times | Measure-Object -Average).Average), 1)
        W ("{0,-13} {1,2}/10 Antworten   min {2} ms   avg {3} ms   max {4} ms" -f $ip, $ok, $min, $avg, $max)
    } else {
        W ("{0,-13}  0/10 Antworten   (nicht erreichbar)" -f $ip)
    }
}

# ---------------------------------------------------------------- ArtPoll
P "Art-Net Discovery (ArtPoll)..."
Section "Art-Net Knoten laut ArtPollReply (Universen/Ports)"
$replies = @()
try {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.EnableBroadcast = $true
    try {
        $u.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,
                                  [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $u.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0))
    } catch { }

    # ArtPoll: "Art-Net\0" + OpCode 0x2000 + ProtVer 0.14 + TalkToMe 0 + Priority 0
    $poll = [byte[]](0x41,0x72,0x74,0x2D,0x4E,0x65,0x74,0x00, 0x00,0x20, 0x00,0x0E, 0x00, 0x00)

    foreach ($target in @('255.255.255.255') + $Nodes) {
        try {
            $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($target), 6454)
            [void]$u.Send($poll, $poll.Length, $ep)
        } catch { }
    }

    $u.Client.ReceiveTimeout = 300
    $deadline = (Get-Date).AddSeconds(4)
    while ((Get-Date) -lt $deadline) {
        try {
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $data = $u.Receive([ref]$remote)
            if ($data.Length -ge 207) { $replies += ,$data }
        } catch { }
    }
    $u.Close()
} catch {
    W ("[Fehler] ArtPoll: " + $_.Exception.Message)
}

$artNodes = @{}
foreach ($d in $replies) {
    $o = Convert-ArtPollReply -Data $d
    if ($o) { $artNodes[$o.IP + "|" + $o.Bind] = $o }
}

if ($artNodes.Count -eq 0) {
    W "KEINE ArtPollReply empfangen."
    W "Moegliche Ursachen: falscher Netzwerkadapter, Firewall, VLAN, oder die Knoten sind aus."
} else {
    $sorted = $artNodes.Values | Sort-Object IP, Bind
    foreach ($n in $sorted) {
        $addrTxt = ($n.Addr | ForEach-Object { "U" + ($_ + 1) + "(Art-Net " + $_ + ")" }) -join ', '
        W ("{0,-13} Bind {1,-3} Ports {2}  MAC {3}" -f $n.IP, $n.Bind, $n.Ports, $n.MAC)
        W ("             Name: " + $n.Name)
        if ($n.Report) { W ("             Report: " + $n.Report) }
        W ("             Port-Adressen: " + $addrTxt)
        W ("             GoodOutput: " + ($n.Good -join ', '))
    }

    W ""
    W "--- Pruefung auf doppelt vergebene Universen (verschiedene Knoten) ---"
    $seen = @{}
    $dup = 0
    foreach ($n in $sorted) {
        foreach ($a in $n.Addr) {
            if ($seen.ContainsKey($a)) {
                if ($seen[$a] -ne $n.IP) {
                    W ("  [!] Universum U{0} (Art-Net {1}) wird von {2} UND {3} beansprucht" -f ($a+1), $a, $seen[$a], $n.IP)
                    $dup++
                }
            } else {
                $seen[$a] = $n.IP
            }
        }
    }
    if ($dup -eq 0) { W "  keine Doppelbelegung zwischen verschiedenen Knoten gefunden" }
}

# ---------------------------------------------------------------- Webseiten
P "Controller-Webseiten..."
Section "Controller-Weboberflaechen"
$alive = @{}
foreach ($n in $artNodes.Values) { $alive[$n.IP] = $true }
foreach ($ip in $Nodes) {
    W ""
    W ("--- " + $ip)
    if ($artNodes.Count -gt 0 -and -not $alive.ContainsKey($ip)) {
        W "  uebersprungen (kein ArtPollReply von diesem Knoten)"
        continue
    }
    foreach ($path in @('/','/status','/api/v1/status')) {
        $url = "http://$ip$path"
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            $len = 0
            try { $len = $r.RawContentLength } catch { $len = $r.Content.Length }
            W ("  GET {0,-22} -> {1} ({2} Bytes)" -f $path, [int]$r.StatusCode, $len)
            $safe = ($path -replace '[^A-Za-z0-9]', '_')
            $file = Join-Path $httpDir ($ip + $safe + ".txt")
            [System.IO.File]::WriteAllText($file, [string]$r.Content)
        } catch {
            W ("  GET {0,-22} -> {1}" -f $path, $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------- Registry
P "MADRIX-Einstellungen..."
Section "MADRIX-Einstellungen (Registry, nur gelesen)"
$regRoot = 'HKCU:\Software\inoage\MADRIX5'
if (Test-Path $regRoot) {
    TryBlock "Registry" {
        Get-ChildItem $regRoot -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $label = $_.Name -replace '^HKEY_CURRENT_USER\\Software\\inoage\\MADRIX5', ''
            if ($label -eq '') { $label = '\' }
            $o = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if (-not $o) { return }
            $vals = @($o.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })
            if ($vals.Count -eq 0) { return }
            W ("[" + $label + "]")
            foreach ($v in $vals) { W ("    " + $v.Name + " = " + $v.Value) }
        }
    }
    $mru = Get-ItemProperty -Path ($regRoot + '\StartOptions') -ErrorAction SilentlyContinue
    if ($mru -and $mru.MostRecentlyUsedSetup) {
        W ""
        W ("Zuletzt geoeffnetes Setup: " + $mru.MostRecentlyUsedSetup)
        if (Test-Path $mru.MostRecentlyUsedSetup) {
            $fi = Get-Item $mru.MostRecentlyUsedSetup
            W ("   Groesse: {0:n0} Bytes   geaendert: {1}" -f $fi.Length, $fi.LastWriteTime)
            if ($fi.Length -lt 40MB) {
                $copy = Join-Path $scriptDir ("LIVE_" + $fi.Name)
                Copy-Item $fi.FullName $copy -Force
                W ("   -> kopiert nach: " + $copy)
            }
        }
    }
} else {
    W "(kein MADRIX-Registry-Key gefunden)"
}

# ---------------------------------------------------------------- MADRIX-Ordner
P "MADRIX-Ordner..."
Section "MADRIX-Konfiguration"
$madrixDirs = @(
    (Join-Path $env:USERPROFILE 'Documents\MADRIX5'),
    'C:\ProgramData\MADRIX5'
)
foreach ($d in $madrixDirs) {
    if (-not (Test-Path $d)) { W ("(fehlt) " + $d); continue }
    W ""
    W ("Ordner: " + $d)
    TryBlock "Inhalt" {
        Get-ChildItem $d -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 25 |
            Format-Table -AutoSize Mode, LastWriteTime, Length, Name | Out-String -Width 200
    }
}

$devDir = Join-Path $env:USERPROFILE 'Documents\MADRIX5\device_settings'
if (Test-Path $devDir) {
    W ""
    W ("Geraetedateien: " + $devDir)
    $devs = Get-ChildItem $devDir -Filter *.mdmxx -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    foreach ($f in $devs) { W ("  {0}  {1,10:n0} Bytes  {2}" -f $f.LastWriteTime, $f.Length, $f.Name) }
    if ($devs.Count -gt 0) {
        $copy = Join-Path $scriptDir ("LIVE_" + $devs[0].Name)
        Copy-Item $devs[0].FullName $copy -Force
        W ("  -> neueste Datei kopiert nach: " + $copy)
    }
}

$setupDir = Join-Path $env:USERPROFILE 'Documents\MADRIX5\setups'
if (Test-Path $setupDir) {
    W ""
    W ("Setups: " + $setupDir)
    TryBlock "Setups" {
        Get-ChildItem $setupDir -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10 |
            Format-Table -AutoSize LastWriteTime, Length, Name | Out-String -Width 200
    }
}

$crashDir = 'C:\ProgramData\MADRIX5\CrashDumps'
if (Test-Path $crashDir) {
    W ""
    W ("CrashDumps: " + $crashDir)
    TryBlock "CrashDumps" {
        Get-ChildItem $crashDir -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10 |
            Format-Table -AutoSize LastWriteTime, Length, Name | Out-String -Width 200
    }
}

# ---------------------------------------------------------------- schreiben
[System.IO.File]::WriteAllText($outFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " Fertig." -ForegroundColor Green
Write-Host (" Datei: " + $outFile)
Write-Host (" Ordner fuer Webseiten: " + $httpDir)
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Bitte den kompletten Ordner in die Sammelstelle kopieren."
Write-Host ""
