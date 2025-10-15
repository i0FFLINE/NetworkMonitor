# Мониторинг активных TCP и UDP-соединений
param(
    [int]$IntervalSec = 3,
    [switch]$ShowPID,
    [switch]$ShowProgress,
    [switch]$ShowUDP,
    [switch]$ShowPorts,
    [int]$DnsTimeoutMs = 2000
)

# Инициализация переменных
$dnsCache = @{}
$previousIPs = @{}
$privateIPPatterns = @(
    '^127\.',
    '^10\.',
    '^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    '^192\.168\.',
    '^169\.254\.'
)

# Функция проверки приватных IP
function Test-PrivateIP {
    param([string]$IP)
    
    if ($IP -eq '127.0.0.1') { return $true }
    
    foreach ($pattern in $privateIPPatterns) {
        if ($IP -match $pattern) {
            return $true
        }
    }
    return $false
}

# Быстрый DNS-резолв с кэшированием и прогрессом
function Resolve-DNSCached {
    param([string]$IPAddress, [int]$TotalIPs = 1, [int]$CurrentIP = 1)
    
    if ($dnsCache.ContainsKey($IPAddress)) {
        return $dnsCache[$IPAddress]
    }
    
    # Для приватных IP не делаем резолв
    if (Test-PrivateIP -IP $IPAddress) {
        if ($IPAddress -eq '127.0.0.1') {
            $dnsCache[$IPAddress] = 'localhost'
        } else {
            $dnsCache[$IPAddress] = $null
        }
        return $dnsCache[$IPAddress]
    }
    
    # Показываем прогресс резолва
    if ($ShowProgress) {
        $percent = [math]::Round(($CurrentIP / $TotalIPs) * 100)
        Write-Progress -Activity "DNS Resolution" -Status "Resolving $IPAddress ($CurrentIP/$TotalIPs)" -PercentComplete $percent
    }
    
    try {
        # Синхронный резолв с таймаутом через Job
        $job = Start-Job -ScriptBlock {
            param($ip)
            try {
                return [System.Net.Dns]::GetHostEntry($ip).HostName
            }
            catch {
                return $null
            }
        } -ArgumentList $IPAddress
        
        # Ждем завершения с таймаутом
        $null = $job | Wait-Job -Timeout ($DnsTimeoutMs / 1000)
        
        if ($job.State -eq 'Completed') {
            $hostName = Receive-Job -Job $job
            if ($hostName -and $hostName -ne $IPAddress -and $hostName -notlike '*in-addr.arpa*') {
                $dnsCache[$IPAddress] = $hostName
                if ($ShowProgress) {
                    Write-Host "  ✓ Resolved: $IPAddress → $hostName" -ForegroundColor Green
                }
            } else {
                $dnsCache[$IPAddress] = $null
                if ($ShowProgress) {
                    Write-Host "  ✗ No reverse DNS: $IPAddress" -ForegroundColor Yellow
                }
            }
        } else {
            # Таймаут - останавливаем job
            $job | Stop-Job
            $dnsCache[$IPAddress] = $null
            if ($ShowProgress) {
                Write-Host "  ⚠ Timeout: $IPAddress" -ForegroundColor Red
            }
        }
        
        # Очищаем job
        $job | Remove-Job -Force
    }
    catch {
        $dnsCache[$IPAddress] = $null
        if ($ShowProgress) {
            Write-Host "  ✗ Error resolving $IPAddress : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    return $dnsCache[$IPAddress]
}

# Получение TCP соединений
function Get-TCPConnections {
    try {
        if ($ShowProgress) {
            Write-Host "Scanning TCP connections..." -ForegroundColor Cyan
        }
        $connections = Get-NetTCPConnection -State Established | Where-Object {
            $_.RemoteAddress -ne '::1' -and 
            $_.RemoteAddress -notlike '*:*' -and
            $_.RemoteAddress -ne '0.0.0.0' -and
            $_.RemoteAddress -ne $null -and
            $_.RemoteAddress -ne '127.0.0.1'
        }
        if ($ShowProgress) {
            Write-Host "Found $($connections.Count) TCP connections" -ForegroundColor Green
        }
        return $connections
    }
    catch {
        if ($ShowProgress) {
            Write-Host "Error getting TCP connections: $($_.Exception.Message)" -ForegroundColor Red
        }
        return @()
    }
}

# Получение UDP соединений
function Get-UDPConnections {
    try {
        if ($ShowProgress) {
            Write-Host "Scanning UDP connections..." -ForegroundColor Cyan
        }
        $connections = Get-NetUDPEndpoint | Where-Object {
            $_.RemoteAddress -ne '::1' -and 
            $_.RemoteAddress -notlike '*:*' -and
            $_.RemoteAddress -ne '0.0.0.0' -and
            $_.RemoteAddress -ne $null -and
            $_.RemoteAddress -ne '255.255.255.255' -and
            $_.RemoteAddress -ne '127.0.0.1'
        }
        if ($ShowProgress) {
            Write-Host "Found $($connections.Count) UDP connections" -ForegroundColor Green
        }
        return $connections
    }
    catch {
        if ($ShowProgress) {
            Write-Host "Error getting UDP connections: $($_.Exception.Message)" -ForegroundColor Red
        }
        return @()
    }
}

# Получение и обработка всех соединений
function Get-ConnectionData {
    $tcpConnections = Get-TCPConnections
    $udpConnections = if ($ShowUDP) { Get-UDPConnections } else { @() }
    
    $allConnections = @()
    $allIPs = @()
    
    # Собираем все уникальные IP
    if ($tcpConnections) { 
        $allIPs += $tcpConnections.RemoteAddress 
    }
    if ($udpConnections) { 
        $allIPs += $udpConnections.RemoteAddress 
    }
    $uniqueIPs = $allIPs | Sort-Object -Unique
    
    if ($ShowProgress) {
        Write-Host "Found $($uniqueIPs.Count) unique IP addresses to resolve" -ForegroundColor Yellow
    }
    
    # Резолв всех IP с прогрессом
    $ipCount = $uniqueIPs.Count
    $currentIP = 0
    
    foreach ($ip in $uniqueIPs) {
        $currentIP++
        if (-not $dnsCache.ContainsKey($ip)) {
            $null = Resolve-DNSCached -IPAddress $ip -TotalIPs $ipCount -CurrentIP $currentIP
        }
    }
    
    # Завершаем прогресс-бар
    if ($ShowProgress) {
        Write-Progress -Activity "DNS Resolution" -Completed
    }
    
    # Обработка TCP соединений
    if ($tcpConnections) {
        if ($ShowProgress) {
            Write-Host "Processing TCP connections..." -ForegroundColor Cyan
        }
        foreach ($conn in $tcpConnections) {
            $ip = $conn.RemoteAddress
            $remotePort = $conn.RemotePort
            
            # Получаем имя процесса
            $processName = "Unknown"
            try {
                if ($conn.OwningProcess) {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($process) {
                        $processName = $process.ProcessName
                    } else {
                        $processName = "PID:$($conn.OwningProcess)"
                    }
                }
            }
            catch {
                $processName = "PID:$($conn.OwningProcess)"
            }
            
            $allConnections += [PSCustomObject]@{
                RemoteAddress = $ip
                Process = $processName
                PID = $conn.OwningProcess
                ResolvedName = $dnsCache[$ip]
                Protocol = "TCP"
                LocalPort = $conn.LocalPort
                RemotePort = $remotePort
            }
        }
    }
    
    # Обработка UDP соединений
    if ($udpConnections) {
        if ($ShowProgress) {
            Write-Host "Processing UDP connections..." -ForegroundColor Cyan
        }
        foreach ($conn in $udpConnections) {
            $ip = $conn.RemoteAddress
            $remotePort = $conn.RemotePort
            
            # Получаем имя процесса
            $processName = "Unknown"
            try {
                if ($conn.OwningProcess) {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($process) {
                        $processName = $process.ProcessName
                    } else {
                        $processName = "PID:$($conn.OwningProcess)"
                    }
                }
            }
            catch {
                $processName = "PID:$($conn.OwningProcess)"
            }
            
            $allConnections += [PSCustomObject]@{
                RemoteAddress = $ip
                Process = $processName
                PID = $conn.OwningProcess
                ResolvedName = $dnsCache[$ip]
                Protocol = "UDP"
                LocalPort = $conn.LocalPort
                RemotePort = $remotePort
            }
        }
    }
    
    if ($ShowProgress) {
        Write-Host "Processing complete. Total connections: $($allConnections.Count)" -ForegroundColor Green
    }
    return $allConnections
}

# Функция для создания строки повторения символов
function Repeat-Char {
    param([string]$Char, [int]$Count)
    return -join ([string]$Char * $Count)
}

# Компактный вывод с раздельными колонками IP и Hostname
function Show-CompactOutput {
    param(
        [array]$Connections,
        [hashtable]$PreviousIPs
    )
    
    $currentIPs = @{}
    $newIPs = @()
    
    Clear-Host
    
    # Заголовок
    $borderLength = 90
    $title = "ACTIVE NETWORK CONNECTIONS"
    if ($ShowUDP) {
        $title += " (TCP+UDP)"
    } else {
        $title += " (TCP only)"
    }
    
    Write-Host $(Repeat-Char "═" $borderLength) -ForegroundColor Cyan
    Write-Host " $title" -ForegroundColor Cyan -NoNewline
    Write-Host " [$(Get-Date -Format 'HH:mm:ss')]" -ForegroundColor Yellow
    Write-Host $(Repeat-Char "═" $borderLength) -ForegroundColor Cyan
    Write-Host ""
    
    # Группировка по процессам
    $byProcess = $Connections | Group-Object Process | Sort-Object Count -Descending
    
    $totalConnections = $Connections.Count
    $tcpCount = ($Connections | Where-Object { $_.Protocol -eq "TCP" }).Count
    $udpCount = ($Connections | Where-Object { $_.Protocol -eq "UDP" }).Count
    
    foreach ($processGroup in $byProcess) {
        $processName = $processGroup.Name
        $processConns = $processGroup.Group
        
        Write-Host " $processName" -ForegroundColor White -NoNewline
        Write-Host " [$($processConns.Count) connections]" -ForegroundColor Gray
        Write-Host ""
        
        foreach ($conn in $processConns) {
            $ip = $conn.RemoteAddress
            $currentIPs[$ip] = $true
            
            $isNew = -not $PreviousIPs.ContainsKey($ip)
            if ($isNew) { $newIPs += $ip }
            
            # Форматируем вывод
            $marker = if ($isNew) { "    → " } else { "      " }
            $color = if ($isNew) { "Green" } else { "Gray" }
            
            Write-Host $marker -NoNewline -ForegroundColor $color
            
            # Колонка 1: IP адрес (фиксированная ширина)
            Write-Host $(($conn.RemoteAddress).PadRight(16)) -NoNewline -ForegroundColor $color
            
            # Колонка 2: Порт если включено
            if ($ShowPorts) {
                $portInfo = ":$(($conn.RemotePort).ToString().PadRight(5))"
                Write-Host $portInfo -NoNewline -ForegroundColor DarkYellow
            } else {
                Write-Host "       " -NoNewline
            }
            
            # Колонка 3: Протокол
            $protocolColor = if ($conn.Protocol -eq "TCP") { "Blue" } else { "Magenta" }
            Write-Host " $($conn.Protocol.PadRight(4))" -NoNewline -ForegroundColor $protocolColor
            
            # Колонка 4: PID если включено
            if ($ShowPID -and $conn.PID) {
                Write-Host " [$($conn.PID)]" -NoNewline -ForegroundColor DarkGray
            } else {
                Write-Host "        " -NoNewline
            }
            
            # Колонка 5: Резолвенное имя хоста (не обрезается)
            if ($conn.ResolvedName) {
                Write-Host "  → $($conn.ResolvedName)" -ForegroundColor DarkCyan
            } else {
                Write-Host ""
            }
        }
        Write-Host ""
    }
    
    # Статистика
    Write-Host $(Repeat-Char "─" $borderLength) -ForegroundColor DarkGray
    Write-Host " STATS: " -NoNewline -ForegroundColor White
    Write-Host "$($byProcess.Count) processes, " -NoNewline -ForegroundColor Gray
    Write-Host "$($currentIPs.Count) hosts, " -NoNewline -ForegroundColor Gray
    Write-Host "$totalConnections connections" -ForegroundColor Gray
    
    if ($ShowUDP) {
        Write-Host " PROTO: " -NoNewline -ForegroundColor White
        Write-Host "TCP: $tcpCount" -NoNewline -ForegroundColor Blue
        Write-Host ", " -NoNewline
        Write-Host "UDP: $udpCount" -ForegroundColor Magenta
    }
    
    if ($newIPs.Count -gt 0) {
        Write-Host " NEW: " -NoNewline -ForegroundColor Green
        Write-Host "$($newIPs.Count) new hosts" -ForegroundColor Green
    }
    
    Write-Host " CACHE: " -NoNewline -ForegroundColor White
    $resolvedCount = ($dnsCache.Values | Where-Object { $_ }).Count
    Write-Host "$resolvedCount DNS entries" -ForegroundColor Gray
    Write-Host $(Repeat-Char "═" $borderLength) -ForegroundColor Cyan
    
    return $currentIPs
}

# Основной цикл
try {
    $mode = if ($ShowUDP) { "TCP+UDP" } else { "TCP only" }
    Write-Host "Starting Network Monitor ($mode)..." -ForegroundColor Green
    Write-Host "Interval: $IntervalSec seconds" -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Red
    Write-Host ""
    
    # Первоначальная пауза чтобы прочитать сообщение
    Start-Sleep -Seconds 2
    
    while ($true) {
        try {
            # Очистка старых jobs на случай ошибок
            Get-Job | Remove-Job -Force
            
            if ($ShowProgress) {
                Write-Host "Scanning cycle started..." -ForegroundColor Cyan
            }
            $connectionData = Get-ConnectionData
            $previousIPs = Show-CompactOutput -Connections $connectionData -PreviousIPs $previousIPs
            
            if ($ShowProgress) {
                Write-Host "Next scan in $IntervalSec seconds..." -ForegroundColor Gray
                Write-Progress -Activity "Monitoring" -Status "Waiting..." -PercentComplete 100
            }
            Start-Sleep -Seconds $IntervalSec
        }
        catch {
            Write-Host "Error in main loop: $($_.Exception.Message)" -ForegroundColor Red
            Start-Sleep -Seconds $IntervalSec
        }
    }
}
catch {
    Write-Host "Monitor stopped." -ForegroundColor Yellow
}
finally {
    if ($ShowProgress) {
        Write-Progress -Activity "Monitoring" -Completed
    }
    # Очистка jobs при завершении
    Get-Job | Remove-Job -Force
}