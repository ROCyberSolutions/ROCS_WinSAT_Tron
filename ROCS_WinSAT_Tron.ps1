# ROCS_WinSAT_Tron.ps1
# Wersja 3.7 - Neonowy rdzeń z wykresami, powiadomieniami e-mail, przesyłaniem plików VirusTotal i dynamicznymi progami
# Powered by ROCyber Solutions

# Param block at the very top
param (
    [switch]$FullScan,
    [string]$ConfigPath = "CyberPunk_Config.json"
)

# Sprawdzenie uprawnień administratora
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ALERTA] Uruchom jako administrator dla pełnej funkcjonalności!" -ForegroundColor Red
    exit
}

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "  ROCS WinSAT Scanner v3.7 - Powered by ROCyber Solutions" -ForegroundColor Magenta
Write-Host "  Wchodzisz do cyfrowego rdzenia. Inicjalizacja matrycy..." -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Start-Sleep -Milliseconds 500

# Inicjalizacja zmiennych globalnych
$script:winSat = $null
$script:defenderStatus = $null
$script:topProcesses = @()
$script:diskHealth = @()
$script:errors = @()
$script:vtApiKey = $null
$script:vtResults = @()
$script:vtCache = @{}
$script:config = $null

# Funkcja do logowania błędów
function Write-ErrorLog {
    param (
        [string]$Message,
        [string]$Severity = "ERROR",
        [string]$FunctionName = (Get-PSCallStack)[1].Command
    )
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Severity] [$FunctionName] $Message"
    $logEntry | Out-File -FilePath "CyberPunk_Error_Log.txt" -Append
}

# Funkcja do wysyłania powiadomień e-mail
function Send-NeonAlert {
    param (
        [string]$Subject,
        [string]$Body
    )
    try {
        if (-not $script:config.SmtpServer -or -not $script:config.FromEmail -or -not $script:config.ToEmail) {
            Write-Host "[INFO] Brak konfiguracji SMTP w pliku konfiguracyjnym. Pomijanie wysyłki e-mail." -ForegroundColor Yellow
            return
        }
        $securePass = $script:config.SmtpPass | ConvertTo-SecureString -ErrorAction Stop
        $cred = New-Object PSCredential ($script:config.SmtpUser, $securePass)
        Send-MailMessage -SmtpServer $script:config.SmtpServer -Port 587 -From $script:config.FromEmail -To $script:config.ToEmail -Subject $Subject -Body $Body -Credential $cred -UseSsl -ErrorAction Stop
        Write-Host "[INFO] Powiadomienie e-mail wysłane: $Subject" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Błąd wysyłania e-mail: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Email alert failed: $($_.Exception.Message)"
    }
}

# Funkcja do ładowania konfiguracji
function Load-Config {
    try {
        if (Test-Path $ConfigPath) {
            $script:config = Get-Content $ConfigPath -ErrorAction Stop | ConvertFrom-Json
            if ($script:config.vtApiKey) {
                try {
                    $credential = Get-Credential -UserName "VirusTotalApiKey" -Message "Wprowadź hasło do klucza API (zostaw puste, jeśli nie zmieniono)" -ErrorAction SilentlyContinue
                    if ($credential) {
                        $script:vtApiKey = $script:config.vtApiKey | ConvertTo-SecureString -ErrorAction Stop | ConvertFrom-SecureString -SecureKey $credential.Password
                        Write-Host "[INFO] Klucz API VirusTotal załadowany z pliku konfiguracyjnego." -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "[INFO] Błąd deszyfrowania klucza API. Wprowadź ponownie w trakcie skanu." -ForegroundColor Yellow
                    $script:vtApiKey = $null
                }
            }
            if (-not $script:config.CpuThreshold) { $script:config | Add-Member -MemberType NoteProperty -Name CpuThreshold -Value 10 }
            if (-not $script:config.MaliciousThreshold) { $script:config | Add-Member -MemberType NoteProperty -Name MaliciousThreshold -Value 1 }
            $script:config | ConvertTo-Json | Out-File $ConfigPath -ErrorAction Stop
        }
        else {
            Write-Host "[INFO] Plik konfiguracyjny nie znaleziony. Tworzenie domyślnego." -ForegroundColor Yellow
            $script:config = [PSCustomObject]@{
                vtApiKey = ""
                SmtpServer = ""
                SmtpUser = ""
                SmtpPass = ""
                FromEmail = ""
                ToEmail = ""
                CpuThreshold = 10
                MaliciousThreshold = 1
            }
            $script:config | ConvertTo-Json | Out-File $ConfigPath -ErrorAction Stop
        }
    }
    catch {
        Write-Host "[ERROR] Błąd ładowania konfiguracji: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Config load failed: $($_.Exception.Message)"
        $script:config = [PSCustomObject]@{
            vtApiKey = ""
            SmtpServer = ""
            SmtpUser = ""
            SmtpPass = ""
            FromEmail = ""
            ToEmail = ""
            CpuThreshold = 10
            MaliciousThreshold = 1
        }
    }
}

Load-Config

# Funkcja do pobierania klucza API VirusTotal
function Get-VirusTotalApiKey {
    if (-not $script:vtApiKey) {
        $script:vtApiKey = Read-Host "Wpisz swój klucz API VirusTotal (jeśli masz; wciśnij Enter, aby pominąć)"
        if (-not $script:vtApiKey) {
            Write-Host "[INFO] Pomijanie integracji VirusTotal - brak klucza API." -ForegroundColor Yellow
        }
        else {
            try {
                $credential = New-Object PSCredential ("VirusTotalApiKey", (Read-Host -AsSecureString "Wprowadź hasło do szyfrowania klucza API (zapisz je!)"))
                $secureKey = $script:vtApiKey | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString -SecureKey $credential.Password
                $script:config.vtApiKey = $secureKey
                $script:config | ConvertTo-Json | Out-File $ConfigPath -ErrorAction Stop
                Write-Host "[INFO] Klucz API VirusTotal zapisany w pliku konfiguracyjnym." -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] Błąd zapisu klucza API: $($_.Exception.Message)" -ForegroundColor Red
                Write-ErrorLog -Message "API key save failed: $($_.Exception.Message)"
            }
        }
    }
    return $script:vtApiKey
}

# Funkcja do sprawdzania IP w VirusTotal
function Check-VirusTotalIP {
    param (
        [string]$ip
    )
    $apiKey = Get-VirusTotalApiKey
    if (-not $apiKey) { return $null }

    if ($script:vtCache.ContainsKey($ip)) {
        Write-Host "[INFO] Pobieranie wyników dla IP ${ip} z pamięci podręcznej." -ForegroundColor Yellow
        return $script:vtCache[$ip]
    }

    try {
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
        $headers = @{ "x-apikey" = $apiKey }
        $response = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
        $data = $response.Content | ConvertFrom-Json

        $vtResult = [PSCustomObject]@{
            IP = $ip
            Harmless = $data.data.attributes.last_analysis_stats.harmless
            Suspicious = $data.data.attributes.last_analysis_stats.suspicious
            Malicious = $data.data.attributes.last_analysis_stats.malicious
            ASOwner = $data.data.attributes.as_owner
            Country = $data.data.attributes.country
        }
        $script:vtResults += $vtResult
        $script:vtCache[$ip] = $vtResult

        Write-Host "`n[VIRUSTOTAL IP REPORT dla ${ip}]" -ForegroundColor Cyan
        Write-Host "  Harmless: $($vtResult.Harmless)" -ForegroundColor Green
        Write-Host "  Suspicious: $($vtResult.Suspicious)" -ForegroundColor Yellow
        Write-Host "  Malicious: $($vtResult.Malicious)" -ForegroundColor Red
        Write-Host "  AS Owner: $($vtResult.ASOwner)" -ForegroundColor Cyan
        Write-Host "  Country: $($vtResult.Country)" -ForegroundColor Cyan

        if ($vtResult.Malicious -ge $script:config.MaliciousThreshold) {
            Write-Host "[ALERTA] Wykryto złośliwą aktywność dla IP ${ip}!" -ForegroundColor Red
            Write-ErrorLog -Message "Malicious IP detected: ${ip} (malicious count: $($vtResult.Malicious))"
            Send-NeonAlert -Subject "CyberPunk Alert: Malicious IP Detected" -Body "IP: ${ip}, Malicious: $($vtResult.Malicious), AS: $($vtResult.ASOwner), Country: $($vtResult.Country)"
        }
        return $vtResult
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "[ERROR] Błąd VirusTotal API dla ${ip}: $errorMessage" -ForegroundColor Red
        Write-ErrorLog -Message "VirusTotal API error for ${ip}: $errorMessage"
        if ($errorMessage -match "429") {
            Write-Host "[INFO] Osiągnięto limit zapytań API (rate limit). Czy spróbować ponownie za 60 sekund? (t/n)" -ForegroundColor Yellow
            $retry = Read-Host
            if ($retry -eq 't') {
                Start-Sleep -Seconds 60
                return Check-VirusTotalIP -ip $ip
            }
        }
        elseif ($errorMessage -match "401") {
            Write-Host "[INFO] Błędny klucz API - sprawdź i wprowadź ponownie." -ForegroundColor Yellow
            $script:vtApiKey = $null
            $script:config.vtApiKey = ""
            $script:config | ConvertTo-Json | Out-File $ConfigPath
        }
        elseif ($errorMessage -match "network") {
            Write-Host "[INFO] Problem z połączeniem sieciowym. Sprawdź połączenie internetowe." -ForegroundColor Yellow
        }
        return $null
    }
}

# Funkcja do sprawdzania hasha pliku w VirusTotal
function Check-VirusTotalFile {
    param (
        [string]$filePath
    )
    $apiKey = Get-VirusTotalApiKey
    if (-not $apiKey) { return $null }

    try {
        if (-not (Test-Path $filePath)) {
            Write-Host "[ERROR] Plik ${filePath} nie istnieje." -ForegroundColor Red
            Write-ErrorLog -Message "File not found: ${filePath}"
            return $null
        }

        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        if ($script:vtCache.ContainsKey($hash.Hash)) {
            Write-Host "[INFO] Pobieranie wyników dla pliku ${filePath} z pamięci podręcznej." -ForegroundColor Yellow
            return $script:vtCache[$hash.Hash]
        }

        $uri = "https://www.virustotal.com/api/v3/files/$($hash.Hash)"
        $headers = @{ "x-apikey" = $apiKey }
        try {
            $response = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
            $data = $response.Content | ConvertFrom-Json

            $vtResult = [PSCustomObject]@{
                File = $filePath
                Hash = $hash.Hash
                Harmless = $data.data.attributes.last_analysis_stats.harmless
                Suspicious = $data.data.attributes.last_analysis_stats.suspicious
                Malicious = $data.data.attributes.last_analysis_stats.malicious
            }
            $script:vtResults += $vtResult
            $script:vtCache[$hash.Hash] = $vtResult

            Write-Host "`n[VIRUSTOTAL FILE REPORT dla ${filePath}]" -ForegroundColor Cyan
            Write-Host "  Hash: $($vtResult.Hash)" -ForegroundColor Cyan
            Write-Host "  Harmless: $($vtResult.Harmless)" -ForegroundColor Green
            Write-Host "  Suspicious: $($vtResult.Suspicious)" -ForegroundColor Yellow
            Write-Host "  Malicious: $($vtResult.Malicious)" -ForegroundColor Red

            if ($vtResult.Malicious -ge $script:config.MaliciousThreshold) {
                Write-Host "[ALERTA] Wykryto złośliwy plik ${filePath}!" -ForegroundColor Red
                Write-ErrorLog -Message "Malicious file detected: ${filePath} (malicious count: $($vtResult.Malicious))"
                Send-NeonAlert -Subject "CyberPunk Alert: Malicious File Detected" -Body "File: ${filePath}, Hash: $($vtResult.Hash), Malicious: $($vtResult.Malicious)"
            }
            return $vtResult
        }
        catch {
            if ($_.Exception.Message -match "404") {
                Write-Host "[INFO] Plik nie znaleziony w bazie VirusTotal. Czy przesłać plik do analizy? (t/n)" -ForegroundColor Yellow
                $confirm = Read-Host
                if ($confirm -eq 't') {
                    $uri = "https://www.virustotal.com/api/v3/files"
                    $form = @{ file = Get-Item $filePath }
                    $response = Invoke-WebRequest -Method POST -Uri $uri -Headers $headers -Form $form -ErrorAction Stop
                    Write-Host "[INFO] Plik przesłany do VirusTotal. Sprawdź wyniki na stronie VirusTotal." -ForegroundColor Green
                    Send-NeonAlert -Subject "CyberPunk Info: File Uploaded to VirusTotal" -Body "File: ${filePath}, Hash: $($hash.Hash) uploaded for analysis."
                }
                return $null
            }
            throw
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "[ERROR] Błąd VirusTotal API dla pliku ${filePath}: $errorMessage" -ForegroundColor Red
        Write-ErrorLog -Message "VirusTotal API error for file ${filePath}: $errorMessage"
        if ($errorMessage -match "429") {
            Write-Host "[INFO] Osiągnięto limit zapytań API (rate limit). Czy spróbować ponownie za 60 sekund? (t/n)" -ForegroundColor Yellow
            $retry = Read-Host
            if ($retry -eq 't') {
                Start-Sleep -Seconds 60
                return Check-VirusTotalFile -filePath $filePath
            }
        }
        return $null
    }
}

# Funkcja do wyświetlania cyberpunkowego paska postępu
function Show-NeonProgress {
    Write-Host "`n[NEON PROGRESS] Synchronizacja danych..." -ForegroundColor Cyan
    for ($i = 0; $i -le 100; $i += 20) {
        Write-Host "[$(('=' * ($i/10)).PadRight(10))>] $i%" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 200
    }
}

# Funkcja do skanowania wydajności systemu
function Get-NeonWinSAT {
    Write-Host "`n[NEON CORE] Skanowanie wydajności w toku..." -ForegroundColor Green
    Write-Host "  Uruchamianie protokołu WinSAT..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 300

    try {
        $script:winSat = Get-CimInstance Win32_WinSAT -ErrorAction Stop
        if (-not $script:winSat -or $script:winSat.WinSPRLevel -eq 0) {
            Write-Host "[ALERTA] Brak lub zerowe dane WinSAT. Inicjalizacja pełnego skanu systemu..." -ForegroundColor Red
            winsat formal | Out-Null
            Start-Sleep -Seconds 10
            $script:winSat = Get-CimInstance Win32_WinSAT -ErrorAction Stop
            if ($script:winSat.WinSPRLevel -eq 0) {
                Write-Host "[CRITICAL] WinSAT zwrócił zera - sprawdź sterowniki/WMI (ryzyko: ukryte malware?)" -ForegroundColor Red
                Write-ErrorLog -Message "WinSAT returned zero scores, possible WMI or driver issue"
                Send-NeonAlert -Subject "CyberPunk Alert: WinSAT Failure" -Body "WinSAT returned zero scores. Possible WMI or driver issue."
            }
        }

        Write-Host "`n[WYNIKI SKANU - NEON OUTPUT]" -ForegroundColor Cyan
        Write-Host "----------------------------------------" -ForegroundColor Cyan
        Write-Host " CPU Core:      $($script:winSat.CPUScore) [NEON PULS]" -ForegroundColor Green
        Write-Host " Memory Grid:   $($script:winSat.MemoryScore) [DATA FLOW]" -ForegroundColor Green
        Write-Host " Graphics:      $($script:winSat.GraphicsScore) [RENDER CORE]" -ForegroundColor Yellow
        Write-Host " D3D Matrix:    $($script:winSat.D3DScore) [GAME PROTOCOL]" -ForegroundColor Green
        Write-Host " Disk Stream:   $($script:winSat.DiskScore) [I/O CIRCUIT]" -ForegroundColor Green
        Write-Host " System Level:  $($script:winSat.WinSPRLevel) [OVERALL GRID]" -ForegroundColor Magenta
        Write-Host "----------------------------------------" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[ERROR] Błąd podczas skanowania WinSAT: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "WinSAT scan failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak uprawnień, problem z WMI lub sterownikami. Uruchom jako admin lub sprawdź system." -ForegroundColor Yellow
    }
}

# Funkcja do skanowania bezpieczeństwa
function Get-CyberSecStatus {
    Write-Host "`n[CYBERSEC GRID] Inicjalizacja skanu bezpieczeństwa..." -ForegroundColor Cyan
    Start-Sleep -Milliseconds 300

    try {
        $script:defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        Write-Host "[DEFENDER CORE]" -ForegroundColor Cyan
        if ($script:defenderStatus.RealTimeProtectionEnabled) {
            Write-Host "  Real-Time Protection: ONLINE" -ForegroundColor Green
        }
        else {
            Write-Host "  Real-Time Protection: OFFLINE" -ForegroundColor Red
            Write-Host "  Próba automatycznego włączenia..." -ForegroundColor Yellow
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            $script:defenderStatus = Get-MpComputerStatus -ErrorAction Stop
            if ($script:defenderStatus.RealTimeProtectionEnabled) {
                Write-Host "  Real-Time Protection: WŁĄCZONE AUTOMATYCZNIE" -ForegroundColor Green
            }
            else {
                Write-Host "  Błąd: Nie udało się włączyć ochrony!" -ForegroundColor Red
                Write-ErrorLog -Message "Failed to enable Real-Time Protection"
                Send-NeonAlert -Subject "CyberPunk Alert: Real-Time Protection Failure" -Body "Failed to enable Real-Time Protection."
            }
        }
        if ($script:defenderStatus.AntivirusEnabled) {
            Write-Host "  Antywirus: ACTIVE" -ForegroundColor Green
        }
        else {
            Write-Host "  Antywirus: INACTIVE" -ForegroundColor Red
            Write-ErrorLog -Message "Antivirus is inactive"
            Send-NeonAlert -Subject "CyberPunk Alert: Antivirus Inactive" -Body "Antivirus is inactive."
        }

        Write-Host "`n[SYSTEM LOAD] Analiza aktywnych procesów..." -ForegroundColor Cyan
        $script:topProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, @{Name="CPU_Usage";Expression={[math]::Round($_.CPU/1000,2)}}, @{Name="Memory_MB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}, @{Name="Path";Expression={$_.Path}}, @{Name="StartTime";Expression={$_.StartTime}}
        $script:topProcesses | ForEach-Object {
            Write-Host "  Proces: $($_.Name) | CPU: $($_.CPU_Usage)s | RAM: $($_.Memory_MB)MB | Ścieżka: $($_.Path) | Start: $($_.StartTime)" -ForegroundColor Yellow
            if ($_.CPU_Usage -gt $script:config.CpuThreshold -and $_.Path) {
                Write-Host "    [ALERTA] Wysokie obciążenie - sprawdź na malware?" -ForegroundColor Red
                $confirmVt = Read-Host "    Czy sprawdzić plik procesu w VirusTotal? (t/n)"
                if ($confirmVt -eq 't' -and $_.Path) {
                    Check-VirusTotalFile -filePath $_.Path
                }
            }
        }

        Write-Host "`n[DISK INTEGRITY] Skanowanie macierzy dyskowej..." -ForegroundColor Cyan
        $script:diskHealth = Get-PhysicalDisk | Select-Object DeviceId, MediaType, OperationalStatus, HealthStatus
        $script:diskHealth | ForEach-Object {
            if ($_.HealthStatus -eq 'Healthy') {
                Write-Host "  Dysk $($_.DeviceId) | Typ: $($_.MediaType) | Status: $($_.HealthStatus)" -ForegroundColor Green
            }
            else {
                Write-Host "  Dysk $($_.DeviceId) | Typ: $($_.MediaType) | Status: $($_.HealthStatus)" -ForegroundColor Red
                Write-ErrorLog -Message "Disk $($_.DeviceId) is not healthy: $($_.HealthStatus)"
                Send-NeonAlert -Subject "CyberPunk Alert: Unhealthy Disk" -Body "Disk $($_.DeviceId) is not healthy: $($_.HealthStatus)"
            }
        }
    }
    catch {
        Write-Host "[ERROR] Błąd podczas skanu bezpieczeństwa: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Security scan failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak modułu MicrosoftDefender lub problem z uprawnieniami." -ForegroundColor Yellow
    }
}

# Funkcja do sprawdzania błędów systemowych
function Check-SystemErrors {
    Write-Host "`n[ERROR SCAN] Analiza logów błędów..." -ForegroundColor Cyan
    try {
        $script:errors = Get-EventLog -LogName System -EntryType Error -Newest 10 | Where-Object { $_.EventID -in @(7036, 1000, 6008, 1001, 41) } -ErrorAction Stop
        if ($script:errors.Count -gt 0) {
            Write-Host "[ALERTA] Wykryto błędy systemowe (potencjalne zagrożenia):" -ForegroundColor Red
            $script:errors | ForEach-Object {
                Write-Host "  Czas: $($_.TimeGenerated) | Źródło: $($_.Source) | ID: $($_.EventID)" -ForegroundColor Yellow
                if ($_.EventID -in @(6008, 41)) {
                    Send-NeonAlert -Subject "CyberPunk Alert: Critical System Error" -Body "Event ID: $($_.EventID), Source: $($_.Source), Time: $($_.TimeGenerated)"
                }
            }
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $script:errors | Export-Csv -Path "CyberPunk_Errors_Log_$timestamp.csv" -NoTypeInformation
            Write-Host "  Log zapisany do CyberPunk_Errors_Log_$timestamp.csv" -ForegroundColor Green
        }
        else {
            Write-Host "  Brak błędów w ostatnich logach." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] Błąd podczas analizy logów: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Error log scan failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak dostępu do logów lub problem z EventLog." -ForegroundColor Yellow
    }
}

# Funkcja do sprawdzania sterowników
function Check-Drivers {
    Write-Host "`n[DRIVER SCAN] Analiza sterowników..." -ForegroundColor Cyan
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.DriverDate } | 
                   Select-Object DeviceName, DriverVersion, @{Name="DriverDate";Expression={[datetime]::Parse($_.DriverDate.Substring(0,8))}} |
                   Sort-Object DriverDate -ErrorAction Stop
        $oldDrivers = $drivers | Where-Object { $_.DriverDate -lt (Get-Date).AddYears(-2) }
        if ($oldDrivers) {
            Write-Host "[ALERTA] Wykryto potencjalnie nieaktualne sterowniki:" -ForegroundColor Red
            $oldDrivers | ForEach-Object {
                Write-Host "  Urządzenie: $($_.DeviceName) | Wersja: $($_.DriverVersion) | Data: $($_.DriverDate)" -ForegroundColor Yellow
            }
            Write-Host "  Zalecenie: Zaktualizuj sterowniki z oficjalnej strony producenta." -ForegroundColor Magenta
            Send-NeonAlert -Subject "CyberPunk Alert: Outdated Drivers" -Body "Outdated drivers detected: $($oldDrivers | ForEach-Object { "$($_.DeviceName) ($($_.DriverDate))" } | Join-String -Separator ', ')"
        }
        else {
            Write-Host "  Wszystkie sterowniki są aktualne." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] Błąd podczas skanu sterowników: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Driver scan failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Problem z WMI lub brak uprawnień." -ForegroundColor Yellow
    }
}

# Funkcja do monitorowania połączeń sieciowych
function Check-NetworkConnections {
    Write-Host "`n[NETWORK SCAN] Analiza aktywnych połączeń sieciowych..." -ForegroundColor Cyan
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | 
                       Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -ErrorAction Stop
        if ($connections) {
            Write-Host "  Aktywne połączenia:" -ForegroundColor Yellow
            $connections | ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                Write-Host "  Lokalny: $($_.LocalAddress):$($_.LocalPort) | Zdalny: $($_.RemoteAddress):$($_.RemotePort) | Proces: $($process.Name) | Ścieżka: $($process.Path)" -ForegroundColor Yellow
            }
            $suspicious = $connections | Where-Object { ($_.RemotePort -lt 1024 -or $_.RemotePort -gt 49152) -and $_.RemoteAddress -notmatch '^(127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)' }
            if ($suspicious) {
                Write-Host "[ALERTA] Wykryto połączenia na nietypowych portach (pominięto prywatne IP):" -ForegroundColor Red
                $suspicious | ForEach-Object {
                    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    Write-Host "  Zdalny: $($_.RemoteAddress):$($_.RemotePort) | Proces: $($process.Name) | Ścieżka: $($process.Path)" -ForegroundColor Red
                    $confirmVt = Read-Host "  Czy sprawdzić to IP w VirusTotal? (t/n)"
                    if ($confirmVt -eq 't') {
                        $vtResult = Check-VirusTotalIP -ip $_.RemoteAddress
                        if ($vtResult -and $vtResult.Malicious -ge $script:config.MaliciousThreshold -and $process.Path) {
                            $confirmFileVt = Read-Host "  Czy sprawdzić plik procesu ($($process.Path)) w VirusTotal? (t/n)"
                            if ($confirmFileVt -eq 't') {
                                Check-VirusTotalFile -filePath $process.Path
                            }
                        }
                    }
                }
                Write-ErrorLog -Message "Suspicious network connections detected"
            }
            else {
                Write-Host "  Brak podejrzanych połączeń (pominięto prywatne IP)." -ForegroundColor Green
            }
        }
        else {
            Write-Host "  Brak aktywnych połączeń TCP." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] Błąd podczas skanu sieci: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Network scan failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak modułu NetTCPIP lub problem z uprawnieniami." -ForegroundColor Yellow
    }
}

# Funkcja do aktualizacji systemu i programów
function Update-SystemAndApps {
    Write-Host "`n[UPDATE MATRIX] Skanowanie aktualizacji..." -ForegroundColor Cyan
    Start-Sleep -Milliseconds 300

    try {
        Write-Host "  [INFO] Aktualizacje minimalizują luki, ale weryfikuj źródła (unikaj spoofingu)." -ForegroundColor Yellow
        $confirm = Read-Host "  Czy chcesz zainstalować aktualizacje systemu i aplikacji? (t/n)"
        if ($confirm -ne 't') {
            Write-Host "  Aktualizacja anulowana." -ForegroundColor Yellow
            return
        }

        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "[INSTALACJA] Pobieranie modułu PSWindowsUpdate..." -ForegroundColor Yellow
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
        }

        Import-Module PSWindowsUpdate -ErrorAction Stop
        if (-not (Get-Command Get-WUInstall -ErrorAction SilentlyContinue)) {
            Write-Host "[ERROR] Cmdlet Get-WUInstall nie jest dostępny. Próbuję przeinstalować moduł..." -ForegroundColor Red
            Remove-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
            Import-Module PSWindowsUpdate -ErrorAction Stop
            if (-not (Get-Command Get-WUInstall -ErrorAction SilentlyContinue)) {
                throw "Nie udało się załadować Get-WUInstall. Sprawdź instalację modułu lub połączenie internetowe."
            }
        }

        $updates = Get-WUList -MicrosoftUpdate -ErrorAction Stop
        if ($updates.Count -gt 0) {
            Write-Host "[ALERTA] Dostępne aktualizacje systemu: $($updates.Count)" -ForegroundColor Red
            Write-Host "  Instalowanie..." -ForegroundColor Yellow
            Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop | Out-Null
            Write-Host "  Aktualizacje zainstalowane. Zalecany restart." -ForegroundColor Green
            Send-NeonAlert -Subject "CyberPunk Info: System Updates Installed" -Body "Installed $($updates.Count) system updates. Reboot recommended."
        }
        else {
            Write-Host "  System aktualny." -ForegroundColor Green
        }

        Write-Host "`n[APP UPDATE] Skanowanie aplikacji..." -ForegroundColor Cyan
        winget upgrade --all --include-unknown --silent | Out-Null
        Write-Host "  Aplikacje zaktualizowane." -ForegroundColor Green
        Send-NeonAlert -Subject "CyberPunk Info: Applications Updated" -Body "All applications updated via winget."
    }
    catch {
        Write-Host "[ERROR] Błąd podczas aktualizacji: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Update failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak internetu, błąd modułu, brak uprawnień. Spróbuj ręcznie: Install-Module PSWindowsUpdate" -ForegroundColor Yellow
    }
}

# Funkcja do tworzenia zadania zaplanowanego
function Set-ScheduledScan {
    Write-Host "`n[SCHEDULED SCAN] Konfiguracja automatycznego skanu..." -ForegroundColor Cyan
    try {
        $confirm = Read-Host "  Czy chcesz utworzyć zadanie zaplanowane (codziennie o 9:00)? (t/n)"
        if ($confirm -ne 't') {
            Write-Host "  Konfiguracja anulowana." -ForegroundColor Yellow
            return
        }
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($PSCommandPath)`" -FullScan" -ErrorAction Stop
        $trigger = New-ScheduledTaskTrigger -Daily -At "9AM" -ErrorAction Stop
        Register-ScheduledTask -TaskName "CyberPunk_Scan" -Action $action -Trigger $trigger -Description "Daily CyberPunk WinSAT Scan" -RunLevel Highest -ErrorAction Stop | Out-Null
        Write-Host "  Zadanie zaplanowane utworzone." -ForegroundColor Green
        Send-NeonAlert -Subject "CyberPunk Info: Scheduled Task Created" -Body "Daily CyberPunk scan scheduled for 9:00 AM."
    }
    catch {
        Write-Host "[ERROR] Błąd podczas tworzenia zadania: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "Scheduled task creation failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak uprawnień do scheduler lub problem z parametrami." -ForegroundColor Yellow
    }
}

# Funkcja do eksportu wyników do HTML
function Export-NeonReport {
    Write-Host "`n[NEON EXPORT] Generowanie raportu HTML..." -ForegroundColor Cyan
    try {
        if (-not $script:winSat) { Get-NeonWinSAT }
        if (-not $script:defenderStatus) { Get-CyberSecStatus }
        if (-not $script:errors) { Check-SystemErrors }

        $realTimeClass = if ($script:defenderStatus.RealTimeProtectionEnabled) { 'status-good' } else { 'status-bad' }
        $realTimeStatus = if ($script:defenderStatus.RealTimeProtectionEnabled) { 'ONLINE' } else { 'OFFLINE' }
        $antivirusClass = if ($script:defenderStatus.AntivirusEnabled) { 'status-good' } else { 'status-bad' }
        $antivirusStatus = if ($script:defenderStatus.AntivirusEnabled) { 'ACTIVE' } else { 'INACTIVE' }

        $recommendations = @()
        if ($script:winSat.WinSPRLevel -lt 7.0) {
            $recommendations += "Zalecenie: Rozważ modernizację sprzętu (np. SSD lub więcej RAM), aby poprawić ogólny wynik systemu."
        }
        if (-not $script:defenderStatus.RealTimeProtectionEnabled) {
            $recommendations += "Zalecenie: Upewnij się, że ochrona w czasie rzeczywistym jest włączona lub rozważ alternatywne oprogramowanie antywirusowe."
        }
        if ($script:diskHealth | Where-Object { $_.HealthStatus -ne 'Healthy' }) {
            $recommendations += "Zalecenie: Wymień uszkodzony dysk, aby zapobiec utracie danych."
        }
        if ($script:vtResults | Where-Object { $_.Malicious -ge $script:config.MaliciousThreshold }) {
            $recommendations += "Zalecenie: Zbadaj podejrzane IP/procesy z raportu VirusTotal. Rozważ izolację systemu i pełny skan antywirusowy."
        }

        $htmlContent = @"
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>CyberPunk WinSAT Report</title>
    <style>
        body {
            background-color: #0d0d0d;
            color: #00ffcc;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        h1, h2 {
            color: #ff00ff;
            text-shadow: 0 0 10px #ff00ff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background-color: #1a1a1a;
        }
        th, td {
            border: 1px solid #00ffcc;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #2a2a2a;
            color: #ff00ff;
        }
        .status-good { color: #00ff00; }
        .status-bad { color: #ff0000; }
        .neon-glow {
            box-shadow: 0 0 10px #00ffcc, 0 0 20px #00ffcc;
        }
        ul.recommendations {
            list-style-type: square;
            margin-top: 20px;
        }
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background-color: #2a2a2a;
            color: #ff00ff;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
        }
        .content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #1a1a1a;
        }
        canvas { max-width: 100%; margin-top: 20px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        function toggleCollapsible() {
            const coll = document.getElementsByClassName("collapsible");
            for (let i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    const content = this.nextElementSibling;
                    if (content.style.display === "block") {
                        content.style.display = "none";
                    } else {
                        content.style.display = "block";
                    }
                });
            }
        }
        window.onload = function() {
            toggleCollapsible();
            const ctx = document.getElementById('winSatChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['CPU', 'Memory', 'Graphics', 'D3D', 'Disk', 'System'],
                    datasets: [{
                        label: 'WinSAT Scores',
                        data: [$($script:winSat.CPUScore), $($script:winSat.MemoryScore), $($script:winSat.GraphicsScore), $($script:winSat.D3DScore), $($script:winSat.DiskScore), $($script:winSat.WinSPRLevel)],
                        backgroundColor: ['#00ffcc', '#00ffcc', '#00ffcc', '#00ffcc', '#00ffcc', '#ff00ff'],
                        borderColor: ['#00ff00', '#00ff00', '#00ff00', '#00ff00', '#00ff00', '#ff00ff'],
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: { y: { beginAtZero: true, max: 10 } },
                    plugins: { legend: { labels: { color: '#00ffcc' } } }
                }
            });
        };
    </script>
</head>
<body>
    <h1>CyberPunk WinSAT Scanner v3.7 - ROCyber Solutions</h1>
    <h2>Raport Systemowy - $(Get-Date)</h2>
    <h3>Wyniki WinSAT</h3>
    <canvas id="winSatChart"></canvas>
    <table class="neon-glow">
        <tr><th>Komponent</th><th>Wynik</th><th>Opis</th></tr>
        <tr><td>CPU Core</td><td>$($script:winSat.CPUScore)</td><td>NEON PULS</td></tr>
        <tr><td>Memory Grid</td><td>$($script:winSat.MemoryScore)</td><td>DATA FLOW</td></tr>
        <tr><td>Graphics</td><td>$($script:winSat.GraphicsScore)</td><td>RENDER CORE</td></tr>
        <tr><td>D3D Matrix</td><td>$($script:winSat.D3DScore)</td><td>GAME PROTOCOL</td></tr>
        <tr><td>Disk Stream</td><td>$($script:winSat.DiskScore)</td><td>I/O CIRCUIT</td></tr>
        <tr><td>System Level</td><td>$($script:winSat.WinSPRLevel)</td><td>OVERALL GRID</td></tr>
    </table>
    <h3>Status Bezpieczeństwa</h3>
    <table class="neon-glow">
        <tr><th>Element</th><th>Status</th></tr>
        <tr><td>Real-Time Protection</td><td class="$realTimeClass">$realTimeStatus</td></tr>
        <tr><td>Antywirus</td><td class="$antivirusClass">$antivirusStatus</td></tr>
    </table>
    <h3>Top Procesy</h3>
    <table class="neon-glow">
        <tr><th>Nazwa</th><th>CPU (s)</th><th>Pamięć (MB)</th><th>Ścieżka</th><th>Czas Startu</th></tr>
        $(if ($script:topProcesses) { ($script:topProcesses | ForEach-Object { "<tr><td>$($_.Name)</td><td>$($_.CPU_Usage)</td><td>$($_.Memory_MB)</td><td>$($_.Path)</td><td>$($_.StartTime)</td></tr>" }) -join '' } else { '<tr><td>Brak danych</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>' })
    </table>
    <h3>Zdrowie Dysków</h3>
    <table class="neon-glow">
        <tr><th>Dysk ID</th><th>Typ</th><th>Status</th></tr>
        $(if ($script:diskHealth) { ($script:diskHealth | ForEach-Object { 
            $diskStatusClass = if ($_.HealthStatus -eq 'Healthy') { 'status-good' } else { 'status-bad' }
            "<tr><td>$($_.DeviceId)</td><td>$($_.MediaType)</td><td class='$diskStatusClass'>$($_.HealthStatus)</td></tr>" 
        }) -join '' } else { '<tr><td>Brak danych</td><td>-</td><td>-</td></tr>' })
    </table>
    <h3>Błędy Systemowe</h3>
    <table class="neon-glow">
        <tr><th>Czas</th><th>Źródło</th><th>ID</th></tr>
        $(if ($script:errors) { ($script:errors | ForEach-Object { "<tr><td>$($_.TimeGenerated)</td><td>$($_.Source)</td><td>$($_.EventID)</td></tr>" }) -join '' } else { '<tr><td>Brak danych</td><td>-</td><td>-</td></tr>' })
    </table>
    <h3 class="collapsible">Wyniki VirusTotal</h3>
    <div class="content">
        <table class="neon-glow">
            <tr><th>Typ</th><th>Obiekt</th><th>Harmless</th><th>Suspicious</th><th>Malicious</th><th>Dodatkowe</th></tr>
            $(if ($script:vtResults) { ($script:vtResults | ForEach-Object { 
                $type = if ($_.IP) { 'IP' } else { 'Plik' }
                $object = if ($_.IP) { $_.IP } else { $_.File }
                $additional = if ($_.IP) { "AS: $($_.ASOwner), Kraj: $($_.Country)" } else { "Hash: $($_.Hash)" }
                "<tr><td>$type</td><td>$object</td><td>$($_.Harmless)</td><td>$($_.Suspicious)</td><td>$($_.Malicious)</td><td>$additional</td></tr>"
            }) -join '' } else { '<tr><td>Brak danych</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>' })
        </table>
    </div>
    <h3>Zalecenia ROCyber Solutions</h3>
    <ul class="recommendations">
        $(if ($recommendations) { ($recommendations | ForEach-Object { "<li>$_</li>" }) -join '' } else { '<li>Brak zaleceń - system w dobrym stanie.</li>' })
    </ul>
</body>
</html>
"@
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $htmlContent | Out-File -FilePath "CyberPunk_Report_$timestamp.html" -Encoding UTF8
        Write-Host "  Raport HTML zapisany do CyberPunk_Report_$timestamp.html" -ForegroundColor Green
        Send-NeonAlert -Subject "CyberPunk Info: HTML Report Generated" -Body "Report saved to CyberPunk_Report_$timestamp.html"
    }
    catch {
        Write-Host "[ERROR] Błąd podczas generowania raportu HTML: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog -Message "HTML report generation failed: $($_.Exception.Message)"
        Write-Host "[INFO] Możliwe przyczyny: Brak danych lub problem z konwersją." -ForegroundColor Yellow
    }
}

# Funkcja menu wyboru
function Show-NeonMenu {
    Write-Host "`n[NEON MENU] Wybierz akcję:" -ForegroundColor Cyan
    Write-Host "  1. Skan wydajności (WinSAT)" -ForegroundColor Green
    Write-Host "  2. Skan bezpieczeństwa (Defender, Procesy, Dyski)" -ForegroundColor Green
    Write-Host "  3. Skan błędów systemowych" -ForegroundColor Green
    Write-Host "  4. Aktualizacja systemu i aplikacji" -ForegroundColor Green
    Write-Host "  5. Skan sterowników" -ForegroundColor Green
    Write-Host "  6. Skan połączeń sieciowych (z VirusTotal)" -ForegroundColor Green
    Write-Host "  7. Utwórz zadanie zaplanowane" -ForegroundColor Green
    Write-Host "  8. Eksport raportu do HTML" -ForegroundColor Green
    Write-Host "  9. Wykonaj wszystkie akcje" -ForegroundColor Green
    Write-Host "  10. Wyjdź" -ForegroundColor Red
    $choice = Read-Host "  Wpisz numer akcji (1-10)"
    return $choice
}

# Główny blok programu
try {
    if ($FullScan) {
        Write-Host "[FULL SCAN] Wymuszanie pełnego skanu WinSAT..." -ForegroundColor Yellow
        winsat formal | Out-Null
        Start-Sleep -Seconds 10
    }

    Show-NeonProgress
    $runAll = $false

    while ($true) {
        $choice = Show-NeonMenu
        switch ($choice) {
            "1" { Get-NeonWinSAT }
            "2" { Get-CyberSecStatus }
            "3" { Check-SystemErrors }
            "4" { Update-SystemAndApps }
            "5" { Check-Drivers }
            "6" { Check-NetworkConnections }
            "7" { Set-ScheduledScan }
            "8" { 
                if (-not $script:winSat) { Get-NeonWinSAT }
                if (-not $script:defenderStatus) { Get-CyberSecStatus }
                if (-not $script:errors) { Check-SystemErrors }
                Export-NeonReport 
            }
            "9" { 
                $runAll = $true
                Get-NeonWinSAT
                Get-CyberSecStatus
                Check-SystemErrors
                Update-SystemAndApps
                Check-Drivers
                Check-NetworkConnections
                Export-NeonReport
            }
            "10" { 
                Write-Host "`n[EXIT] Opuszczanie matrycy. System zabezpieczony." -ForegroundColor Magenta
                break
            }
            default { Write-Host "[BŁĄD] Nieprawidłowy wybór. Wybierz 1-10." -ForegroundColor Red }
        }
        if ($runAll -or $choice -eq "10") { break }
        Write-Host "`n[NEON CORE] Naciśnij Enter, aby wrócić do menu..." -ForegroundColor Cyan
        Read-Host
    }

    Write-Host "`n[GRID STATUS] Skan zakończony. System w stanie bojowym." -ForegroundColor Green
    Write-Host "  ROCyber Solutions zaleca: Aktualizuj sterowniki, monitoruj procesy, chroń matrycę." -ForegroundColor Magenta
    Write-Host "=============================================================" -ForegroundColor Cyan

    if ($script:winSat -and $script:defenderStatus) {
        $report = @{
            WinSAT = $script:winSat
            Defender = $script:defenderStatus
            TopProcesses = if ($script:topProcesses) { $script:topProcesses } else { @() }
            DiskHealth = if ($script:diskHealth) { $script:diskHealth } else { @() }
            Errors = if ($script:errors) { $script:errors } else { @() }
            VirusTotal = if ($script:vtResults) { $script:vtResults } else { @() }
        }
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $report | ConvertTo-Json | Out-File "CyberPunk_Report_$timestamp.json"
        Write-Host "  Raport JSON zapisany do CyberPunk_Report_$timestamp.json" -ForegroundColor Green
        Send-NeonAlert -Subject "CyberPunk Info: JSON Report Generated" -Body "Report saved to CyberPunk_Report_$timestamp.json"
    }
}
catch {
    Write-Host "[CRITICAL ERROR] Błąd w matrycy: $($_.Exception.Message)" -ForegroundColor Red
    Write-ErrorLog -Message "Main script execution failed: $($_.Exception.Message)"
    Send-NeonAlert -Subject "CyberPunk Alert: Critical Script Error" -Body "Main script execution failed: $($_.Exception.Message)"
}
finally {
    Write-Host "[FINALIZE] Zakończenie operacji w matrycy." -ForegroundColor Cyan
}