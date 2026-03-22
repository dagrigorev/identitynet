# ============================================================================
# run.ps1 — Identity Network launcher for Windows (PowerShell)
# ============================================================================

param(
    [Parameter(Position=0)] [string]$Command = "help",
    [Parameter(Position=1)] [string]$Arg1    = "",
    [Parameter(Position=2)] [string]$Arg2    = "",
    [Parameter(Position=3)] [string]$Arg3    = "",
    [Parameter(ValueFromRemainingArguments=$true)] [string[]]$Rest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$IMAGE = "identitynet:latest"

function Write-Info  { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Err   { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Write-Warn  { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }

function Assert-Docker {
    try { docker info 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw } }
    catch {
        Write-Err "Docker is not running. Start Docker Desktop first."
        Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        exit 1
    }
}

function Assert-Built {
    docker image inspect $IMAGE 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warn "Image not found, building..."; Invoke-Build }
}

function Invoke-Build {
    Write-Step "Building Identity Network Docker image"
    Write-Info "Compiling C++20 source (~2 min first time)..."
    docker build --target runtime -t $IMAGE .
    if ($LASTEXITCODE -ne 0) { Write-Err "Build failed."; exit 1 }
    Write-Ok "Image built: $IMAGE"
}

function Invoke-Demo  { Assert-Built; docker run --rm --name idn-demo  $IMAGE identitynet-demo }
function Invoke-Tests { Assert-Built; docker run --rm --name idn-tests $IMAGE identitynet-tests }
function Invoke-Up    {
    Assert-Built
    docker compose up -d discovery server
    Start-Sleep 3
    Write-Ok "Running: discovery:7700  server:7701"
}
function Invoke-Down  { docker compose down; Write-Ok "Stopped." }
function Invoke-Shell {
    Assert-Built
    Write-Info "Shell in container. Type 'exit' to leave."
    docker run --rm -it --name idn-shell $IMAGE /bin/bash
}
function Invoke-Logs  {
    $svc = if ($Arg1) { $Arg1 } else { "proxy-client" }
    docker logs -f --tail 50 "idn-$svc"
}

# ── PROXY CLIENT ──────────────────────────────────────────────────────────────
function Invoke-ProxyClient {
    if (-not $Arg1 -or -not $Arg2 -or -not $Arg3) {
        Write-Host ""
        Write-Host " Usage: .\run.ps1 proxy-client <VPS_IP> <PORT> `"<PUBKEY>`"" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " Example:" -ForegroundColor Cyan
        Write-Host "   .\run.ps1 proxy-client 1.2.3.4 7701 `"r6Kub85zfI+qfUGx...`""
        Write-Host ""
        Write-Host " Get PUBKEY from VPS:  bash setup_vps.sh"
        return
    }

    $VPS_IP   = $Arg1
    $VPS_PORT = $Arg2
    $PUBKEY   = $Arg3
    $SOCKS    = if ($Rest -and $Rest.Count -gt 0) { $Rest[0] } else { "1080" }

    Write-Step "Identity Network Proxy Client"
    Assert-Built

    Write-Info "VPS:        $VPS_IP`:$VPS_PORT"
    Write-Info "Server key: $($PUBKEY.Substring(0,[Math]::Min(20,$PUBKEY.Length)))..."
    Write-Info "SOCKS5:     127.0.0.1:$SOCKS"
    Write-Host ""

    $keyVol = "idn-proxy-client-keys"
    docker volume create $keyVol 2>&1 | Out-Null
    docker run --rm -v "${keyVol}:/data" $IMAGE `
        identitynet-proxy-client init --key /data/proxy_client.key 2>&1 | Out-Null

    Write-Info "Starting tunnel..."
    Write-Host ""

    docker run --rm `
        --name idn-proxy-client `
        -v "${keyVol}:/data" `
        -p "${SOCKS}:${SOCKS}" `
        $IMAGE `
        identitynet-proxy-client run `
            --key /data/proxy_client.key `
            --pubkey "$PUBKEY" `
            --server-host $VPS_IP `
            --server-port $VPS_PORT `
            --proxy-port $SOCKS

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Err "Connection failed. Check:"
        Write-Host "  ping $VPS_IP"
        Write-Host "  Test-NetConnection $VPS_IP -Port $VPS_PORT"
        Write-Host "  Is identitynet-proxy-server running on VPS?"
    }
}

# ── PROXY TEST ────────────────────────────────────────────────────────────────
function Invoke-ProxyTest {
    $PORT = if ($Arg1) { $Arg1 } else { "1080" }
    Write-Step "Testing SOCKS5 proxy on 127.0.0.1:$PORT"

    $t = Test-NetConnection -ComputerName 127.0.0.1 -Port $PORT -WarningAction SilentlyContinue
    if (-not $t.TcpTestSucceeded) {
        Write-Err "Nothing on port $PORT. Start proxy first."
        return
    }
    Write-Ok "Port $PORT is open"
    Write-Host ""

    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        Write-Info "Checking your IP via proxy..."
        $via  = curl.exe --socks5-hostname "127.0.0.1:$PORT" --max-time 10 --silent https://ifconfig.me
        $real = (Invoke-WebRequest -Uri "https://ifconfig.me" -UseBasicParsing).Content.Trim()
        Write-Host "  Via proxy: $via" -ForegroundColor $(if ($via -ne $real) { "Green" } else { "Yellow" })
        Write-Host "  Direct:    $real" -ForegroundColor Yellow
        if ($via -ne $real) { Write-Ok "Proxy works! Traffic exits from VPS." }
        else                { Write-Warn "Same IP — something may be wrong." }
    } else {
        Write-Info "Test manually: curl --socks5-hostname 127.0.0.1:$PORT https://ifconfig.me"
    }
}

function Show-Help {
    Write-Host ""
    Write-Host " Identity Network — Windows Launcher" -ForegroundColor Cyan
    Write-Host " =====================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " Proxy Quick Start:" -ForegroundColor Yellow
    Write-Host "   1. On VPS:   bash setup_vps.sh  (note the PUBLIC KEY)"
    Write-Host "   2. Windows:  .\run.ps1 build"
    Write-Host "   3. Windows:  .\run.ps1 proxy-client 1.2.3.4 7701 `"<PUBKEY>`""
    Write-Host "   4. Firefox:  Settings > SOCKS5 > 127.0.0.1:1080"
    Write-Host "   5. Verify:   .\run.ps1 proxy-test"
    Write-Host ""
    Write-Host " Commands:" -ForegroundColor Yellow
    Write-Host "   .\run.ps1 build                         Build Docker image"
    Write-Host "   .\run.ps1 demo                          Full demo (4 scenarios)"
    Write-Host "   .\run.ps1 tests                         Run 32 unit tests"
    Write-Host "   .\run.ps1 proxy-client IP PORT PUBKEY   Start SOCKS5 proxy tunnel"
    Write-Host "   .\run.ps1 proxy-test   [PORT]           Verify proxy is working"
    Write-Host "   .\run.ps1 up / down                     Start/stop infrastructure"
    Write-Host "   .\run.ps1 logs [service]                Container logs"
    Write-Host "   .\run.ps1 shell                         bash in container"
    Write-Host ""
}

Assert-Docker
switch ($Command.ToLower()) {
    "build"        { Invoke-Build }
    "demo"         { Invoke-Demo }
    "tests"        { Invoke-Tests }
    "test"         { Invoke-Tests }
    "up"           { Invoke-Up }
    "down"         { Invoke-Down }
    "proxy-client" { Invoke-ProxyClient }
    "proxy-test"   { Invoke-ProxyTest }
    "logs"         { Invoke-Logs }
    "shell"        { Invoke-Shell }
    "bash"         { Invoke-Shell }
    "help"         { Show-Help }
    default        { Write-Err "Unknown: $Command"; Show-Help; exit 1 }
}
