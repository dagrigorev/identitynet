# ============================================================================
# run.ps1 — Identity Network launcher for Windows (PowerShell)
#
# Prerequisites:
#   Docker Desktop: https://www.docker.com/products/docker-desktop/
#
# Usage:
#   .\run.ps1 build
#   .\run.ps1 demo
#   .\run.ps1 tests
#   .\run.ps1 up
#   .\run.ps1 ping <NODE_ID>
#   .\run.ps1 echo <NODE_ID> "message"
#   .\run.ps1 shell
#   .\run.ps1 down
# ============================================================================

param(
    [Parameter(Position=0)]
    [string]$Command = "help",

    [Parameter(Position=1)]
    [string]$Arg1 = "",

    [Parameter(Position=2)]
    [string]$Arg2 = "Hello from Windows via Identity Network!"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$IMAGE = "identitynet:latest"
$NETWORK = "identitynet_idn-net"

# ── Colored output helpers ─────────────────────────────────────────────────
function Write-Info  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Step  { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Magenta }

# ── Check Docker ───────────────────────────────────────────────────────────
function Assert-Docker {
    try {
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw }
    } catch {
        Write-Err "Docker is not running. Please start Docker Desktop."
        Write-Host "  Download: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
        exit 1
    }
}

# ── Ensure image is built ──────────────────────────────────────────────────
function Assert-Built {
    $exists = docker image inspect $IMAGE 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Image '$IMAGE' not found. Building now..."
        Invoke-Build
    }
}

# ── Build ──────────────────────────────────────────────────────────────────
function Invoke-Build {
    Write-Step "Building Identity Network Docker image"
    Write-Info "Compiling C++20 source inside Ubuntu 24.04 container..."
    Write-Info "This takes ~1-2 minutes on first run."
    Write-Host ""

    docker build --target runtime -t $IMAGE .
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Build failed. Check output above."
        exit 1
    }

    Write-Host ""
    Write-Ok "Build complete. Image: $IMAGE"
    docker image inspect $IMAGE --format "  Size: {{.Size}} bytes  Created: {{.Created}}" 2>$null
}

# ── Demo ───────────────────────────────────────────────────────────────────
function Invoke-Demo {
    Write-Step "Identity Network — Full Demo"
    Write-Info "Running all 4 required scenarios:"
    Write-Host "  1. connect_by_node_id  — resolve via discovery, no IP in API"
    Write-Host "  2. connect_by_pubkey   — MITM-resistant key pinning"
    Write-Host "  3. ACL enforcement     — identity-based allow + deny"
    Write-Host "  4. MITM rejection      — wrong pubkey detected and aborted"
    Write-Host ""

    Assert-Built
    docker run --rm --name idn-demo $IMAGE identitynet-demo
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Ok "Demo completed successfully."
    } else {
        Write-Err "Demo exited with code $LASTEXITCODE"
        exit 1
    }
}

# ── Tests ──────────────────────────────────────────────────────────────────
function Invoke-Tests {
    Write-Step "Identity Network — Test Suite"
    Write-Info "Running 32 unit + integration tests..."
    Write-Host ""

    Assert-Built
    docker run --rm --name idn-tests $IMAGE identitynet-tests
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "All tests passed."
    } else {
        Write-Err "Tests failed."
        exit 1
    }
}

# ── Up ─────────────────────────────────────────────────────────────────────
function Invoke-Up {
    Write-Step "Starting Discovery + Server"
    Assert-Built

    Write-Info "Starting discovery server on :7700..."
    Write-Info "Starting identity server on :7701..."
    Write-Host ""

    docker compose up -d discovery server
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to start services."
        exit 1
    }

    Write-Info "Waiting for services to initialize..."
    Start-Sleep -Seconds 3

    # Show server identity
    Write-Host ""
    Write-Step "Server Identity"
    $keyData = docker exec idn-server cat /data/server.key 2>$null
    if ($keyData) {
        $keyData | Where-Object { $_ -match "node_id|public_key|fingerprint" } | ForEach-Object {
            Write-Host "  $_" -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Ok "Infrastructure running."
    Write-Host "  Discovery server:  localhost:7700" -ForegroundColor Green
    Write-Host "  Identity server:   localhost:7701" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  .\run.ps1 ping <NODE_ID_FROM_ABOVE>"
    Write-Host "  .\run.ps1 echo <NODE_ID> `"hello`""
    Write-Host "  .\run.ps1 down"
}

# ── Down ───────────────────────────────────────────────────────────────────
function Invoke-Down {
    Write-Info "Stopping all Identity Network containers..."
    docker compose down
    Write-Ok "Stopped."
}

# ── Ping ───────────────────────────────────────────────────────────────────
function Invoke-Ping {
    if (-not $Arg1) {
        Write-Err "Usage: .\run.ps1 ping <NODE_ID>"
        Write-Host "  NODE_ID is the 64-char hex shown at server startup."
        Write-Host "  Or run: docker exec idn-server cat /data/server.key"
        exit 1
    }

    Write-Step "PING"
    Write-Info "Connecting to identity: $Arg1"
    Write-Info "No IP address in this command — identity IS the address."
    Write-Host ""

    Assert-Built

    # Ensure the network exists (from docker compose up)
    $netExists = docker network inspect $NETWORK 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Network '$NETWORK' not found. Run '.\run.ps1 up' first,"
        Write-Warn "or using the demo network..."
        $NETWORK = "bridge"
    }

    docker run --rm `
        --network $NETWORK `
        --name idn-ping-client `
        $IMAGE `
        identitynet-client ping `
            --key /tmp/ping.key `
            --discovery discovery:7700 `
            --node $Arg1 `
            --count 4
}

# ── Echo ───────────────────────────────────────────────────────────────────
function Invoke-Echo {
    if (-not $Arg1) {
        Write-Err "Usage: .\run.ps1 echo <NODE_ID> `"message`""
        exit 1
    }

    Write-Step "ECHO"
    Write-Info "Target identity: $Arg1"
    Write-Info "Message: $Arg2"
    Write-Host ""

    Assert-Built

    docker run --rm `
        --network $NETWORK `
        --name idn-echo-client `
        $IMAGE `
        identitynet-client echo `
            --key /tmp/echo.key `
            --discovery discovery:7700 `
            --node $Arg1 `
            --message $Arg2
}

# ── Shell ──────────────────────────────────────────────────────────────────
function Invoke-Shell {
    Write-Step "Interactive Shell"
    Write-Info "Entering container. Available commands:"
    Write-Host "  identitynet-discovery --help"
    Write-Host "  identitynet-server --help"
    Write-Host "  identitynet-client --help"
    Write-Host "  identitynet-demo"
    Write-Host "  identitynet-tests"
    Write-Host ""
    Write-Info "Type 'exit' to leave."
    Write-Host ""

    Assert-Built
    docker run --rm -it --name idn-shell $IMAGE /bin/bash
}

# ── Logs ───────────────────────────────────────────────────────────────────
function Invoke-Logs {
    docker compose logs -f --tail 50
}

# ── Stress ─────────────────────────────────────────────────────────────────
function Invoke-Stress {
    if (-not $Arg1) {
        Write-Err "Usage: .\run.ps1 stress <NODE_ID>"
        exit 1
    }

    Write-Step "Stress Test"
    Write-Info "Target: $Arg1"
    Write-Info "Running 500 connections, 8 threads..."
    Write-Host ""

    Assert-Built
    docker run --rm `
        --network $NETWORK `
        $IMAGE `
        identitynet-client stress `
            --key /tmp/stress.key `
            --discovery discovery:7700 `
            --node $Arg1 `
            --count 500 `
            --threads 8
}

# ── Help ───────────────────────────────────────────────────────────────────
function Show-Help {
    Write-Host ""
    Write-Host " Identity Network — PowerShell Launcher" -ForegroundColor Cyan
    Write-Host " =======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " Prerequisites:" -ForegroundColor Yellow
    Write-Host "   Docker Desktop (running)"
    Write-Host "   https://www.docker.com/products/docker-desktop/"
    Write-Host ""
    Write-Host " Commands:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   .\run.ps1 build              " -NoNewline; Write-Host "Build Docker image" -ForegroundColor Green
    Write-Host "   .\run.ps1 demo               " -NoNewline; Write-Host "Full demo (4 scenarios + stress)" -ForegroundColor Green
    Write-Host "   .\run.ps1 tests              " -NoNewline; Write-Host "Run 32 unit + integration tests" -ForegroundColor Green
    Write-Host "   .\run.ps1 up                 " -NoNewline; Write-Host "Start discovery + server in background" -ForegroundColor Green
    Write-Host "   .\run.ps1 down               " -NoNewline; Write-Host "Stop all containers" -ForegroundColor Green
    Write-Host "   .\run.ps1 ping  <NODE_ID>    " -NoNewline; Write-Host "Ping server by cryptographic identity" -ForegroundColor Green
    Write-Host "   .\run.ps1 echo  <NODE_ID> MSG" -NoNewline; Write-Host "Send echo message" -ForegroundColor Green
    Write-Host "   .\run.ps1 stress <NODE_ID>   " -NoNewline; Write-Host "High-load stress test" -ForegroundColor Green
    Write-Host "   .\run.ps1 shell              " -NoNewline; Write-Host "Interactive bash shell" -ForegroundColor Green
    Write-Host "   .\run.ps1 logs               " -NoNewline; Write-Host "Tail server logs" -ForegroundColor Green
    Write-Host ""
    Write-Host " Quick start (fastest):" -ForegroundColor Yellow
    Write-Host "   .\run.ps1 build"
    Write-Host "   .\run.ps1 demo"
    Write-Host ""
    Write-Host " Full workflow:" -ForegroundColor Yellow
    Write-Host "   .\run.ps1 build"
    Write-Host "   .\run.ps1 up"
    Write-Host "   # Note the NODE_ID printed above"
    Write-Host "   .\run.ps1 ping  <NODE_ID>"
    Write-Host "   .\run.ps1 echo  <NODE_ID> `"hello from Windows`""
    Write-Host "   .\run.ps1 stress <NODE_ID>"
    Write-Host "   .\run.ps1 down"
    Write-Host ""
    Write-Host " Note: IP addresses are NEVER used as identifiers." -ForegroundColor DarkGray
    Write-Host "       Identity IS the address. IP is only a carrier." -ForegroundColor DarkGray
    Write-Host ""
}

# ── Main dispatch ──────────────────────────────────────────────────────────
Assert-Docker

switch ($Command.ToLower()) {
    "build"      { Invoke-Build }
    "demo"       { Invoke-Demo }
    "tests"      { Invoke-Tests }
    "test"       { Invoke-Tests }
    "up"         { Invoke-Up }
    "down"       { Invoke-Down }
    "ping"       { Invoke-Ping }
    "echo"       { Invoke-Echo }
    "shell"      { Invoke-Shell }
    "bash"       { Invoke-Shell }
    "logs"       { Invoke-Logs }
    "stress"     { Invoke-Stress }
    "help"       { Show-Help }
    default      { Write-Err "Unknown command: $Command"; Show-Help; exit 1 }
}
