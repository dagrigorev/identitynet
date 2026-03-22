@echo off
REM ============================================================================
REM run.bat — Identity Network launcher for Windows (CMD)
REM
REM Prerequisites:
REM   Docker Desktop installed and running
REM   https://www.docker.com/products/docker-desktop/
REM
REM Usage:
REM   run.bat build          Build the Docker image
REM   run.bat demo           Run full demo (all 4 scenarios)
REM   run.bat tests          Run test suite (32 tests)
REM   run.bat up             Start discovery + server in background
REM   run.bat down           Stop all containers
REM   run.bat ping NODE_ID   Ping a server by NodeId
REM   run.bat echo NODE_ID MSG  Echo a message
REM   run.bat shell          Open interactive shell in container
REM   run.bat logs           Show server logs
REM ============================================================================

setlocal EnableDelayedExpansion

set IMAGE=identitynet:latest
set COMPOSE_FILE=docker-compose.yml

REM ── Check Docker is available ──────────────────────────────────────────────
docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop.
    echo         Download: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

REM ── Parse command ──────────────────────────────────────────────────────────
if "%1"=="" goto :help
if "%1"=="help" goto :help
if "%1"=="build" goto :build
if "%1"=="demo" goto :demo
if "%1"=="tests" goto :tests
if "%1"=="up" goto :up
if "%1"=="down" goto :down
if "%1"=="ping" goto :ping
if "%1"=="echo" goto :echo_cmd
if "%1"=="shell" goto :shell
if "%1"=="logs" goto :logs
if "%1"=="init-server" goto :init_server
if "%1"=="init-client" goto :init_client
goto :help

REM ── Build ──────────────────────────────────────────────────────────────────
:build
echo [*] Building Identity Network Docker image...
echo [*] This compiles C++20 source inside the container.
echo.
docker build --target runtime -t %IMAGE% .
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed.
    exit /b 1
)
echo.
echo [OK] Build complete. Image: %IMAGE%
goto :end

REM ── Demo ───────────────────────────────────────────────────────────────────
:demo
echo [*] Running full Identity Network demo...
echo [*] Demonstrates all 4 scenarios:
echo     1. connect_by_node_id  (discovery resolution)
echo     2. connect_by_pubkey   (MITM-resistant pinning)
echo     3. ACL enforcement     (allow + deny)
echo     4. MITM rejection      (wrong pubkey pinned)
echo.
call :ensure_built
docker run --rm --name idn-demo %IMAGE% identitynet-demo
goto :end

REM ── Tests ──────────────────────────────────────────────────────────────────
:tests
echo [*] Running Identity Network test suite (32 tests)...
echo.
call :ensure_built
docker run --rm --name idn-tests %IMAGE% identitynet-tests
goto :end

REM ── Up (start infrastructure) ─────────────────────────────────────────────
:up
echo [*] Starting Discovery + Server in background...
call :ensure_built
docker compose --profile "" up -d discovery server
echo.
echo [*] Waiting for services to be ready...
timeout /t 3 /nobreak >nul

REM Get server NodeId
echo [*] Server identity:
docker exec idn-server cat /data/server.key 2>nul | findstr "node_id"
echo.
echo [OK] Infrastructure running.
echo      Discovery: localhost:7700
echo      Server:    localhost:7701
echo.
echo To connect:
echo   run.bat ping ^<NODE_ID^>
echo   run.bat echo ^<NODE_ID^> "your message"
echo.
echo To stop: run.bat down
goto :end

REM ── Down ───────────────────────────────────────────────────────────────────
:down
echo [*] Stopping all Identity Network containers...
docker compose down
echo [OK] Stopped.
goto :end

REM ── Ping ───────────────────────────────────────────────────────────────────
:ping
if "%2"=="" (
    echo Usage: run.bat ping ^<NODE_ID^>
    echo.
    echo The NODE_ID is the 64-char hex shown when server starts.
    echo Or get it from: docker exec idn-server cat /data/server.key
    exit /b 1
)
echo [*] Pinging identity: %2
docker run --rm --network idn-net %IMAGE% ^
    identitynet-client ping ^
    --key /tmp/ping_client.key ^
    --discovery discovery:7700 ^
    --node %2 ^
    --count 4
goto :end

REM ── Echo ───────────────────────────────────────────────────────────────────
:echo_cmd
if "%2"=="" (
    echo Usage: run.bat echo ^<NODE_ID^> "message"
    exit /b 1
)
set MSG=%3
if "%MSG%"=="" set MSG=Hello from Windows!
echo [*] Sending echo to: %2
echo [*] Message: %MSG%
docker run --rm --network idn-net %IMAGE% ^
    identitynet-client echo ^
    --key /tmp/echo_client.key ^
    --discovery discovery:7700 ^
    --node %2 ^
    --message "%MSG%"
goto :end

REM ── Shell ──────────────────────────────────────────────────────────────────
:shell
echo [*] Opening interactive shell in Identity Network container...
echo     Type 'exit' to leave.
echo.
call :ensure_built
docker run --rm -it --network idn-net --name idn-shell %IMAGE% /bin/bash
goto :end

REM ── Logs ───────────────────────────────────────────────────────────────────
:logs
docker compose logs -f --tail=50
goto :end

REM ── Init server (generate identity) ───────────────────────────────────────
:init_server
echo [*] Generating server identity...
docker run --rm -v idn-server-keys:/data %IMAGE% ^
    identitynet-server init --key /data/server.key
goto :end

REM ── Init client (generate identity) ───────────────────────────────────────
:init_client
echo [*] Generating client identity...
docker run --rm -v idn-client-keys:/data %IMAGE% ^
    identitynet-client init --key /data/client.key
docker run --rm -v idn-client-keys:/data %IMAGE% ^
    identitynet-client show --key /data/client.key
goto :end

REM ── Helper: ensure image is built ─────────────────────────────────────────
:ensure_built
docker image inspect %IMAGE% >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [*] Image not found. Building first...
    call :build
)
goto :eof

REM ── Help ───────────────────────────────────────────────────────────────────
:help
echo.
echo  Identity Network — Windows Launcher
echo  =====================================
echo.
echo  Prerequisites: Docker Desktop (https://www.docker.com/products/docker-desktop/)
echo.
echo  Commands:
echo.
echo    run.bat build              Build Docker image (do this first)
echo    run.bat demo               Full demo: 4 scenarios + stress test
echo    run.bat tests              Run 32 unit + integration tests
echo    run.bat up                 Start discovery + server (background)
echo    run.bat down               Stop all containers
echo    run.bat ping ^<NODE_ID^>     Ping server by cryptographic identity
echo    run.bat echo ^<NODE_ID^> MSG  Echo message to server
echo    run.bat shell              Interactive bash shell in container
echo    run.bat logs               Tail server logs
echo    run.bat init-server        Generate/show server identity
echo    run.bat init-client        Generate/show client identity
echo.
echo  Quick start:
echo    run.bat build
echo    run.bat demo
echo.
echo  Full workflow:
echo    run.bat build
echo    run.bat up
echo    run.bat init-server        ^<-- note the NODE_ID
echo    run.bat ping ^<NODE_ID^>
echo    run.bat echo ^<NODE_ID^> "hello"
echo    run.bat down
echo.

:end
endlocal
