@echo off
REM ============================================
REM DEATH STAR - Firewall Traffic Test Generator
REM ============================================
REM This script requires ADMINISTRATOR PRIVILEGES
REM It will create temporary firewall rules to block test traffic
REM ============================================

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo ERROR: This script requires Administrator privileges!
    echo Please right-click and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo ============================================
echo DEATH STAR - Firewall Traffic Test Generator
echo ============================================
echo.

REM Check if firewall logging is enabled
echo [CHECK] Verifying firewall logging settings...
netsh advfirewall show publicprofile | findstr /C:"LogDroppedConnections" | findstr /C:"Enable" >nul
if %errorLevel% neq 0 (
    echo.
    echo WARNING: Firewall logging may not be enabled!
    echo Please enable "Log dropped packets" in Windows Firewall settings.
    echo.
    echo To enable:
    echo   1. Win+R, type "wf.msc"
    echo   2. Right-click "Windows Defender Firewall"
    echo   3. Properties ^> Public Profile
    echo   4. Logging section ^> Customize
    echo   5. Set "Log dropped packets" to YES
    echo.
    pause
)

REM Show log file status
set LOGFILE=C:\Windows\System32\LogFiles\Firewall\pfirewall.log
echo [CHECK] Firewall log location: %LOGFILE%
if exist "%LOGFILE%" (
    for %%A in ("%LOGFILE%") do echo [CHECK] Current log size: %%~zA bytes
) else (
    echo [CHECK] Log file not found! Logging may be disabled.
)
echo.

echo This will generate REAL blocked firewall entries by:
echo   1. Creating temporary outbound block rules
echo   2. Attempting connections (which get blocked)
echo   3. Cleaning up the rules
echo.
echo Make sure DEATH STAR is running in another window!
echo.
pause
echo.

REM ============================================
REM STEP 1: Create temporary firewall block rules
REM ============================================
echo [SETUP] Creating temporary firewall block rules...

netsh advfirewall firewall add rule name="DEATH_STAR_TEST_SSH" dir=out action=block protocol=TCP remoteport=22 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_RDP" dir=out action=block protocol=TCP remoteport=3389 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_SMB" dir=out action=block protocol=TCP remoteport=445 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_HTTP" dir=out action=block protocol=TCP remoteport=8080 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_MYSQL" dir=out action=block protocol=TCP remoteport=3306 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_TELNET" dir=out action=block protocol=TCP remoteport=23 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_FTP" dir=out action=block protocol=TCP remoteport=21 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_VNC" dir=out action=block protocol=TCP remoteport=5900 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_MSSQL" dir=out action=block protocol=TCP remoteport=1433 >nul
netsh advfirewall firewall add rule name="DEATH_STAR_TEST_MDNS" dir=out action=block protocol=UDP remoteport=5353 >nul

echo [SETUP] Rules created successfully!
echo.

REM ============================================
REM STEP 2: Generate test traffic (gets blocked)
REM ============================================
echo [GENERATING] Creating test traffic...
echo.

echo [1/15] Testing SSH port 22...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('203.0.113.45', 22) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [2/15] Testing RDP port 3389...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('198.51.100.89', 3389) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [3/15] Testing SMB port 445...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('192.0.2.156', 445) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [4/15] Testing HTTP-ALT port 8080...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('203.0.113.100', 8080) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [5/15] Testing MySQL port 3306...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('198.51.100.200', 3306) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [6/15] Testing Telnet port 23...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('192.0.2.50', 23) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [7/15] Testing FTP port 21...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('203.0.113.75', 21) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [8/15] Testing VNC port 5900...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('198.51.100.150', 5900) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [9/15] Testing MSSQL port 1433...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('192.0.2.99', 1433) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [10/15] Testing mDNS UDP port 5353...
powershell -Command "$client = New-Object System.Net.Sockets.UdpClient; try { $client.Connect('203.0.113.25', 5353); $client.Send([byte[]]@(0x00), 1) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

REM Port scan pattern - multiple ports from same IP
echo [11/15] Testing port scan pattern (SSH)...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('45.76.142.23', 22) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [12/15] Testing port scan pattern (Telnet)...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('45.76.142.23', 23) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [13/15] Testing port scan pattern (RDP)...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('45.76.142.23', 3389) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [14/15] Testing port scan pattern (SMB)...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('45.76.142.23', 445) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo [15/15] Testing port scan pattern (MySQL)...
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('45.76.142.23', 3306) } catch {}; $client.Close()" 2>nul
timeout /t 1 /nobreak >nul

echo.
echo [GENERATING] Test traffic generated!
echo.

REM ============================================
REM STEP 3: Clean up firewall rules
REM ============================================
echo [CLEANUP] Removing temporary firewall rules...

netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_SSH" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_RDP" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_SMB" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_HTTP" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_MYSQL" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_TELNET" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_FTP" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_VNC" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_MSSQL" >nul
netsh advfirewall firewall delete rule name="DEATH_STAR_TEST_MDNS" >nul

echo [CLEANUP] Rules removed successfully!
echo.

echo ============================================
echo Test complete!
echo ============================================
echo.

REM Check if log file grew
if exist "%LOGFILE%" (
    for %%A in ("%LOGFILE%") do (
        echo [RESULT] Final log size: %%~zA bytes
        echo [RESULT] Log file location: %LOGFILE%
    )
    echo.
    echo To verify entries were logged, check the last few lines:
    echo   powershell -Command "Get-Content '%LOGFILE%' -Tail 20"
) else (
    echo [RESULT] Log file still not found!
)
echo.

echo Generated blocked traffic for:
echo   - SSH (22), Telnet (23), FTP (21)
echo   - RDP (3389), SMB (445), MySQL (3306)
echo   - VNC (5900), MSSQL (1433), mDNS (5353)
echo   - HTTP-ALT (8080)
echo   - Port scan pattern from 45.76.142.23 (5+ ports)
echo.
echo Check DEATH STAR dashboard for new firewall log entries!
echo Note: Entries may take 5-10 seconds to appear in logs.
echo.
echo If you don't see entries in DEATH STAR:
echo   1. Check log file grew (size above)
echo   2. Windows Firewall logging is enabled for ALL profiles
echo   3. "Log dropped packets" is set to YES
echo   4. DEATH STAR is running with admin privileges
echo   5. Try running in demo mode: DEATH_STAR.exe --demo
echo.
pause
