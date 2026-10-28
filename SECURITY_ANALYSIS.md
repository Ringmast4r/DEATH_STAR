# Security Analysis: DEATH STAR dashboard.py

## Executive Summary

This analysis identifies **12 security concerns** ranging from **HIGH** to **LOW** severity. While the application is designed for defensive security monitoring, several vulnerabilities could be exploited by malicious actors or lead to unintended data exposure.

---

## 🔴 HIGH SEVERITY ISSUES

### 1. **Path Traversal Vulnerability in `--log-path` Argument** (CWE-22)
**Location:** Lines 193, 2307-2308, 519

**Issue:**
```python
# Line 193: No validation of user-provided log_path
self.log_path = log_path or self._get_default_log_path()

# Line 2307-2308: User can specify arbitrary path
parser.add_argument("--log-path", type=str, default=None,
                    help="Custom firewall log file path...")

# Line 519: File opened without path validation
with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
```

**Risk:**
- Attacker can read arbitrary files: `--log-path ../../../etc/passwd`
- Attacker can read sensitive files: `--log-path C:\Windows\System32\config\SAM`
- No path normalization or validation

**Impact:** HIGH - Unauthorized file access, information disclosure

**Recommendation:**
```python
from pathlib import Path
import os.path

def _validate_log_path(self, log_path):
    """Validate and normalize log path"""
    if not log_path:
        return self._get_default_log_path()
    
    # Normalize path
    path = Path(log_path).resolve()
    
    # Whitelist allowed directories
    allowed_dirs = [
        Path(r"C:\Windows\System32\LogFiles\Firewall"),
        Path("/var/log"),
    ]
    
    # Check if path is within allowed directories
    for allowed in allowed_dirs:
        try:
            path.relative_to(allowed)
            return str(path)
        except ValueError:
            continue
    
    # If not in whitelist, use default
    return self._get_default_log_path()
```

---

### 2. **CSV Injection Vulnerability** (CWE-1236)
**Location:** Lines 248-263

**Issue:**
```python
# Line 248-263: User-controlled data written to CSV without sanitization
writer.writerow([
    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    getattr(conn, 'ip', 'Unknown'),           # ⚠️ User-controlled
    getattr(conn, 'dst_ip', 'Unknown'),      # ⚠️ User-controlled
    getattr(conn, 'port', 'Unknown'),         # ⚠️ User-controlled
    getattr(conn, 'protocol', 'Unknown'),     # ⚠️ User-controlled
    getattr(conn, 'service', 'Unknown'),      # ⚠️ User-controlled
    getattr(conn, 'country', '??'),           # ⚠️ User-controlled
    getattr(conn, 'city', 'Unknown'),         # ⚠️ User-controlled
    getattr(conn, 'isp', 'Unknown'),          # ⚠️ User-controlled
    getattr(conn, 'threat', 'UNKNOWN'),       # ⚠️ User-controlled
    getattr(conn, 'attack_type', 'PROBE'),    # ⚠️ User-controlled
    getattr(conn, 'action', 'DROP')           # ⚠️ User-controlled
])
```

**Risk:**
- Malicious firewall log entries can inject formulas: `=cmd|'/c calc'!A0`
- When CSV is opened in Excel, formulas execute automatically
- Can lead to remote code execution if Excel opens the CSV

**Impact:** HIGH - Remote code execution via Excel formula injection

**Recommendation:**
```python
def _sanitize_csv_value(self, value):
    """Sanitize CSV values to prevent formula injection"""
    if not isinstance(value, str):
        value = str(value)
    
    # Prefix dangerous characters with tab
    if value.startswith(('=', '+', '-', '@', '\t', '\r')):
        return "'" + value
    return value

# In _log_attack:
writer.writerow([
    self._sanitize_csv_value(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    self._sanitize_csv_value(getattr(conn, 'ip', 'Unknown')),
    # ... sanitize all values
])
```

---

### 3. **HTTP Request Injection / SSRF Risk** (CWE-918)
**Location:** Lines 117-168

**Issue:**
```python
# Line 140: IP address directly inserted into URL without validation
url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
```

**Risk:**
- Malicious IP addresses can inject query parameters: `127.0.0.1?evil=param`
- Could potentially be used for SSRF if internal services are exposed
- No validation of IP format before API call

**Impact:** MEDIUM-HIGH - Potential SSRF, request manipulation

**Recommendation:**
```python
import ipaddress
import re

def _validate_ip(self, ip):
    """Validate IP address format"""
    # Remove any query parameters or path traversal attempts
    ip = ip.split('?')[0].split('/')[0].split('#')[0].strip()
    
    try:
        # Validate IPv4
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        try:
            # Validate IPv6
            ipaddress.IPv6Address(ip)
            return ip
        except ValueError:
            return None

# In get_geolocation:
validated_ip = self._validate_ip(ip)
if not validated_ip:
    return self._get_fallback_geo_data()
    
url = f"http://ip-api.com/json/{validated_ip}?fields=status,country,countryCode,city,isp,org,as"
```

---

## 🟡 MEDIUM SEVERITY ISSUES

### 4. **Unvalidated Subprocess Execution** (CWE-78)
**Location:** Lines 739, 789, 802, 817, 828, 854, 911, 925, 957, 966

**Issue:**
```python
# Multiple subprocess.run() calls with hardcoded commands
result = subprocess.run(['wmic', 'os', 'get', 'BuildNumber'], ...)
result = subprocess.run(['dmidecode', '-t', '2'], ...)
result = subprocess.run(['xrandr'], ...)
```

**Risk:**
- Commands are hardcoded (good), but no validation of output
- If environment is compromised, PATH manipulation could execute malicious binaries
- No timeout on some subprocess calls (though most have timeout=2)

**Impact:** MEDIUM - Potential command injection if PATH is compromised

**Recommendation:**
```python
import shutil

def _safe_subprocess(self, cmd, timeout=2):
    """Execute subprocess with full path validation"""
    if not cmd:
        return None
    
    # Use full paths for system commands
    cmd_map = {
        'wmic': r'C:\Windows\System32\wbem\wmic.exe',
        'dmidecode': '/usr/sbin/dmidecode',
        'xrandr': '/usr/bin/xrandr',
    }
    
    # Replace command with full path if available
    if cmd[0] in cmd_map:
        full_path = cmd_map[cmd[0]]
        if os.path.exists(full_path):
            cmd[0] = full_path
        else:
            # Fallback: use which/shardutil to find command
            cmd_path = shutil.which(cmd[0])
            if cmd_path:
                cmd[0] = cmd_path
            else:
                return None  # Command not found
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
```

---

### 5. **Information Disclosure via System Info** (CWE-200)
**Location:** Lines 726-1002, 1999-2009

**Issue:**
```python
# Line 2003-2005: MAC address extraction
mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                for elements in range(0,2*6,2)][::-1])

# Line 2012-2013: System information displayed
info_keys = ['System IP', 'MAC Addr', 'OS', 'Kernel', 'Architecture', 'BIOS', 
             'Host', 'Network', 'Terminal', 'Resolution', 'Motherboard', 'CPU', ...]
```

**Risk:**
- MAC address can be used for device tracking
- System information could reveal security posture
- No option to mask sensitive information in non-demo mode

**Impact:** MEDIUM - Privacy concerns, device fingerprinting

**Recommendation:**
- Add `--privacy-mode` flag to mask sensitive information
- Optionally hash MAC addresses
- Allow users to disable system info collection

---

### 6. **Unbounded Log File Reading** (CWE-400)
**Location:** Lines 513-538

**Issue:**
```python
# Line 519-535: Reads entire log file without size limits
with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
    f.seek(0, 2)  # Go to end
    while self.running:
        line = f.readline()
        if line:
            # Process line
```

**Risk:**
- If log file is extremely large, memory could be exhausted
- No maximum file size check
- No rate limiting on log processing

**Impact:** MEDIUM - Denial of service via resource exhaustion

**Recommendation:**
```python
MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

def tail_file(self):
    try:
        if not os.path.exists(self.log_path):
            return
        
        # Check file size
        file_size = os.path.getsize(self.log_path)
        if file_size > MAX_LOG_FILE_SIZE:
            # Only read from end if file is too large
            with open(self.log_path, 'rb') as f:
                f.seek(max(0, file_size - MAX_LOG_FILE_SIZE))
                f.readline()  # Skip partial line
                # Continue from here
        
        # ... rest of tail_file logic
```

---

### 7. **Insecure HTTP Connection** (CWE-319)
**Location:** Line 140

**Issue:**
```python
# Line 140: Uses HTTP instead of HTTPS
url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
```

**Risk:**
- Man-in-the-middle attacks possible
- Geolocation data could be intercepted/modified
- No certificate validation

**Impact:** MEDIUM - Data interception, tampering

**Recommendation:**
```python
# Use HTTPS
url = f"https://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
```

---

### 8. **Race Condition in Log File Rotation** (CWE-362)
**Location:** Lines 234-266

**Issue:**
```python
# Line 241-244: Check and rotation not atomic
today = datetime.now().strftime("%Y-%m-%d")
expected_file = self.log_dir / f"attacks_{today}.csv"
if expected_file != self.current_log_file:
    self._setup_logging()  # Could be called by multiple threads
```

**Risk:**
- Multiple threads could create duplicate log files
- File handles could be opened/closed incorrectly
- Data loss possible during rotation

**Impact:** MEDIUM - Data integrity issues

**Recommendation:**
```python
def _log_attack(self, conn):
    if not self.enable_logging:
        return
    
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        expected_file = self.log_dir / f"attacks_{today}.csv"
        
        # Atomic check and update
        with self.csv_lock:
            if expected_file != self.current_log_file:
                self._setup_logging()
            
            # Ensure file exists
            if not self.current_log_file.exists():
                self._setup_logging()
            
            # Write with lock held
            with open(self.current_log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([...])
    except Exception as e:
        # Log error instead of silently failing
        pass
```

---

## 🟢 LOW SEVERITY ISSUES

### 9. **Weak IP Validation** (CWE-20)
**Location:** Lines 126-127

**Issue:**
```python
# Line 126-127: Simple string prefix check for private IPs
if ip.startswith(('10.', '192.168.', '172.16.', '127.', 'localhost',
                  'fe80:', '::1', 'fc00:', 'fd00:')):
```

**Risk:**
- Doesn't validate full IP format
- Could miss edge cases (e.g., `10.0.0.0.1` would match `10.`)
- IPv6 validation is incomplete

**Impact:** LOW - Minor validation issues

**Recommendation:**
```python
import ipaddress

def _is_private_ip(self, ip):
    """Check if IP is private using ipaddress library"""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
```

---

### 10. **Silent Exception Handling** (CWE-703)
**Location:** Multiple locations (Lines 158, 264, 266, 536-538)

**Issue:**
```python
# Line 158, 264, 266, 536-538: Exceptions silently swallowed
except Exception as e:
    pass  # Silently fail
```

**Risk:**
- Errors are hidden, making debugging difficult
- Security issues could go unnoticed
- No logging of failures

**Impact:** LOW - Debugging and monitoring issues

**Recommendation:**
```python
import logging

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='death_star.log'
)

try:
    # ... code
except Exception as e:
    logging.warning(f"Error in {function_name}: {e}", exc_info=True)
    # Still fail gracefully, but log it
```

---

### 11. **No Input Rate Limiting** (CWE-307)
**Location:** Lines 117-168

**Issue:**
```python
# Line 117-168: No rate limiting on geolocation API calls
def get_geolocation(self, ip):
    # Cache helps, but no explicit rate limiting
```

**Risk:**
- Could exceed ip-api.com rate limits (45 req/min)
- No backoff strategy
- Could be used for DoS against API

**Impact:** LOW - Service availability

**Recommendation:**
```python
import time
from collections import deque

class IPIntelligence:
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 3600
        self.request_times = deque(maxlen=45)  # Track last 45 requests
        self.min_request_interval = 1.34  # 60 seconds / 45 requests
    
    def get_geolocation(self, ip):
        # ... cache check ...
        
        # Rate limiting
        now = time.time()
        if self.request_times:
            time_since_last = now - self.request_times[-1]
            if time_since_last < self.min_request_interval:
                time.sleep(self.min_request_interval - time_since_last)
        
        self.request_times.append(time.time())
        # ... make API call ...
```

---

### 12. **Weak Cache Implementation** (CWE-400)
**Location:** Lines 114-115

**Issue:**
```python
# Line 114-115: In-memory cache with no size limits
self.cache = {}  # Could grow unbounded
```

**Risk:**
- Memory exhaustion if many unique IPs are processed
- No cache eviction policy
- No maximum cache size

**Impact:** LOW - Resource exhaustion

**Recommendation:**
```python
from collections import OrderedDict

class IPIntelligence:
    def __init__(self, max_cache_size=10000):
        self.cache = OrderedDict()
        self.max_cache_size = max_cache_size
        self.cache_ttl = 3600
    
    def _evict_old_entries(self):
        """Evict expired or oldest entries"""
        now = time.time()
        expired = [ip for ip, data in self.cache.items() 
                   if now - data.get('timestamp', 0) > self.cache_ttl]
        for ip in expired:
            del self.cache[ip]
        
        # Evict oldest if still over limit
        while len(self.cache) > self.max_cache_size:
            self.cache.popitem(last=False)  # Remove oldest
```

---

## Additional Security Recommendations

### 1. **Add Input Validation Layer**
Create a centralized input validation module for all user inputs.

### 2. **Implement Logging**
Add proper logging instead of silent exception handling.

### 3. **Add Configuration File**
Move hardcoded values (API endpoints, timeouts, limits) to configuration.

### 4. **Security Headers**
If adding web interface, implement proper security headers.

### 5. **Dependency Scanning**
Regularly scan dependencies for known vulnerabilities.

### 6. **Code Signing**
For Windows executable, use proper code signing certificate (not self-signed).

### 7. **Privilege Separation**
Consider running with minimal privileges instead of requiring admin/sudo.

---

## Summary

| Severity | Count | Issues |
|----------|-------|--------|
| 🔴 HIGH | 3 | Path traversal, CSV injection, HTTP injection |
| 🟡 MEDIUM | 5 | Subprocess execution, Info disclosure, Unbounded reads, HTTP, Race conditions |
| 🟢 LOW | 4 | Weak validation, Silent exceptions, Rate limiting, Cache limits |

**Total Issues:** 12

**Priority Fixes:**
1. Path traversal in `--log-path` argument
2. CSV injection in log file writing
3. HTTP request injection in geolocation API

---

## Testing Recommendations

1. **Fuzz Testing:** Test `--log-path` with various path traversal payloads
2. **CSV Injection Testing:** Create malicious firewall log entries with formula injection
3. **Rate Limiting:** Test geolocation API with rapid requests
4. **File Size Limits:** Test with extremely large log files
5. **Concurrent Access:** Test log file rotation with multiple threads

---

*Analysis Date: 2025-01-XX*
*Analyzer: Security Review*
*Version Analyzed: 1.6.4*
