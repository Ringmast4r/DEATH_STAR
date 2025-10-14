#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEATH STAR - Real-time Network Attack Visualization
Spinning 3D ASCII Globe with Neofetch-style System Info
"""

import os
import sys
import time
import math
import threading
import platform
import json
import urllib.request
import urllib.error
import csv
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path

# Check for required dependencies with helpful install instructions
try:
    import psutil
except ImportError:
    print("\n❌ ERROR: Missing required module 'psutil'")
    print("\n📦 INSTALL INSTRUCTIONS:\n")

    # Detect OS and provide specific instructions
    if sys.platform == 'linux':
        # Check if it's Kali/Debian-based or other Linux
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                if 'kali' in os_info or 'debian' in os_info or 'ubuntu' in os_info:
                    print("  Option 1 (Recommended - via apt):")
                    print("    sudo apt install python3-psutil python3-blessed")
                    print("\n  Option 2 (via pip with override):")
                    print("    pip3 install psutil blessed --break-system-packages")
                else:
                    print("  sudo pip3 install psutil blessed")
        except:
            print("  sudo pip3 install psutil blessed")
    elif sys.platform == 'win32':
        print("  pip install psutil blessed")
    else:  # macOS
        print("  pip3 install psutil blessed")

    print("\n  Or install from requirements.txt:")
    print("    pip3 install -r requirements.txt --break-system-packages")
    print("\n")
    sys.exit(1)

try:
    from blessed import Terminal
except ImportError:
    print("\n❌ ERROR: Missing required module 'blessed'")
    print("\n📦 INSTALL INSTRUCTIONS:\n")

    if sys.platform == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                if 'kali' in os_info or 'debian' in os_info or 'ubuntu' in os_info:
                    print("  Option 1 (Recommended - via apt):")
                    print("    sudo apt install python3-blessed python3-psutil")
                    print("\n  Option 2 (via pip with override):")
                    print("    pip3 install blessed psutil --break-system-packages")
                else:
                    print("  sudo pip3 install blessed psutil")
        except:
            print("  sudo pip3 install blessed psutil")
    elif sys.platform == 'win32':
        print("  pip install blessed psutil")
    else:
        print("  pip3 install blessed psutil")

    print("\n  Or install from requirements.txt:")
    print("    pip3 install -r requirements.txt --break-system-packages")
    print("\n")
    sys.exit(1)

# Enable Windows VT100 terminal for RGB colors and UTF-8
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ANSI escape code processing
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        # Set UTF-8 output encoding
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

# Version follows Semantic Versioning (SemVer): MAJOR.MINOR.PATCH
# MAJOR: Breaking changes, MINOR: New features, PATCH: Bug fixes
VERSION = "1.6.4"

def rgb(r, g, b):
    """Create RGB color escape code"""
    return f'\033[38;2;{r};{g};{b}m'

def rgb_bg(r, g, b):
    """Create RGB background color escape code"""
    return f'\033[48;2;{r};{g};{b}m'

RESET = '\033[0m'


class IPIntelligence:
    """IP Geolocation and Threat Intelligence"""

    def __init__(self):
        self.cache = {}  # {ip: {geo_data, threat_data, timestamp}}
        self.cache_ttl = 3600  # 1 hour cache

    def get_geolocation(self, ip):
        """Get geolocation for IP address using ip-api.com (free, no key needed)"""
        # Check cache first
        if ip in self.cache:
            cached = self.cache[ip]
            if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                return cached.get('geo')

        # Skip local/private IPs (IPv4 and IPv6)
        if ip.startswith(('10.', '192.168.', '172.16.', '127.', 'localhost',
                          'fe80:', '::1', 'fc00:', 'fd00:')):
            geo_data = {
                'country': 'LOCAL',
                'countryCode': 'LO',
                'city': 'Private Network',
                'isp': 'Local Network',
                'threat': 'SAFE'
            }
            self.cache[ip] = {'geo': geo_data, 'timestamp': time.time()}
            return geo_data

        try:
            # ip-api.com free tier: 45 requests/minute
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={'User-Agent': 'DEATH-STAR/1.0'})

            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())

                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country', 'Unknown'),
                        'countryCode': data.get('countryCode', '??'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', ''),
                        'as': data.get('as', ''),
                        'threat': self._assess_threat(data)
                    }
                    self.cache[ip] = {'geo': geo_data, 'timestamp': time.time()}
                    return geo_data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            pass

        # Fallback
        return {
            'country': 'Unknown',
            'countryCode': '??',
            'city': 'Unknown',
            'isp': 'Unknown',
            'threat': 'UNKNOWN'
        }

    def _assess_threat(self, geo_data):
        """Basic threat assessment based on ISP/Org"""
        org = geo_data.get('org', '').lower()
        isp = geo_data.get('isp', '').lower()

        # Cloud providers (common for scanners/bots)
        if any(x in org or x in isp for x in ['amazon', 'aws', 'google cloud', 'azure', 'digitalocean', 'ovh', 'hetzner']):
            return 'CLOUD'

        # Hosting providers (often used by malicious actors)
        if any(x in org or x in isp for x in ['hosting', 'server', 'datacenter', 'vps', 'dedicated']):
            return 'HOSTING'

        # Residential/ISP (less likely to be malicious)
        if any(x in isp for x in ['telecom', 'comcast', 'verizon', 'att', 'broadband', 'cable']):
            return 'ISP'

        return 'UNKNOWN'


class FirewallLogParser:
    """Parse firewall logs and detect port scans"""

    def __init__(self, log_path=None, demo_mode=False, enable_logging=True):
        self.platform = sys.platform
        self.log_path = log_path or self._get_default_log_path()
        self.ip_tracking = {}  # {ip: [(port, timestamp), ...]}
        self.scan_threshold = 5  # ports within time window
        self.time_window = 60  # seconds
        self.running = False
        self.connections = deque(maxlen=20)
        self.demo_mode = demo_mode
        self.ip_intel = IPIntelligence()

        # Attack logging to CSV
        self.enable_logging = enable_logging
        self.log_dir = Path("logs")
        self.csv_lock = threading.Lock()
        if self.enable_logging:
            self._setup_logging()

    def _setup_logging(self):
        """Setup CSV logging directory and today's log file"""
        try:
            # Create logs directory if it doesn't exist
            self.log_dir.mkdir(exist_ok=True)

            # Generate today's log filename
            today = datetime.now().strftime("%Y-%m-%d")
            self.current_log_file = self.log_dir / f"attacks_{today}.csv"

            # Create CSV with headers if it doesn't exist
            if not self.current_log_file.exists():
                with open(self.current_log_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'Timestamp', 'Source_IP', 'Dest_IP', 'Port', 'Protocol',
                        'Service', 'Country', 'City', 'ISP', 'Threat_Level',
                        'Attack_Type', 'Action'
                    ])
        except Exception as e:
            print(f"Warning: Could not setup logging: {e}")
            self.enable_logging = False

    def _log_attack(self, conn):
        """Log attack/connection to CSV file"""
        if not self.enable_logging:
            return

        try:
            # Check if we need to rotate to new day's file
            today = datetime.now().strftime("%Y-%m-%d")
            expected_file = self.log_dir / f"attacks_{today}.csv"
            if expected_file != self.current_log_file:
                self._setup_logging()

            # Thread-safe write to CSV
            with self.csv_lock:
                with open(self.current_log_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        getattr(conn, 'ip', 'Unknown'),
                        getattr(conn, 'dst_ip', 'Unknown'),
                        getattr(conn, 'port', 'Unknown'),
                        getattr(conn, 'protocol', 'Unknown'),
                        getattr(conn, 'service', 'Unknown'),
                        getattr(conn, 'country', '??'),
                        getattr(conn, 'city', 'Unknown'),
                        getattr(conn, 'isp', 'Unknown'),
                        getattr(conn, 'threat', 'UNKNOWN'),
                        getattr(conn, 'attack_type', 'PROBE'),
                        getattr(conn, 'action', 'DROP')
                    ])
        except Exception as e:
            # Silently fail to avoid disrupting dashboard
            pass

    def _get_default_log_path(self):
        """Get default firewall log path for platform"""
        if self.platform == 'win32':
            return r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        else:
            # Try UFW first, then iptables
            ufw_log = "/var/log/ufw.log"
            iptables_log = "/var/log/kern.log"
            if os.path.exists(ufw_log):
                return ufw_log
            return iptables_log

    def parse_windows_log_line(self, line):
        """Parse Windows firewall log format"""
        # Skip header lines
        if line.startswith('#') or not line.strip():
            return None

        try:
            # Format: date time action protocol src-ip dst-ip src-port dst-port size flags ...
            parts = line.split()
            if len(parts) < 8:
                return None

            return {
                'timestamp': f"{parts[0]} {parts[1]}",
                'action': parts[2],
                'protocol': parts[3],
                'src_ip': parts[4],
                'dst_ip': parts[5],
                'src_port': parts[6],
                'dst_port': parts[7]
            }
        except:
            return None

    def parse_linux_log_line(self, line):
        """Parse Linux UFW/iptables log format"""
        try:
            # UFW format: [timestamp] [UFW BLOCK] IN=... SRC=... DST=... PROTO=... DPT=...
            if 'UFW' in line and 'BLOCK' in line:
                entry = {}
                # Extract SRC IP
                if 'SRC=' in line:
                    src_start = line.index('SRC=') + 4
                    src_end = line.index(' ', src_start)
                    entry['src_ip'] = line[src_start:src_end]

                # Extract DST port
                if 'DPT=' in line:
                    dpt_start = line.index('DPT=') + 4
                    dpt_end = line.find(' ', dpt_start)
                    if dpt_end == -1:
                        dpt_end = len(line)
                    entry['dst_port'] = line[dpt_start:dpt_end]

                # Extract protocol
                if 'PROTO=' in line:
                    proto_start = line.index('PROTO=') + 6
                    proto_end = line.index(' ', proto_start)
                    entry['protocol'] = line[proto_start:proto_end]

                entry['action'] = 'DROP'
                entry['timestamp'] = line.split()[0:3]  # Syslog timestamp
                return entry
        except:
            pass
        return None

    def detect_scan(self, src_ip):
        """Detect if IP is performing a port scan"""
        current_time = time.time()

        # Clean old entries
        if src_ip in self.ip_tracking:
            self.ip_tracking[src_ip] = [
                (port, ts) for port, ts in self.ip_tracking[src_ip]
                if current_time - ts < self.time_window
            ]

            # Check if threshold exceeded
            unique_ports = set(port for port, ts in self.ip_tracking[src_ip])
            if len(unique_ports) >= self.scan_threshold:
                return True, list(unique_ports)
        return False, []

    def add_entry(self, entry):
        """Track entry and detect scans"""
        if not entry or entry['action'] != 'DROP':
            return

        src_ip = entry['src_ip']
        dst_port = entry['dst_port']
        current_time = time.time()

        # Track this attempt
        if src_ip not in self.ip_tracking:
            self.ip_tracking[src_ip] = []
        self.ip_tracking[src_ip].append((dst_port, current_time))

        # Check for scan
        is_scan, ports = self.detect_scan(src_ip)

        # Create connection object
        Connection = type('Connection', (), {})
        conn = Connection()
        conn.ip = src_ip
        conn.dst_ip = entry.get('dst_ip', 'Unknown')  # Destination IP
        conn.port = dst_port
        conn.protocol = entry.get('protocol', 'TCP')
        conn.timestamp = entry.get('timestamp', '')
        conn.action = entry.get('action', 'DROP')  # ALLOW or DROP

        # Count occurrences from this IP
        conn.count = len([c for c in self.connections if hasattr(c, 'ip') and c.ip == src_ip]) + 1

        # Known port detection
        port_names = {
            '22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '21': 'FTP',
            '23': 'Telnet', '25': 'SMTP', '3306': 'MySQL', '3389': 'RDP',
            '445': 'SMB', '1433': 'MSSQL', '5900': 'VNC', '8080': 'HTTP-ALT',
            '137': 'NetBIOS', '138': 'NetBIOS', '139': 'NetBIOS'
        }
        conn.service = port_names.get(dst_port, f'Port {dst_port}')

        # Determine attack type for display
        if is_scan:
            conn.attack_type = f"SCAN ({len(ports)}p)"
        else:
            conn.attack_type = "PROBE"

        # Get geolocation and threat intel (non-blocking, cached)
        geo_data = self.ip_intel.get_geolocation(src_ip)
        conn.country = geo_data.get('countryCode', '??')
        conn.country_full = geo_data.get('country', 'Unknown')
        conn.city = geo_data.get('city', 'Unknown')
        conn.isp = geo_data.get('isp', 'Unknown')
        conn.threat = geo_data.get('threat', 'UNKNOWN')

        self.connections.append(conn)

        # Log attack to CSV file
        self._log_attack(conn)

    def generate_demo_traffic(self):
        """Generate simulated firewall log entries for demo/testing"""
        import random

        demo_ips = [
            '203.0.113.45',    # Example IPs (TEST-NET-3)
            '198.51.100.89',   # (TEST-NET-2)
            '192.0.2.156',     # (TEST-NET-1)
            '45.76.142.23',
            '185.220.101.67',
            '91.219.237.244',
        ]

        demo_ports = ['22', '80', '443', '3389', '445', '21', '23', '25', '3306', '8080', '5900', '1433']
        protocols = ['TCP', 'UDP']

        while self.running:
            # Generate 1-3 entries every 2-5 seconds
            time.sleep(random.uniform(2, 5))

            num_entries = random.randint(1, 3)
            for _ in range(num_entries):
                ip = random.choice(demo_ips)
                port = random.choice(demo_ports)
                proto = random.choice(protocols)

                entry = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'action': 'DROP',
                    'protocol': proto,
                    'src_ip': ip,
                    'dst_ip': '192.168.1.100',
                    'src_port': str(random.randint(40000, 65000)),
                    'dst_port': port
                }

                self.add_entry(entry)

    def generate_screenshot_demo_traffic(self):
        """Generate diverse fake data immediately for screenshots"""
        import random

        # Diverse fake data for screenshots - realistic but clearly demo
        screenshot_data = [
            # CLOUD threats (yellow)
            {'ip': '45.76.142.23', 'port': '22', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '52.14.136.135', 'port': '3389', 'proto': 'TCP', 'country': 'US', 'city': 'Ohio', 'isp': 'Amazon AWS', 'threat': 'CLOUD'},
            {'ip': '35.198.12.45', 'port': '445', 'proto': 'TCP', 'country': 'US', 'city': 'Iowa', 'isp': 'Google Cloud', 'threat': 'CLOUD'},

            # HOSTING threats (red)
            {'ip': '185.220.101.67', 'port': '23', 'proto': 'TCP', 'country': 'DE', 'city': 'Frankfurt', 'isp': 'Hetzner Hosting', 'threat': 'HOSTING'},
            {'ip': '91.219.237.244', 'port': '3306', 'proto': 'TCP', 'country': 'NL', 'city': 'Amsterdam', 'isp': 'DataCamp VPS', 'threat': 'HOSTING'},
            {'ip': '198.51.100.89', 'port': '8080', 'proto': 'TCP', 'country': 'FR', 'city': 'Paris', 'isp': 'OVH Dedicated', 'threat': 'HOSTING'},

            # ISP/SAFE threats (green)
            {'ip': '203.0.113.45', 'port': '80', 'proto': 'TCP', 'country': 'CN', 'city': 'Beijing', 'isp': 'China Telecom', 'threat': 'SAFE'},
            {'ip': '192.0.2.156', 'port': '443', 'proto': 'TCP', 'country': 'RU', 'city': 'Moscow', 'isp': 'Rostelecom', 'threat': 'SAFE'},
            {'ip': '198.18.0.45', 'port': '21', 'proto': 'TCP', 'country': 'BR', 'city': 'São Paulo', 'isp': 'Vivo Telecom', 'threat': 'SAFE'},

            # Port scan example - same IP, multiple ports
            {'ip': '45.76.142.23', 'port': '22', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '45.76.142.23', 'port': '80', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '45.76.142.23', 'port': '443', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '45.76.142.23', 'port': '3389', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '45.76.142.23', 'port': '445', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},
            {'ip': '45.76.142.23', 'port': '3306', 'proto': 'TCP', 'country': 'US', 'city': 'New York', 'isp': 'DigitalOcean', 'threat': 'CLOUD'},

            # Additional diverse entries
            {'ip': '104.18.32.167', 'port': '5900', 'proto': 'TCP', 'country': 'GB', 'city': 'London', 'isp': 'Cloudflare', 'threat': 'CLOUD'},
            {'ip': '13.107.21.200', 'port': '1433', 'proto': 'TCP', 'country': 'US', 'city': 'Virginia', 'isp': 'Microsoft Azure', 'threat': 'CLOUD'},
            {'ip': '151.101.1.140', 'port': '25', 'proto': 'TCP', 'country': 'US', 'city': 'California', 'isp': 'Fastly CDN', 'threat': 'CLOUD'},
        ]

        # Immediately add all entries (no delay)
        for idx, data in enumerate(screenshot_data):
            # Stagger timestamps slightly for realism
            import datetime
            now = datetime.datetime.now()
            timestamp = (now - datetime.timedelta(seconds=len(screenshot_data)-idx)).strftime('%Y-%m-%d %H:%M:%S')

            entry = {
                'timestamp': timestamp,
                'action': 'DROP',
                'protocol': data['proto'],
                'src_ip': data['ip'],
                'dst_ip': '192.168.1.100',
                'src_port': str(random.randint(40000, 65000)),
                'dst_port': data['port']
            }

            # Manually set geo data for screenshot mode (bypass API)
            self.add_entry(entry)

            # Override geolocation for this IP
            if hasattr(self, 'connections') and len(self.connections) > 0:
                conn = self.connections[-1]
                conn.country = data['country']
                conn.city = data['city']
                conn.isp = data['isp']
                conn.threat = data['threat']

    def tail_file(self):
        """Tail log file for new entries"""
        try:
            if not os.path.exists(self.log_path):
                return

            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Go to end of file
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if line:
                        # Parse based on platform
                        if self.platform == 'win32':
                            entry = self.parse_windows_log_line(line)
                        else:
                            entry = self.parse_linux_log_line(line)

                        if entry:
                            self.add_entry(entry)
                    else:
                        time.sleep(0.01)  # Wait for new data (10ms for near-instant live feed)
        except Exception as e:
            # Silently fail if log not accessible
            pass

    def start(self):
        """Start monitoring in background thread"""
        self.running = True
        if self.demo_mode:
            # Check if screenshot mode was requested
            import sys
            if '--demo-screenshot' in sys.argv:
                # Immediately populate with screenshot data (no background thread needed)
                self.generate_screenshot_demo_traffic()
            else:
                # Regular demo mode with continuous generation
                thread = threading.Thread(target=self.generate_demo_traffic, daemon=True)
                thread.start()
        else:
            thread = threading.Thread(target=self.tail_file, daemon=True)
            thread.start()

    def stop(self):
        """Stop monitoring"""
        self.running = False

    def get_connections(self):
        """Get recent connections"""
        return list(self.connections)


# Static Death Star ASCII art for flat display - compact version
DEATH_STAR_STATIC = [
    "                             .-------===-=+=-:                               ",
    "                       .-------:=-======-===+=++++=.                         ",
    "                    :----:------=-=-=-===-=++++=+++***-                      ",
    "                 :-----::::---:=---:=====--+=++=+**+**+**-                   ",
    "               --::--::.:::-::--:=---==+=--===#%#####*+++*##                 ",
    "            .-::.:::::.:::::------:--=====-=-%%#####**+++==*#*.              ",
    "           :-::.::::.::::::::::-:-::=======+=#%%%###**+=--=:+##+             ",
    "         .:--::.::::.......:..:::-:--=+-=====%%%%##%#++=-:----###:           ",
    "        :-:-::.::.: ...... ...:::--::=-==---==#%%%%%%%+--------#%%*          ",
    "       :-::::.::: ........ ..:::::-::==-=---==+#%%%%%%#--:---=-+#%%*         ",
    "      -:---:...:. .:.::... .::::::-::--=----===+*#%%%@#==----+-+#%%%#        ",
    "     ::---....:: ..:.:.... .:-:::::-::---=---===+++*%###**++=++=###%%%+      ",
    "    .-:--:-:.:-:...::.:... .:::::::-::--===--===++++++*#####***####%%%%-     ",
    "    =------...:. ..:.:.::..:::::::--:-===---===++++++++*******#####%%%%.     ",
    "   :-------...:.  .:...:.. .........::::::-----=====++++++***######%%%%+     ",
    "   ----::......-+=----====-----------====+++******######********###%%%%#     ",
    "   -::-=*#=:......::.....:..:::::::--::-----=-====+++++++++**#%%%%%%%%%%:    ",
    "   *+-:::::::::.::::::::.::::--:::--=-:---====++*+**++******##*###%%%%%%=    ",
    "  .-------:::--::::--:::.:::----:--==-:===+++=++*+********#*##*#%%%%%%%%*    ",
    "  .+-=-----:-----:-----:.:-:----:-===--===+=+=+****+**#*###*%###%%%%%%%%#    ",
    "  .+==----:--=------=---::-===--:=+===-===++++***##**####%####%%%%#%%#%%*    ",
    "   +====-----==---=====-:---====-===+=-+++++++***#***#######%#%%%%#%%%#%-    ",
    "   =+=======-=========----======-=+++==++++*++**###**##%####%%#%%%#%%%%%.    ",
    "   =*+++=====-===-===+=====++++++=+++++*++***+++*%#*#**#######%%%#%%%%%*     ",
    "   .+++++=+=--====-++=++=+=*++++++++++**+****+**###*#*#######%%%%%%%%%%=     ",
    "    =*++++++===+++=++=++=++******++**+*#+****+*#*########%%#%%%%%%%%%%#      ",
    "     **++++++==+=========++++++*+++**#**+***##***########%#%%%%%#%%#%%       ",
    "     :**+*+*+++**++++++++++*****+*+**#*#**####**########%%#%%%#%%%%%%-       ",
    "      -#******++*******+*++****#+**###*#**####*#########%#%%%%%%%#%%-        ",
    "       -#********#*#***#****######*###*###%######%%%%%%%%%%%%%%%#%%-         ",
    "        .##*#*******########*%####*##%#%#%#%%%%%%%%%%%%%%%%%%%%%%%           ",
    "          +%#########%#####%##%#%###%%#%%%%%%%%%%%%%%%%#%%%%%%%%*            ",
    "           :#%##%#%%#%%%##%%%%%#%%#%%%%%%%%%%%%%%%%%%%%%%%%%%%#.             ",
    "             :%%%%###%#########%%%%%#%%%%%%%%%%%%%%%%%%%%%%%%:               ",
    "               :#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#.                 ",
    "                  +%@@%%%%%%@%@%%%%%%%%%%%%%@%@%%%%%%%%#=                    ",
    "                     -%%@%@@%%@@@@@@%@@@%%@@@%%%%%%%%-                       ",
    "                         :+@@@@@@@@@%%%%%%@%%@%%+:                           ",
    "                               .-===+++==-:.                                 ",
    "                                    ...                                      ",
    "                                                                             ",
]

# Earth bitmap data (120x60 equirectangular projection)
EARTH_MAP = [
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                             # ####### #################                                    #                           ",
    "                       #    #   ### #################            ###                                                    ",
    "                      ###  ## ####       ############ #                        ##         ########        #####         ",
    "                  ## ###   #  ### ##      ###########                         #    #### ################   ###          ",
    "      ######## ###### #### # #  #  ###     #########              #######        # ## ##################################",
    " ### ###########################    ####   #####      #          ####### ###############################################",
    "      ########################       ##    ####                #### ####################################################",
    "      ### # #################      ##        #                ##### # ##########################################  ##    ",
    "                ##############     #####                   #     #  #######################################      ##     ",
    "                 ################ #######                # #   ###########################################      ##      ",
    "                  ########################                 ################################################             ",
    "                    ###################  ##                ################################################             ",
    "                   ################### #                    ##########  ####  ############################              ",
    "                   ##################                    ##### ##  ###    ### ##########################                ",
    "                   #################                     ###       # ######## ######################  #    #            ",
    "                    ###############                       #  ###       ##############################  #  #             ",
    "                     #############                        ######        #############################                   ",
    "                       ######## #                        ############################################                   ",
    "                      # ####     #                      ##################### #######################                   ",
    "                       # ###      #                    ################# ######    #################                    ",
    "                         ###  #   #                    ################## ######     ####  #####                        ",
    "                          #####   # #                  ################## #####      ###    ####                        ",
    "                             ####                      ################### ###       ##      ####   #                   ",
    "                               #    #                  ####################           #      # ##                       ",
    "                                #  #####                #####################         #      # #     ##                 ",
    "                                   ######                #### ###############          #      #    #                    ",
    "                                   ########                     ############                 ##   ##                    ",
    "                                  #########                     ###########                   #  ####                   ",
    "                                  #############                 ##########                    ##### #     ##            ",
    "                                 ################                ########                                  ## #         ",
    "                                  ###############                #########                         ## #    # #          ",
    "                                   #############                 #########                                              ",
    "                                   ############                  #########  #                         # ##  #           ",
    "                                     ##########                 #########  ##                        ########           ",
    "                                     ##########                  #######   ##                      ###########     #    ",
    "                                     ########                    #######   #                      #############         ",
    "                                     #######                     ######                           ##############        ",
    "                                     #######                      #####                            #############        ",
    "                                     ######                       ####                             ###   ######         ",
    "                                    #####                                                                  ####       # ",
    "                                    #####                                                                              #",
    "                                    ###                                                                      #        # ",
    "                                    ###                                                                             ##  ",
    "                                    ##                                                                                  ",
    "                                   ##                                                                                   ",
    "                                    ##                                                                                  ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                       #                                                                                ",
    "                                      #                                #  ##########   ########################         ",
    "                                   #####                 ########################## #################################   ",
    "                  # ## #   #############              #############################################################     ",
    "        ## #########################             ##################################################################     ",
    "           ######################## #  #  ##     #################################################################      ",
    "    ##################################################################################################################  ",
    "########################################################################################################################",
]

# ASCII Logos for neofetch-style display (from neofetch repo issue #1466)
LOGOS = {
    "Windows": [
        " ....::  ll",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        "",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        " ``  llllll",
    ],
    "Linux": [
        "    ___",
        "   (.. |",
        "   (<> |",
        "  / __  \\",
        " ( /  \\ /|",
    ],
    "Darwin": [  # macOS
        "      .:'",
        "  __ :'__",
        " .'`__`-'",
        " :__/  ",
        " :/'",
    ],
}

def get_demo_system_info():
    """Return fake system info for screenshots (masks real data)"""
    return {
        'OS': 'Windows 11 (Build 22631)',
        'Kernel': '10.0.22631.4037',
        'Terminal': 'Windows Terminal',
        'Resolution': '1920x1080',
        'Motherboard': 'ASUS ROG STRIX Z790-E GAMING',
        'CPU': 'Intel(R) Core(TM) i7-13700K @ 3.40GHz',
        'GPU': 'NVIDIA GeForce RTX 4070',
        'RAM': '16GB / 32GB (50%)',
        'Disk': '512GB / 1024GB (50%)',
        'Network': 'Ethernet',
        'Uptime': '5d 12h',
        'Host': 'DEATHSTAR-PC',
        'Architecture': 'AMD64',
        'BIOS': 'American Megatrends F7',
        'CPU Load': '42%',
        'CPU Temp': '58°C',
        'Battery': None
    }, 'Windows'

def get_system_info():
    """Gather system information neofetch-style"""
    info = {}

    # OS with build version
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()

    # Extract Windows build number if available
    if sys.platform == 'win32':
        try:
            import subprocess
            result = subprocess.run(['wmic', 'os', 'get', 'BuildNumber'],
                                    capture_output=True, text=True, timeout=2)
            build_lines = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'BuildNumber' not in line]
            if build_lines:
                info['OS'] = f"{os_name} {os_release} (Build {build_lines[0]})"
            else:
                info['OS'] = f"{os_name} {os_release}"
        except:
            info['OS'] = f"{os_name} {os_release}"
    else:
        # For Linux, show kernel version
        info['OS'] = f"{os_name} {os_release}"

    # Kernel/Build
    if sys.platform == 'win32':
        info['Kernel'] = os_version
    else:
        info['Kernel'] = platform.release()

    # Terminal Type Detection
    terminal_type = "Unknown"
    try:
        # Check environment variables for terminal type
        if os.environ.get('WT_SESSION'):
            terminal_type = "Windows Terminal"
        elif os.environ.get('ConEmuPID'):
            terminal_type = "ConEmu"
        elif os.environ.get('HYPER_VERSION'):
            terminal_type = "Hyper"
        elif os.environ.get('ALACRITTY_SOCKET'):
            terminal_type = "Alacritty"
        elif os.environ.get('TERM_PROGRAM'):
            terminal_type = os.environ.get('TERM_PROGRAM')
        elif os.environ.get('TERM'):
            terminal_type = os.environ.get('TERM')
        elif sys.platform == 'win32':
            # Check if running in cmd or powershell
            parent = os.environ.get('PROMPT', '')
            if 'PS' in parent:
                terminal_type = "PowerShell"
            else:
                terminal_type = "CMD"
    except:
        terminal_type = "Unknown"
    info['Terminal'] = terminal_type

    # Screen Resolution
    try:
        if sys.platform == 'win32':
            import subprocess
            result = subprocess.run(['wmic', 'path', 'Win32_VideoController', 'get', 'CurrentHorizontalResolution,CurrentVerticalResolution'],
                                    capture_output=True, text=True, timeout=2)
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'Current' not in line]
            if lines:
                parts = lines[0].split()
                if len(parts) >= 2:
                    info['Resolution'] = f"{parts[0]}x{parts[1]}"
                else:
                    info['Resolution'] = "N/A"
            else:
                info['Resolution'] = "N/A"
        else:
            # Linux - try xrandr
            result = subprocess.run(['xrandr'], capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if '*' in line:
                    parts = line.split()
                    info['Resolution'] = parts[0]
                    break
            else:
                info['Resolution'] = "N/A"
    except:
        info['Resolution'] = "N/A"

    # Motherboard
    try:
        if sys.platform == 'win32':
            import subprocess
            result = subprocess.run(['wmic', 'baseboard', 'get', 'Manufacturer,Product'],
                                    capture_output=True, text=True, timeout=2)
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'Manufacturer' not in line]
            if lines:
                mobo = lines[0]
                # Don't pre-truncate, let the display logic handle it
                info['Motherboard'] = mobo
            else:
                info['Motherboard'] = "N/A"
        else:
            # Linux - try dmidecode
            result = subprocess.run(['dmidecode', '-t', '2'], capture_output=True, text=True, timeout=2)
            manufacturer = ""
            product = ""
            for line in result.stdout.split('\n'):
                if 'Manufacturer:' in line:
                    manufacturer = line.split(':')[1].strip()
                if 'Product Name:' in line:
                    product = line.split(':')[1].strip()
            if manufacturer and product:
                mobo = f"{manufacturer} {product}"
                # Don't pre-truncate, let the display logic handle it
                info['Motherboard'] = mobo
            else:
                info['Motherboard'] = "N/A"
    except:
        info['Motherboard'] = "N/A"

    # CPU
    cpu = platform.processor()
    # Don't pre-truncate, let the display logic handle it
    info['CPU'] = cpu

    # GPU
    try:
        if sys.platform == 'win32':
            import subprocess
            result = subprocess.run(['wmic', 'path', 'win32_VideoController', 'get', 'name'],
                                    capture_output=True, text=True, timeout=2)
            # Parse output, skip header and empty lines
            gpu_lines = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'Name' not in line]
            if gpu_lines:
                gpu = gpu_lines[0]
                if len(gpu) > 25:
                    gpu = gpu[:22] + "..."
                info['GPU'] = gpu
            else:
                info['GPU'] = "N/A"
        else:
            info['GPU'] = "N/A"
    except:
        info['GPU'] = "N/A"

    # Memory (RAM) - Total and Used
    mem = psutil.virtual_memory()
    total_gb = mem.total // 1024**3
    used_gb = mem.used // 1024**3
    percent = mem.percent
    info['RAM'] = f"{used_gb}GB / {total_gb}GB ({int(percent)}%)"

    # Disk Usage
    try:
        disk = psutil.disk_usage('C:\\' if sys.platform == 'win32' else '/')
        total_gb = disk.total // 1024**3
        used_gb = disk.used // 1024**3
        percent = disk.percent
        info['Disk'] = f"{used_gb}GB / {total_gb}GB ({int(percent)}%)"
    except:
        info['Disk'] = "N/A"

    # Battery (if laptop)
    try:
        battery = psutil.sensors_battery()
        if battery:
            percent = int(battery.percent)
            plugged = battery.power_plugged
            status = "Charging" if plugged else "Discharging"
            # Estimate time remaining
            if battery.secsleft != psutil.POWER_TIME_UNLIMITED and battery.secsleft != psutil.POWER_TIME_UNKNOWN:
                hours = battery.secsleft // 3600
                mins = (battery.secsleft % 3600) // 60
                info['Battery'] = f"{percent}% ({status}) {hours}h {mins}m"
            else:
                info['Battery'] = f"{percent}% ({status})"
        else:
            info['Battery'] = None  # Desktop - no battery
    except:
        info['Battery'] = None

    # Network Connection Type
    try:
        if sys.platform == 'win32':
            import subprocess
            # Check for wireless adapters
            result = subprocess.run(['wmic', 'nic', 'where', 'NetEnabled=true', 'get', 'Name'],
                                   capture_output=True, text=True, timeout=2)
            network_type = "Unknown"
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if 'wireless' in line_lower or 'wi-fi' in line_lower or '802.11' in line_lower or 'wifi' in line_lower:
                    network_type = 'WiFi'
                    break
                elif 'ethernet' in line_lower or 'gigabit' in line_lower or 'realtek' in line_lower:
                    network_type = 'Ethernet'
            info['Network'] = network_type
        else:
            # Linux: Check for wireless interfaces
            import subprocess
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'no wireless' not in result.stderr.lower():
                info['Network'] = 'WiFi'
            else:
                info['Network'] = 'Ethernet'
    except:
        info['Network'] = 'Unknown'

    # Uptime
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        days = uptime.days
        hours = uptime.seconds // 3600
        mins = (uptime.seconds % 3600) // 60
        if days > 0:
            info['Uptime'] = f"{days}d {hours}h"
        else:
            info['Uptime'] = f"{hours}h {mins}m"
    except:
        info['Uptime'] = "N/A"

    # Host
    info['Host'] = platform.node()

    # Architecture
    info['Architecture'] = platform.machine()

    # BIOS Version
    try:
        if sys.platform == 'win32':
            import subprocess
            result = subprocess.run(['wmic', 'bios', 'get', 'SMBIOSBIOSVersion'],
                                    capture_output=True, text=True, timeout=2)
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip() and 'SMBIOSBIOSVersion' not in line]
            if lines:
                info['BIOS'] = lines[0]
            else:
                info['BIOS'] = "N/A"
        else:
            # Linux - try dmidecode
            result = subprocess.run(['dmidecode', '-s', 'bios-version'], capture_output=True, text=True, timeout=2)
            bios = result.stdout.strip()
            info['BIOS'] = bios if bios else "N/A"
    except:
        info['BIOS'] = "N/A"

    # CPU Load
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        info['CPU Load'] = f"{cpu_percent}%"
    except:
        info['CPU Load'] = "N/A"

    # CPU Temperature (if available)
    try:
        if hasattr(psutil, 'sensors_temperatures'):
            temps = psutil.sensors_temperatures()
            if temps:
                # Try to find CPU temp (varies by system)
                cpu_temp = None
                for name, entries in temps.items():
                    if 'coretemp' in name.lower() or 'cpu' in name.lower() or 'k10temp' in name.lower():
                        if entries:
                            cpu_temp = entries[0].current
                            break
                if cpu_temp:
                    info['CPU Temp'] = f"{int(cpu_temp)}°C"
                else:
                    info['CPU Temp'] = "N/A"
            else:
                info['CPU Temp'] = "N/A"
        else:
            info['CPU Temp'] = "N/A"
    except:
        info['CPU Temp'] = "N/A"

    return info, os_name


class Globe:
    """3D ASCII Globe renderer"""

    def __init__(self, width, height, aspect_ratio=2.0):
        self.width = max(1, width)
        self.height = max(1, height)
        self.aspect_ratio = aspect_ratio
        self.map_width = len(EARTH_MAP[0])
        self.map_height = len(EARTH_MAP)
        self.radius = min(float(width) / 2.5, float(height) * aspect_ratio / 2.5)
        self.radius = max(1.0, self.radius)
        self.attacks = []
        # Lighting parameters (matching Go version)
        self.lighting = False
        self.light_lon = 0.0
        self.light_lat = 0.0
        self.light_follow = True  # Light rotates with globe for day/night effect
        # Plus mode - simplify globe to + characters
        self.plus_mode = False

    def add_attack(self, lat, lon, label="*"):
        self.attacks.append((lat, lon, label))

    def sample_earth_at(self, lat, lon):
        lat_norm = (lat + 90) / 180
        lon_norm = (lon + 180) / 360
        y = int(lat_norm * (self.map_height - 1))
        x = int(lon_norm * (self.map_width - 1))
        y = max(0, min(y, self.map_height - 1))
        x = max(0, min(x, self.map_width - 1))
        return EARTH_MAP[y][x]

    def project_3d_to_2d(self, lat, lon, rotation):
        adjusted_lon = -lon + 90
        adjusted_lon = ((adjusted_lon + 180) % 360) - 180
        lat_rad = math.radians(lat)
        lon_rad = math.radians(adjusted_lon + math.degrees(rotation))
        x = math.cos(lat_rad) * math.cos(lon_rad)
        y = math.sin(lat_rad)
        z = math.cos(lat_rad) * math.sin(lon_rad)
        if z < 0:
            return None, None, False
        screen_x = int(x * self.radius) + self.width // 2
        screen_y = int(-y * self.radius / self.aspect_ratio) + self.height // 2
        if screen_x < 0 or screen_x >= self.width or screen_y < 0 or screen_y >= self.height:
            return None, None, False
        return screen_x, screen_y, True

    def render(self, rotation, rainbow_mode=False, skittles_mode=False):
        """Render globe and return 2D array of (char, color_index, shaded)"""
        screen = [[(' ', 0, False) for _ in range(self.width)] for _ in range(self.height)]
        density = [[0.0 for _ in range(self.width)] for _ in range(self.height)]
        attack_layer = [[False for _ in range(self.width)] for _ in range(self.height)]

        center_x = self.width // 2
        center_y = self.height // 2

        # Mark attacks
        for lat, lon, label in self.attacks:
            sx, sy, visible = self.project_3d_to_2d(lat, lon, rotation)
            if visible:
                attack_layer[sy][sx] = True

        # Sample globe
        for y in range(self.height):
            for x in range(self.width):
                dx = float(x - center_x)
                dy = float(y - center_y) * self.aspect_ratio
                distance = math.sqrt(dx*dx + dy*dy)

                if distance <= self.radius:
                    nx = dx / self.radius
                    ny = dy / self.radius
                    nz_squared = 1 - nx*nx - ny*ny
                    if nz_squared >= 0:
                        nz = math.sqrt(nz_squared)
                        lat = math.degrees(math.asin(ny))
                        lon = math.degrees(math.atan2(nx, nz)) + math.degrees(rotation)
                        while lon < -180:
                            lon += 360
                        while lon > 180:
                            lon -= 360

                        earth_char = self.sample_earth_at(lat, lon)
                        base_density = 0.0
                        if earth_char == '#':
                            base_density = 1.0
                        elif earth_char == '.':
                            base_density = 0.6
                        elif earth_char != ' ':
                            base_density = 0.8

                        # Apply base density (no lighting modification - visual dimming is applied via colors)
                        density[y][x] += base_density

                        # Simplified anti-aliasing - only add to current pixel neighbors
                        if base_density > 0:
                            aa_factor = 0.05
                            # Only update immediate neighbors (not diagonal)
                            if x > 0:
                                density[y][x-1] += aa_factor
                            if x < self.width - 1:
                                density[y][x+1] += aa_factor
                            if y > 0:
                                density[y-1][x] += aa_factor
                            if y < self.height - 1:
                                density[y+1][x] += aa_factor

                if self.radius - 0.5 < distance < self.radius + 0.5:
                    # Border enhancement - respect lighting for consistent dimming
                    border_density = 0.2
                    if self.lighting:
                        # Calculate approximate lighting for border (use average or dim it)
                        border_density = 0.2 * 0.6  # Apply same 60% dimming as shaded colors
                    density[y][x] += border_density

        # Convert to characters with color indices
        for y in range(self.height):
            for x in range(self.width):
                d = density[y][x]
                char = ' '
                shaded = False

                if d >= 1.0:
                    char = '+' if self.plus_mode else '@'
                elif d >= 0.8:
                    char = '+' if self.plus_mode else '#'
                elif d >= 0.6:
                    char = '+' if self.plus_mode else '%'
                elif d >= 0.4:
                    char = '+' if self.plus_mode else 'o'
                elif d >= 0.3:
                    char = '='
                elif d >= 0.2:
                    char = '+'
                elif d >= 0.15:
                    char = '-'
                elif d >= 0.1:
                    char = '.'
                elif d >= 0.05:
                    char = '`'

                if attack_layer[y][x]:
                    char = '*'

                # Simple global dim toggle: if lighting is on, ALL chars are dimmed
                if self.lighting and char != ' ':
                    shaded = True

                # Determine color index
                color_idx = 0
                if char != ' ':
                    if rainbow_mode:
                        # Rainbow uses gradient pattern for smooth color transitions
                        color_idx = ((x + y) % 7) + 1  # 7 rainbow colors in diagonal pattern
                    elif skittles_mode:
                        # Skittles uses hash function for random color distribution
                        # Bitwise XOR and multiple prime multipliers to avoid banding
                        h1 = (x * 2654435761) & 0xFFFFFFFF
                        h2 = (y * 2246822519) & 0xFFFFFFFF
                        h3 = ((x ^ y) * 3266489917) & 0xFFFFFFFF
                        hash_val = (h1 ^ h2 ^ h3) & 0xFFFFFFFF
                        color_idx = (hash_val % 16) + 1  # 16 skittles colors (1-16)
                    else:
                        color_idx = 0  # Default color

                screen[y][x] = (char, color_idx, shaded)

        return screen


class Dashboard:
    """Main dashboard with blessed terminal control"""

    THEMES = {
        "matrix": {"name": "Matrix", "globe": "bright_green", "feed": "bright_yellow", "stats": "bright_cyan"},
        "amber": {"name": "Amber", "globe": "bright_yellow", "feed": "bright_yellow", "stats": "yellow"},
        "nord": {"name": "Nord", "globe": "bright_cyan", "feed": "bright_blue", "stats": "bright_cyan"},
        "dracula": {"name": "Dracula", "globe": "bright_magenta", "feed": "bright_magenta", "stats": "magenta"},
        "mono": {"name": "Mono", "globe": "bright_white", "feed": "bright_white", "stats": "white"},
        "rainbow": {"name": "Rainbow", "globe": "bright_green", "feed": "bright_magenta", "stats": "bright_cyan", "rainbow": True},
        "skittles": {"name": "Skittles", "globe": "bright_green", "feed": "bright_yellow", "stats": "bright_magenta", "skittles": True},
    }

    def __init__(self, rotation_period=30, theme="matrix", log_path=None, demo_mode=False):
        self.term = Terminal()
        self.rotation_period = rotation_period
        self.start_time = time.time()

        self.theme_names = list(self.THEMES.keys())
        self.current_theme_index = self.theme_names.index(theme) if theme in self.theme_names else 0
        self.theme = self.THEMES[self.theme_names[self.current_theme_index]]

        self.paused = False
        self.show_legend = False
        self.lighting = False
        self.plus_mode = False
        self.death_star_mode = False
        self.show_attack_details = False
        self.operator_mode = False
        self.running = True
        self.globe = None
        self.demo_mode = demo_mode

        # Detect screenshot mode for masking real system stats
        import sys
        self.screenshot_mode = '--demo-screenshot' in sys.argv

        self.test_locations = [
            (40.7128, -74.0060, "NYC"),
            (51.5074, -0.1278, "LON"),
            (35.6762, 139.6503, "TYO"),
            (-33.8688, 151.2093, "SYD"),
        ]

        # Cache system info (expensive to compute every frame)
        self.sys_info_cache = None
        self.sys_info_os = None
        self.sys_info_last_update = 0
        self.sys_info_update_interval = 2.0  # Update every 2 seconds

        # Initialize firewall log parser
        self.log_parser = FirewallLogParser(log_path, demo_mode=demo_mode)
        self.use_real_logs = self._verify_firewall_logging_active() or demo_mode

    def _verify_firewall_logging_active(self):
        """Verify that firewall logging is actually active (not just file exists)"""
        if not os.path.exists(self.log_parser.log_path):
            return False

        try:
            file_stat = os.stat(self.log_parser.log_path)
            file_mtime = file_stat.st_mtime
            time_since_update = time.time() - file_mtime

            # If file was created/modified recently (within 24 hours), assume logging is enabled
            # This handles newly enabled logging or cleared log files
            if time_since_update < 86400:  # 24 hours
                # Even 0-byte files are OK if recently created (logging just enabled)
                return True

            # If file is older, it must have content to verify logging is actually working
            if file_stat.st_size == 0:
                return False

            # Check if file has been modified within last 7 days
            # This indicates Windows Firewall logging is configured
            if time_since_update < 604800:  # 7 days in seconds
                return True

            # If file is older than 7 days, check if it has valid log entries
            # (Even old entries indicate logging was configured at some point)
            with open(self.log_parser.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first 50 lines to check for valid firewall log format
                lines = f.readlines()[:50]
                if not lines:
                    return False

                # Look for Windows Firewall log header or valid entries
                for line in lines:
                    line = line.strip()
                    # Check for firewall log header comments
                    if line.startswith('#Fields:') or line.startswith('#Software:'):
                        return True
                    # Check for valid log entry (skip empty lines and comments)
                    if not line or line.startswith('#'):
                        continue
                    # Try to parse Windows firewall log format
                    parts = line.split()
                    if len(parts) >= 8:
                        # Valid firewall log entry format detected
                        return True

                # File exists and has content but doesn't look like a firewall log
                return False
        except Exception:
            return False

    def cycle_theme(self):
        self.current_theme_index = (self.current_theme_index + 1) % len(self.theme_names)
        self.theme = self.THEMES[self.theme_names[self.current_theme_index]]

    def get_rotation(self):
        if self.paused:
            return self.pause_rotation if hasattr(self, 'pause_rotation') else 0
        elapsed = time.time() - self.start_time
        # Slower rotation - one full rotation per period (default 30 seconds)
        return -(elapsed / self.rotation_period) * 2 * math.pi

    def get_color(self, color_name, color_idx=0, dim=False):
        """Get color formatter using direct ANSI RGB codes"""
        # Vibrant rainbow with bright, saturated colors (as RGB tuples)
        rainbow_colors = [
            (255, 0, 0),      # Red
            (255, 127, 0),    # Orange
            (255, 255, 0),    # Yellow
            (0, 255, 0),      # Green
            (0, 191, 255),    # Deep Sky Blue (brighter than dark blue)
            (138, 43, 226),   # Blue-Violet (replaces dark Indigo)
            (255, 0, 255),    # Magenta/Violet (brighter)
        ]

        # Expanded skittles palette with 16 vibrant candy colors (as RGB tuples)
        skittles_colors = [
            (255, 0, 0),      # Red (strawberry)
            (255, 69, 0),     # Orange-Red
            (255, 127, 0),    # Orange
            (255, 165, 0),    # Bright Orange
            (255, 215, 0),    # Gold
            (255, 255, 0),    # Yellow (lemon)
            (173, 255, 47),   # Yellow-Green
            (0, 255, 0),      # Green (lime)
            (0, 255, 127),    # Spring Green
            (0, 206, 209),    # Turquoise
            (0, 191, 255),    # Deep Sky Blue
            (0, 0, 255),      # Blue
            (138, 43, 226),   # Blue-Violet
            (148, 0, 211),    # Violet (grape)
            (255, 0, 255),    # Magenta
            (255, 20, 147),   # Deep Pink
        ]

        if color_idx > 0:
            # Use skittles colors if in skittles mode, otherwise rainbow
            if hasattr(self, 'theme') and self.theme.get("skittles", False):
                # Skittles uses 1-16, so subtract 1 for 0-based index
                r, g, b = skittles_colors[(color_idx - 1) % len(skittles_colors)]
            else:
                # Rainbow uses 1-7, so subtract 1 for 0-based index
                r, g, b = rainbow_colors[(color_idx - 1) % len(rainbow_colors)]

            # Apply dimming if requested
            if dim:
                r = int(r * 0.6)
                g = int(g * 0.6)
                b = int(b * 0.6)

            color_code = rgb(r, g, b)
            return lambda text: color_code + str(text) + RESET

        # RGB color map matching Go themes exactly
        color_map = {
            # Matrix theme - fluorescent green
            "bright_green": (0, 255, 65),
            "green": (0, 150, 40),  # Shaded green

            # Bright colors
            "bright_yellow": (255, 255, 0),
            "yellow": (255, 176, 0),
            "bright_cyan": (0, 255, 255),
            "cyan": (0, 191, 255),
            "bright_magenta": (255, 0, 255),
            "magenta": (255, 0, 255),
            "bright_blue": (100, 149, 237),
            "blue": (0, 0, 255),
            "bright_white": (255, 255, 255),
            "white": (200, 200, 200),
            "bright_red": (255, 0, 0),
            "red": (255, 0, 0),
            "orange": (255, 165, 0),
            "purple": (138, 43, 226),
        }

        # Get RGB values and apply dimming if requested
        r, g, b = color_map.get(color_name, (255, 255, 255))
        if dim:
            # Dim by ~60% for shaded areas (matching the matrix green ratio: 150/255 ≈ 0.59)
            r = int(r * 0.6)
            g = int(g * 0.6)
            b = int(b * 0.6)

        color_code = rgb(r, g, b)
        return lambda text: color_code + str(text) + RESET

    def render_death_star(self, width, height, rotation, rainbow_mode=False, skittles_mode=False):
        """Render Death Star as static ASCII art - sized to match globe"""
        screen = [[(' ', 0, False) for _ in range(width)] for _ in range(height)]

        # Use the clean static Death Star art
        art_lines = DEATH_STAR_STATIC
        source_height = len(art_lines)
        source_width = max(len(line) for line in art_lines) if source_height > 0 else 0

        if source_height == 0 or source_width == 0:
            return screen

        # Match globe's sizing - globe uses radius = min(width/2.5, height*2.0/2.5)
        # Then apply adjustment factor to match visual appearance
        aspect_ratio = 2.0
        radius = min(float(width) / 2.5, float(height) * aspect_ratio / 2.5)
        radius = max(1.0, radius)

        # Apply 65% adjustment for visual matching
        target_height = (radius * 2) * 0.65

        scale = target_height / source_height if source_height > 0 else 1

        # Calculate scaled dimensions
        scaled_height = int(source_height * scale)
        scaled_width = int(source_width * scale)

        # Center the Death Star
        start_y = (height - scaled_height) // 2
        start_x = (width - scaled_width) // 2

        # Render with downsampling if needed
        for screen_y in range(scaled_height):
            if start_y + screen_y >= height:
                break

            # Map screen position back to source
            source_y = int(screen_y / scale)
            if source_y >= len(art_lines):
                continue

            line = art_lines[source_y]

            for screen_x in range(scaled_width):
                if start_x + screen_x >= width:
                    break

                # Map screen position back to source
                source_x = int(screen_x / scale)
                if source_x >= len(line):
                    char = ' '
                else:
                    char = line[source_x]

                # Determine color index based on mode
                color_idx = 0
                shaded = False

                if char != ' ':
                    final_x = start_x + screen_x
                    final_y = start_y + screen_y

                    # Apply lighting (dimming) if enabled
                    if self.lighting:
                        shaded = True

                    if rainbow_mode:
                        color_idx = ((final_x + final_y) % 7) + 1
                    elif skittles_mode:
                        h1 = (final_x * 2654435761) & 0xFFFFFFFF
                        h2 = (final_y * 2246822519) & 0xFFFFFFFF
                        h3 = ((final_x ^ final_y) * 3266489917) & 0xFFFFFFFF
                        hash_val = (h1 ^ h2 ^ h3) & 0xFFFFFFFF
                        color_idx = (hash_val % 16) + 1

                screen[start_y + screen_y][start_x + screen_x] = (char, color_idx, shaded)

        return screen

    def analyze_ip_type(self, ip):
        """Analyze IP address and return detailed explanation"""
        if ip.startswith('fe80:'):
            return {
                'type': 'IPv6 Link-Local',
                'meaning': 'A device on your local network (not internet)',
                'threat': 'Safe - Private network device'
            }
        elif ip.startswith('ff02:'):
            return {
                'type': 'IPv6 Multicast',
                'meaning': 'Broadcast to multiple devices on local network',
                'threat': 'Safe - Normal network operation'
            }
        elif ip.startswith('::1') or ip == 'localhost':
            return {
                'type': 'IPv6 Localhost',
                'meaning': 'Your own computer talking to itself',
                'threat': 'Safe - Internal system communication'
            }
        elif ip.startswith(('fc00:', 'fd00:')):
            return {
                'type': 'IPv6 Unique Local',
                'meaning': 'Private IPv6 address (like 192.168.x.x)',
                'threat': 'Safe - Private network'
            }
        elif ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.16.'):
            return {
                'type': 'IPv4 Private',
                'meaning': 'Device on your home/office network',
                'threat': 'Safe - Private network'
            }
        elif ip.startswith('127.'):
            return {
                'type': 'IPv4 Localhost',
                'meaning': 'Your own computer (loopback)',
                'threat': 'Safe - Internal system communication'
            }
        else:
            return {
                'type': 'Public Internet IP',
                'meaning': 'External device from the internet',
                'threat': 'Depends on activity - Check threat level'
            }

    def get_service_info(self, port, service):
        """Get detailed information about a service/port"""
        service_info = {
            '5353': {
                'name': 'mDNS (Multicast DNS)',
                'use': 'Device discovery on local networks',
                'common': 'Printers, Apple devices (AirPlay/AirDrop), smart home',
                'why_blocked': 'Windows Firewall blocks multicast by default'
            },
            '22': {
                'name': 'SSH (Secure Shell)',
                'use': 'Remote server administration',
                'common': 'Linux servers, network equipment',
                'why_blocked': 'Common target for brute-force attacks'
            },
            '3389': {
                'name': 'RDP (Remote Desktop)',
                'use': 'Remote Windows desktop access',
                'common': 'Windows servers, work computers',
                'why_blocked': 'Frequent target for ransomware attacks'
            },
            '445': {
                'name': 'SMB (Server Message Block)',
                'use': 'Windows file sharing',
                'common': 'Network drives, printers',
                'why_blocked': 'Major ransomware attack vector (WannaCry, etc.)'
            },
            '80': {
                'name': 'HTTP (Web Traffic)',
                'use': 'Unencrypted web servers',
                'common': 'Websites, web applications',
                'why_blocked': 'Usually not blocked unless running web server'
            },
            '443': {
                'name': 'HTTPS (Secure Web)',
                'use': 'Encrypted web servers',
                'common': 'Secure websites, APIs',
                'why_blocked': 'Usually not blocked unless running web server'
            },
            '3306': {
                'name': 'MySQL Database',
                'use': 'Database server access',
                'common': 'Web applications, data storage',
                'why_blocked': 'Should never be exposed to internet'
            },
            '8080': {
                'name': 'HTTP-ALT (Web Alternate)',
                'use': 'Alternate web server port',
                'common': 'Development servers, proxies',
                'why_blocked': 'Often targeted by automated scanners'
            },
            '23': {
                'name': 'Telnet',
                'use': 'Unencrypted remote access',
                'common': 'Legacy systems (INSECURE - use SSH instead)',
                'why_blocked': 'Sends passwords in plain text - major security risk'
            },
            '21': {
                'name': 'FTP (File Transfer)',
                'use': 'Unencrypted file transfer',
                'common': 'Legacy file servers',
                'why_blocked': 'Insecure - credentials sent in plain text'
            }
        }

        return service_info.get(str(port), {
            'name': service or f'Port {port}',
            'use': 'Unknown service',
            'common': 'Check port documentation',
            'why_blocked': 'Firewall rule or default deny policy'
        })

    def render_operator_panel(self, width, height):
        """Render detailed operator statistics panel - replaces globe with red panel"""
        screen = [[(' ', 0, False) for _ in range(width)] for _ in range(height)]

        # Get connections from log parser
        connections = self.log_parser.get_connections() if hasattr(self.log_parser, 'get_connections') else []

        # Calculate statistics
        total_connections = len(connections)
        tcp_count = sum(1 for c in connections if hasattr(c, 'protocol') and c.protocol == 'TCP')
        udp_count = sum(1 for c in connections if hasattr(c, 'protocol') and c.protocol == 'UDP')
        icmp_count = sum(1 for c in connections if hasattr(c, 'protocol') and c.protocol == 'ICMP')

        # Count by threat level
        safe_count = sum(1 for c in connections if hasattr(c, 'threat_level') and c.threat_level == 'SAFE/ISP')
        cloud_count = sum(1 for c in connections if hasattr(c, 'threat_level') and c.threat_level == 'CLOUD')
        hosting_count = sum(1 for c in connections if hasattr(c, 'threat_level') and c.threat_level == 'HOSTING')
        local_count = sum(1 for c in connections if hasattr(c, 'threat_level') and c.threat_level == 'LOCAL')
        unknown_count = sum(1 for c in connections if hasattr(c, 'threat_level') and c.threat_level == 'UNKNOWN')

        # Top source IPs
        ip_counts = {}
        for c in connections:
            if hasattr(c, 'ip'):
                ip_counts[c.ip] = ip_counts.get(c.ip, 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Top destination ports
        port_counts = {}
        for c in connections:
            if hasattr(c, 'port'):
                port_counts[c.port] = port_counts.get(c.port, 0) + 1
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Port scan detection
        scan_count = sum(1 for c in connections if hasattr(c, 'attack_type') and c.attack_type == 'PORT SCAN')

        # Build text content
        lines = [
            "═══════════════════════════════════════════════════════════",
            "OPERATOR MODE - DETAILED VIEW".center(59),
            "═══════════════════════════════════════════════════════════",
            "",
            "CONNECTION STATISTICS:",
            f"  Total Connections: {total_connections}",
            f"  TCP: {tcp_count}  │  UDP: {udp_count}  │  ICMP: {icmp_count}",
            "",
            "THREAT LEVEL BREAKDOWN:",
            f"  SAFE/ISP:  {safe_count:3d}  (Residential)",
            f"  CLOUD:     {cloud_count:3d}  (AWS, Azure, GCP)",
            f"  HOSTING:   {hosting_count:3d}  (VPS, Dedicated)",
            f"  LOCAL:     {local_count:3d}  (Private Network)",
            f"  UNKNOWN:   {unknown_count:3d}  (Unclassified)",
            "",
            "PORT SCAN DETECTION:",
            f"  Scan Attempts: {scan_count}",
            "",
            "TOP 5 SOURCE IPs:",
        ]

        if top_ips:
            for ip, count in top_ips:
                lines.append(f"  {ip:<18s}  ({count:3d} attempts)")
        else:
            lines.append("  No connections logged")

        lines.extend([
            "",
            "TOP 5 TARGETED PORTS:",
        ])

        if top_ports:
            for port, count in top_ports:
                # Get service name
                service = "Unknown"
                for c in connections:
                    if hasattr(c, 'port') and c.port == port and hasattr(c, 'service'):
                        service = c.service
                        break
                lines.append(f"  Port {port:<5s}  ({service:<10s})  {count:3d} attempts")
        else:
            lines.append("  No ports targeted")

        lines.extend([
            "",
            "FIREWALL STATUS:",
            f"  Log File: {'ACTIVE' if self.use_real_logs else 'INACTIVE'}",
            f"  Demo Mode: {'ENABLED' if self.demo_mode else 'DISABLED'}",
        ])

        # Add detailed analysis section for top threat
        if top_ips and top_ports:
            top_ip = top_ips[0][0]
            top_port = str(top_ports[0][0])

            # Get IP type analysis
            ip_analysis = self.analyze_ip_type(top_ip)

            # Get service information
            service_name = "Unknown"
            for c in connections:
                if hasattr(c, 'port') and str(c.port) == top_port and hasattr(c, 'service'):
                    service_name = c.service
                    break
            service_info = self.get_service_info(top_port, service_name)

            # Get threat level
            threat_level = "UNKNOWN"
            for c in connections:
                if hasattr(c, 'ip') and c.ip == top_ip and hasattr(c, 'threat'):
                    threat_level = c.threat
                    break

            # Build detailed analysis
            lines.extend([
                "",
                "═══════════════════════════════════════════════════════════",
                "DETAILED ANALYSIS - MOST ACTIVE SOURCE".center(59),
                "═══════════════════════════════════════════════════════════",
                "",
                f"SOURCE IP: {top_ip}",
                f"  Type: {ip_analysis['type']}",
                f"  Meaning: {ip_analysis['meaning']}",
                f"  Assessment: {ip_analysis['threat']}",
                f"  Threat Level: {threat_level}",
                "",
                f"TARGET PORT: {top_port} ({service_info['name']})",
                f"  Purpose: {service_info['use']}",
                f"  Common Uses: {service_info['common']}",
                f"  Why Blocked: {service_info['why_blocked']}",
                "",
                "VERDICT:",
            ])

            # Generate verdict based on IP type and threat level
            if ip_analysis['type'].startswith('IPv6 Link-Local') or ip_analysis['type'].startswith('IPv6 Multicast'):
                lines.extend([
                    "  This is NORMAL, HARMLESS local network traffic.",
                    "  Your devices are doing routine network discovery.",
                    "  Not an attack - just standard network operations.",
                ])
            elif ip_analysis['type'].startswith('IPv4 Private') or 'Local' in ip_analysis['type']:
                lines.extend([
                    "  This is LOCAL network traffic (not from internet).",
                    "  Likely from your own devices or network equipment.",
                    "  Generally safe unless you suspect a compromised device.",
                ])
            elif threat_level == 'HOSTING':
                lines.extend([
                    "  CAUTION: This is from a hosting provider/VPS.",
                    "  Often used by automated scanners and attackers.",
                    "  Your firewall is correctly blocking this traffic.",
                ])
            elif threat_level == 'CLOUD':
                lines.extend([
                    "  WARNING: This is from a cloud provider.",
                    "  Could be legitimate service or automated scanner.",
                    "  Monitor for repeated attempts or port scans.",
                ])
            else:
                lines.extend([
                    "  External internet connection attempt detected.",
                    "  Your firewall is blocking this traffic.",
                    "  Monitor the threat level and frequency.",
                ])

        lines.extend([
            "",
            "Press [O] again to return to globe view",
        ])

        # Center and render text
        start_y = max(0, (height - len(lines)) // 2)
        for idx, line in enumerate(lines):
            y = start_y + idx
            if y >= height:
                break
            start_x = max(0, (width - len(line)) // 2)
            for i, char in enumerate(line):
                x = start_x + i
                if x < width:
                    screen[y][x] = (char, 0, False)

        return screen

    def render(self):
        """Render entire dashboard to terminal - builds buffer then outputs ONCE"""
        # Create globe
        globe_width = int(self.term.width * 0.65)
        globe_height = self.term.height - 2

        # Detect resize and clear screen
        if self.globe is None or self.globe.width != globe_width or self.globe.height != globe_height:
            # Clear on resize to prevent artifacts
            print(self.term.home + self.term.clear, end='', flush=True)
            self.globe = Globe(globe_width, globe_height, aspect_ratio=2.0)
            for lat, lon, label in self.test_locations:
                self.globe.add_attack(lat, lon, label)

        rotation = self.get_rotation()
        rainbow = self.theme.get("rainbow", False)
        skittles = self.theme.get("skittles", False)

        # Check render mode priority: Operator > Death Star > Globe
        if self.operator_mode:
            # Render detailed operator statistics panel
            globe_screen = self.render_operator_panel(globe_width, globe_height)
        elif self.death_star_mode:
            # Render Death Star ASCII art instead of globe (with rotation)
            globe_screen = self.render_death_star(globe_width, globe_height, rotation, rainbow, skittles)
        else:
            # Set globe lighting and plus mode states
            self.globe.lighting = self.lighting
            self.globe.plus_mode = self.plus_mode
            globe_screen = self.globe.render(rotation, rainbow, skittles)

        # Build entire frame as a string buffer (like tcell's back buffer)
        output = []

        # Hide cursor at start of each frame (critical for preventing cursor visibility)
        output.append('\033[?25l')

        # Start with home position to ensure we overwrite everything
        output.append(self.term.home)

        # Draw globe panel border (red for operator mode, green otherwise)
        if self.operator_mode:
            globe_color_border = self.term.bright_red
            title = " Operator Mode "
        elif self.death_star_mode:
            globe_color_border = self.get_color(self.theme["globe"])
            title = " Death Star "
        else:
            globe_color_border = self.get_color(self.theme["globe"])
            title = " Attack Globe "
        border_line = "┌" + title + "─" * (globe_width - len(title) - 2) + "┐"
        output.append(self.term.move(0, 0) + globe_color_border(border_line) + '\033[0m')
        # Side borders (will draw bottom after content to prevent flicker)
        for y in range(1, globe_height + 1):
            output.append(self.term.move(y, 0) + globe_color_border("│") + '\033[0m')
            output.append(self.term.move(y, globe_width - 1) + globe_color_border("│") + '\033[0m')

        # Draw globe content (no clearing needed - we overwrite everything)
        globe_color = self.get_color(self.theme["globe"])
        globe_color_dim = self.get_color(self.theme["globe"], dim=True)  # Theme-aware dimmed color

        for y in range(len(globe_screen)):
            # Build entire line then write once
            line_chars = []
            max_x = min(len(globe_screen[y]), globe_width - 2)  # Limit to inner border width
            for x in range(max_x):
                char, color_idx, shaded = globe_screen[y][x]
                if char != ' ':
                    if rainbow or skittles:
                        color = self.get_color("", color_idx, dim=shaded)
                    elif shaded:
                        color = globe_color_dim
                    else:
                        color = globe_color
                    line_chars.append(color(char))
                else:
                    line_chars.append(' ')

            # Write entire line at once
            if line_chars:
                output.append(self.term.move(y + 1, 1) + ''.join(line_chars))

        # Draw globe bottom border AFTER content to prevent flicker
        output.append(self.term.move(globe_height + 1, 0) + globe_color_border("└" + "─" * (globe_width - 2) + "┘") + '\033[0m')

        # Draw feed panel with border (yellow)
        feed_x = globe_width + 2
        feed_width = self.term.width - feed_x - 1
        # Ensure minimum width for feed panel (prevents negative/tiny widths)
        feed_width = max(feed_width, 20)
        feed_height = self.term.height // 2 - 2
        feed_color = self.get_color(self.theme["feed"])

        # Clear panel interior first
        for y in range(1, feed_height):
            output.append(self.term.move(y, feed_x + 1) + ' ' * (feed_width - 2))

        # Top border
        output.append(self.term.move(0, feed_x) + feed_color("┌ Live Feed " + "─" * (feed_width - 13) + "┐") + '\033[0m')
        # Bottom border
        output.append(self.term.move(feed_height, feed_x) + feed_color("└" + "─" * (feed_width - 2) + "┘") + '\033[0m')
        # Side borders
        for y in range(1, feed_height):
            output.append(self.term.move(y, feed_x) + feed_color("│") + '\033[0m')
            output.append(self.term.move(y, feed_x + feed_width - 1) + feed_color("│") + '\033[0m')

        # Feed content - show connection feed with headers
        # Add column headers - Enhanced with STATUS, DST IP, COUNTRY and THREAT
        # Reduced IP widths from 15 to 13 to prevent overflow with long IPv6 addresses
        header = f"{'TIME':<8s} {'SRC IP':<13s} {'DST IP':<13s} {'PORT':<5s} {'PROTO':<5s} {'STATUS':<8s} {'SVC':<7s} {'CC':<3s} {'THREAT':<7s}"
        output.append(self.term.move(1, feed_x + 1) + self.term.bright_yellow(header[:feed_width - 3]))
        output.append(self.term.move(2, feed_x + 1) + feed_color("─" * min(len(header), feed_width - 3)))

        # Show connection feed - use real firewall logs if available
        if self.use_real_logs:
            connections = self.log_parser.get_connections()[-10:]
        else:
            # Fallback to test data if logs unavailable
            connections = list(self.connections)[-10:]

        for i, conn in enumerate(connections):
            y_pos = 3 + i
            if y_pos < feed_height - 1:
                # Extract time from timestamp (HH:MM:SS)
                time_str = ""
                if hasattr(conn, 'timestamp') and conn.timestamp:
                    try:
                        time_str = conn.timestamp.split()[1] if ' ' in conn.timestamp else conn.timestamp[:8]
                    except:
                        time_str = "??:??:??"
                else:
                    time_str = "??:??:??"

                # Get service name
                service = getattr(conn, 'service', getattr(conn, 'username', 'Unknown'))

                # Get country code
                country = getattr(conn, 'country', '??')

                # Get threat level
                threat = getattr(conn, 'threat', 'UNKNOWN')

                # Color code threat level
                if threat == 'SAFE' or threat == 'ISP':
                    threat_color = self.term.green
                elif threat == 'CLOUD':
                    threat_color = self.term.yellow
                elif threat == 'HOSTING':
                    threat_color = self.term.red
                else:
                    threat_color = self.term.white

                # Determine status and color
                status = getattr(conn, 'action', 'DROP')
                if status == 'DROP':
                    status_text = 'BLOCKED'
                    status_color = self.term.red
                elif status == 'ALLOW':
                    status_text = 'ALLOWED'
                    status_color = self.term.green
                else:
                    status_text = status.upper()
                    status_color = self.term.white

                # Build line with enhanced details including STATUS and DST IP
                # Truncate IPs to fit in columns (IPv6 can be very long)
                dst_ip = getattr(conn, 'dst_ip', 'Unknown')
                src_ip_display = conn.ip[:13] if len(conn.ip) > 13 else conn.ip
                dst_ip_display = dst_ip[:13] if len(dst_ip) > 13 else dst_ip
                service_display = service[:7] if len(service) > 7 else service  # Shortened SERVICE to SVC (7 chars)

                line_base = f"{time_str:<8s} {src_ip_display:<13s} {dst_ip_display:<13s} {conn.port:<5s} {conn.protocol:<5s} "
                line_status = f"{status_text:<8s} "
                line_service = f"{service_display:<7s} {country:<3s} "
                line_threat = f"{threat:<7s}"

                # Truncate line to fit within panel width (prevent overflow into globe)
                full_line = line_base + line_status + line_service + line_threat
                max_line_width = feed_width - 3  # Account for borders and padding
                if len(full_line) > max_line_width:
                    full_line = full_line[:max_line_width]

                # Build colored output with proper sections
                # Calculate section lengths for proper coloring after truncation
                base_len = len(line_base)
                status_len = len(line_status)
                service_len = len(line_service)

                if len(full_line) <= base_len:
                    # Only base fits
                    output.append(self.term.move(y_pos, feed_x + 1) + self.term.cyan(full_line))
                elif len(full_line) <= base_len + status_len:
                    # Base + partial status
                    output.append(self.term.move(y_pos, feed_x + 1) +
                                self.term.cyan(full_line[:base_len]) +
                                status_color(full_line[base_len:]))
                elif len(full_line) <= base_len + status_len + service_len:
                    # Base + status + partial service
                    output.append(self.term.move(y_pos, feed_x + 1) +
                                self.term.cyan(full_line[:base_len]) +
                                status_color(full_line[base_len:base_len + status_len]) +
                                self.term.cyan(full_line[base_len + status_len:]))
                else:
                    # Full line: base + status + service + threat
                    output.append(self.term.move(y_pos, feed_x + 1) +
                                self.term.cyan(full_line[:base_len]) +
                                status_color(full_line[base_len:base_len + status_len]) +
                                self.term.cyan(full_line[base_len + status_len:base_len + status_len + service_len]) +
                                threat_color(full_line[base_len + status_len + service_len:]))

        # Draw stats panel with border (cyan)
        stats_y = feed_height + 1
        stats_height = self.term.height - stats_y - 1
        stats_color = self.get_color(self.theme["stats"])

        # Clear panel interior first
        for y in range(stats_y + 1, self.term.height - 1):
            output.append(self.term.move(y, feed_x + 1) + ' ' * (feed_width - 2))

        # Top border
        stats_title = f" Stats - {self.theme['name'].upper()} "
        dashes = max(0, feed_width - len(stats_title) - 2)
        output.append(self.term.move(stats_y, feed_x) + stats_color("┌" + stats_title + "─" * dashes + "┐") + '\033[0m')
        # Side borders
        for y in range(stats_y + 1, self.term.height - 1):
            output.append(self.term.move(y, feed_x) + stats_color("│") + '\033[0m')
            output.append(self.term.move(y, feed_x + feed_width - 1) + stats_color("│") + '\033[0m')
        # Bottom border
        output.append(self.term.move(self.term.height - 1, feed_x) + stats_color("└" + "─" * (feed_width - 2) + "┘") + '\033[0m')

        # System info (neofetch-style without ASCII logo) - updated in background thread
        sys_info = self.sys_info_cache if self.sys_info_cache else {}
        os_name = self.sys_info_os if self.sys_info_os else "Unknown"

        # Get System IP and MAC address (use fake data in screenshot mode)
        if self.screenshot_mode:
            local_ip = "192.168.1.100"
            mac = "00:1a:2b:3c:4d:5e"
            user = "operator"
        else:
            import socket
            import uuid
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
            except:
                local_ip = "Unknown"
                mac = "Unknown"
            user = os.environ.get('USERNAME', os.environ.get('USER', 'user'))

        # Display order for info - expanded list with IP and MAC
        info_keys = ['System IP', 'MAC Addr', 'OS', 'Kernel', 'Architecture', 'BIOS', 'Host', 'Network', 'Terminal',
                     'Resolution', 'Motherboard', 'CPU', 'CPU Load', 'CPU Temp', 'GPU',
                     'RAM', 'Disk', 'Uptime']

        # Add dynamic values to sys_info
        sys_info['System IP'] = local_ip
        sys_info['MAC Addr'] = mac

        # Add Battery if it exists (laptop only)
        if sys_info.get('Battery'):
            info_keys.append('Battery')

        # Render system info display
        row = stats_y + 1

        # User@Host at top (full width)
        hostname_val = sys_info.get('Host', 'unknown')
        user_host = f"{user}@{hostname_val}"
        if len(user_host) > feed_width - 3:
            user_host = user_host[:feed_width - 6] + "..."
        output.append(self.term.move(row, feed_x + 1) + self.term.bright_cyan(user_host))
        output.append(self.term.move(row + 1, feed_x + 1) + stats_color("─" * min(len(user_host), feed_width - 3)))

        # Show system info
        info_start = row + 2
        for i, key in enumerate(info_keys):
            if info_start + i >= self.term.height - 3:  # Stop if we run out of space
                break
            value = sys_info.get(key, 'N/A')
            # Truncate if too long - allow more space for values
            max_value_len = feed_width - len(key) - 5  # key + ": " (2) + margin (3)
            max_value_len = max(max_value_len, 3)  # Ensure minimum of 3 chars for "..."
            if len(value) > max_value_len:
                value = value[:max_value_len - 3] + "..."
            # Display info
            output.append(self.term.move(info_start + i, feed_x + 1) + stats_color(f"{key}: ") + self.term.white(value))

        # Draw stats bottom border AFTER content to prevent flicker
        output.append(self.term.move(self.term.height - 1, feed_x) + stats_color("└" + "─" * (feed_width - 2) + "┘") + '\033[0m')

        # Status at bottom with version display
        status_color = self.term.red if self.paused else self.term.green
        status_text = f"{'PAUSED' if self.paused else 'RUNNING'}"
        legend_text = " | C for legend"
        version_text = f"v{VERSION}"

        # Calculate padding to right-align version
        status_line_length = len(status_text) + len(legend_text)
        available_width = feed_width - 3  # Account for borders
        version_padding = available_width - status_line_length - len(version_text)

        if version_padding > 0:
            # Room for version on same line
            output.append(self.term.move(self.term.height - 2, feed_x + 1) +
                         status_color(status_text) +
                         self.term.cyan(legend_text) +
                         ' ' * version_padding +
                         self.term.bright_black(version_text))
        else:
            # Not enough room, just show status
            output.append(self.term.move(self.term.height - 2, feed_x + 1) +
                         status_color(status_text) +
                         self.term.cyan(legend_text))

        # Draw Attack Details panel (overlay on Live Feed) - Press A to toggle
        if self.show_attack_details:
            # Get latest connection for details
            if self.use_real_logs:
                connections = self.log_parser.get_connections()
            else:
                connections = list(self.connections)

            if connections:
                latest = connections[-1]

                # Panel dimensions (overlay on feed panel, top-right area)
                panel_width = min(feed_width - 4, 50)  # Fit within feed panel with padding
                panel_height = 14
                panel_x = feed_x + 2  # Slight offset from feed border
                panel_y = 2  # Start near top of screen

                # Draw panel with border (cyan on black background for visibility)
                panel_color = self.term.bright_cyan

                # Clear background for panel area (prevent flicker from feed text)
                for clear_y in range(panel_y, panel_y + panel_height + 2):
                    output.append(self.term.move(clear_y, panel_x) + self.term.on_black(' ' * panel_width))

                # Top border
                output.append(self.term.move(panel_y, panel_x) + self.term.on_black + panel_color("┌─ Attack Details " + "─" * (panel_width - 19) + "┐") + '\033[0m')

                # Content lines
                details = [
                    f"IP Address: {latest.ip}",
                    f"Location: {getattr(latest, 'city', 'Unknown')}, {getattr(latest, 'country_full', 'Unknown')} ({getattr(latest, 'country', '??')})",
                    f"ISP/Org: {getattr(latest, 'isp', 'Unknown')}",
                    f"",
                    f"Target Port: {latest.port} ({getattr(latest, 'service', 'Unknown')})",
                    f"Protocol: {latest.protocol}",
                    f"Timestamp: {getattr(latest, 'timestamp', 'Unknown')}",
                    f"",
                    f"Threat Level: {getattr(latest, 'threat', 'UNKNOWN')}",
                    f"Attack Type: {getattr(latest, 'attack_type', 'PROBE')}",
                    f"Attempts: {getattr(latest, 'count', 1)}",
                    f"",
                ]

                for i, line in enumerate(details):
                    y = panel_y + 1 + i
                    # Draw side borders and content - truncate if too long
                    max_content_width = panel_width - 4  # Account for borders and padding
                    if len(line) > max_content_width:
                        line = line[:max_content_width - 3] + "..."
                    padded_line = f" {line:<{panel_width - 4}} "
                    output.append(self.term.move(y, panel_x) + self.term.on_black + panel_color("│") + self.term.white(padded_line) + panel_color("│") + '\033[0m')

                # Bottom border
                bottom_y = panel_y + len(details) + 1
                output.append(self.term.move(bottom_y, panel_x) + self.term.on_black + panel_color("└" + "─" * (panel_width - 2) + "┘") + '\033[0m')
                output.append(self.term.move(bottom_y + 1, panel_x) + self.term.on_black + self.term.bright_yellow(" Press [A] to close ".center(panel_width)) + '\033[0m')

        # Draw toggleable status bar inside globe area (above borders)
        if self.show_legend:
            status_bar = f"[Space]Pause [T]Theme [L]Light [P]Plus [D]DeathStar [O]Operator [A]Details [C]Legend [Q]Quit"
            legend_y = globe_height  # Place inside globe, just above bottom border
            # Fill the globe inner width (between side borders)
            bottom_line = self.term.on_black + self.term.bright_yellow(status_bar.center(globe_width - 2)) + '\033[0m'
            output.append(self.term.move(legend_y, 1) + bottom_line)
        else:
            # Clear the legend line when off
            legend_y = globe_height
            clear_line = ' ' * (globe_width - 2)
            output.append(self.term.move(legend_y, 1) + clear_line)

        # Move cursor to safe position (bottom right, outside visible area) and hide it again
        output.append(self.term.move(self.term.height - 1, self.term.width - 1))
        output.append('\033[?25l')

        # Single write to stdout (like tcell's Show())
        print(''.join(output), end='', flush=True)

    def update_system_info(self):
        """Update system info in background thread"""
        while self.running:
            try:
                if self.screenshot_mode:
                    self.sys_info_cache, self.sys_info_os = get_demo_system_info()
                else:
                    self.sys_info_cache, self.sys_info_os = get_system_info()
                self.sys_info_last_update = time.time()
            except:
                pass
            time.sleep(self.sys_info_update_interval)

    def handle_input(self):
        """Handle keyboard input in background thread"""
        with self.term.cbreak():
            while self.running:
                key = self.term.inkey(timeout=0.05)
                if key:
                    if key.lower() in ('q', 'x') or key.code == self.term.KEY_ESCAPE:
                        self.running = False
                    elif key == ' ':
                        if self.paused:
                            self.start_time = time.time() - (self.pause_rotation / (-2 * math.pi)) * self.rotation_period
                        else:
                            self.pause_rotation = self.get_rotation()
                        self.paused = not self.paused
                    elif key.lower() == 't':
                        self.cycle_theme()
                    elif key.lower() == 'l':
                        self.lighting = not self.lighting
                    elif key.lower() == 'p':
                        self.plus_mode = not self.plus_mode
                    elif key.lower() == 'c':
                        self.show_legend = not self.show_legend
                    elif key.lower() == 'd':
                        self.death_star_mode = not self.death_star_mode
                    elif key.lower() == 'a':
                        self.show_attack_details = not self.show_attack_details
                    elif key.lower() == 'o':
                        self.operator_mode = not self.operator_mode

    def run(self):
        """Main run loop"""
        # Start firewall log monitoring if available
        if self.use_real_logs:
            self.log_parser.start()
        else:
            # Add test connections as fallback
            Connection = type('Connection', (), {})
            self.connections = deque(maxlen=20)

            conn1 = Connection()
            conn1.ip = '192.168.1.100'
            conn1.username = 'SSH'
            conn1.password = 'TCP'
            self.connections.append(conn1)

            conn2 = Connection()
            conn2.ip = '10.0.0.55'
            conn2.username = 'RDP'
            conn2.password = 'TCP'
            self.connections.append(conn2)

            conn3 = Connection()
            conn3.ip = '172.16.0.99'
            conn3.username = 'PORT SCAN'
            conn3.password = '8 ports'
            self.connections.append(conn3)

        # Initialize system info immediately (especially for screenshot mode)
        if self.screenshot_mode:
            self.sys_info_cache, self.sys_info_os = get_demo_system_info()
        else:
            try:
                self.sys_info_cache, self.sys_info_os = get_system_info()
            except:
                pass

        # Start background threads
        input_thread = threading.Thread(target=self.handle_input, daemon=True)
        input_thread.start()

        sysinfo_thread = threading.Thread(target=self.update_system_info, daemon=True)
        sysinfo_thread.start()

        # Enter fullscreen mode ONCE, hide cursor ONCE
        # Use explicit ANSI escape code for cursor hiding (more reliable than blessed)
        print('\033[?25l', end='', flush=True)  # Hide cursor
        with self.term.fullscreen(), self.term.hidden_cursor():
            try:
                while self.running:
                    frame_start = time.time()
                    self.render()

                    # Maintain 20 FPS for smooth animation (~50ms per frame)
                    elapsed = time.time() - frame_start
                    sleep_time = max(0, 0.050 - elapsed)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
            except KeyboardInterrupt:
                pass
            finally:
                self.running = False
                # Restore cursor on exit
                print('\033[?25h', end='', flush=True)  # Show cursor


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Network Attack Dashboard (Blessed - No Flicker)")
    parser.add_argument("--theme", choices=["matrix", "amber", "nord", "dracula", "mono", "rainbow", "skittles"],
                        default="matrix", help="Color theme (default: matrix)")
    parser.add_argument("--rotation", type=int, default=50,
                        help="Globe rotation period in seconds (default: 50)")
    parser.add_argument("--log-path", type=str, default=None,
                        help="Custom firewall log file path (auto-detected if not specified)")
    parser.add_argument("--demo", action="store_true",
                        help="Enable demo mode with simulated attack traffic")
    parser.add_argument("--demo-screenshot", action="store_true",
                        help="Enable screenshot demo mode with immediate diverse fake data (perfect for README photos)")
    args = parser.parse_args()

    # DEATH STAR pixelate-in effect
    print("\033[2J\033[H")  # Clear screen

    death_star_text = r"""
    ██████╗  ███████╗  █████╗  ████████╗ ██╗  ██╗     ███████╗ ████████╗  █████╗  ██████╗
    ██████╗  ███████╗  █████╗  ████████╗ ██╗  ██╗     ███████╗ ████████╗  █████╗  ██████╗
    ██╔══██╗ ██╔════╝ ██╔══██╗ ╚══██╔══╝ ██║  ██║     ██╔════╝ ╚══██╔══╝ ██╔══██╗ ██╔══██╗
    ██╔══██╗ ██╔════╝ ██╔══██╗ ╚══██╔══╝ ██║  ██║     ██╔════╝ ╚══██╔══╝ ██╔══██╗ ██╔══██╗
    ██║  ██║ █████╗   ███████║    ██║    ███████║     ███████╗    ██║    ███████║ ██████╔╝
    ██║  ██║ █████╗   ███████║    ██║    ███████║     ███████╗    ██║    ███████║ ██████╔╝
    ██║  ██║ ██╔══╝   ██╔══██║    ██║    ██╔══██║     ╚════██║    ██║    ██╔══██║ ██╔══██╗
    ██║  ██║ ██╔══╝   ██╔══██║    ██║    ██╔══██║     ╚════██║    ██║    ██╔══██║ ██╔══██╗
    ██████╔╝ ███████╗ ██║  ██║    ██║    ██║  ██║     ███████║    ██║    ██║  ██║ ██║  ██║
    ██████╔╝ ███████╗ ██║  ██║    ██║    ██║  ██║     ███████║    ██║    ██║  ██║ ██║  ██║
    ╚═════╝  ╚══════╝ ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═╝     ╚══════╝    ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝
    ╚═════╝  ╚══════╝ ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═╝     ╚══════╝    ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝


    """

    lines = death_star_text.strip().split('\n')

    # Pixelate-in effect (6 stages for longer animation)
    import random
    import select
    import sys

    skip_animation = False

    def check_skip():
        """Check if Enter was pressed to skip animation"""
        if sys.platform == 'win32':
            import msvcrt
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key in (b'\r', b'\n'):
                    return True
        else:
            # Unix/Linux
            if select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.read(1)
                if key in ('\r', '\n'):
                    return True
        return False

    # Stage 1: Random noise (15% visible)
    print("\033[31m")  # Red
    for line in lines:
        pixelated = ''.join(c if random.random() < 0.15 else ' ' for c in line)
        print(pixelated)
    if check_skip():
        skip_animation = True

    if not skip_animation:
        time.sleep(0.4)

        # Stage 2: More visible (30% visible)
        print("\033[2J\033[H")
        print("\033[31m")
        for line in lines:
            pixelated = ''.join(c if random.random() < 0.3 else ' ' for c in line)
            print(pixelated)
        if check_skip():
            skip_animation = True

    if not skip_animation:
        time.sleep(0.4)

        # Stage 3: Half visible (50% visible)
        print("\033[2J\033[H")
        print("\033[31m")
        for line in lines:
            pixelated = ''.join(c if random.random() < 0.5 else ' ' for c in line)
            print(pixelated)
        if check_skip():
            skip_animation = True

    if not skip_animation:
        time.sleep(0.4)

        # Stage 4: More complete (70% visible)
        print("\033[2J\033[H")
        print("\033[31m")
        for line in lines:
            pixelated = ''.join(c if random.random() < 0.7 else ' ' for c in line)
            print(pixelated)
        if check_skip():
            skip_animation = True

    if not skip_animation:
        time.sleep(0.4)

        # Stage 5: Almost complete (85% visible)
        print("\033[2J\033[H")
        print("\033[31m")
        for line in lines:
            pixelated = ''.join(c if random.random() < 0.85 else ' ' for c in line)
            print(pixelated)
        if check_skip():
            skip_animation = True

    if not skip_animation:
        time.sleep(0.4)

        # Stage 6: Full reveal
        print("\033[2J\033[H")
        print("\033[31m")
        print(death_star_text)
        print("\033[0m")

        # Show creator credit
        print("\033[2J\033[H")
        print("\033[31m")
        print(death_star_text)
        print("\033[0m")
        print("\033[90m")  # Dark grey color
        print("Created by ringmast4r".center(96))
        print("\033[0m")
        time.sleep(1.5)

    # Use screenshot demo mode if specified, otherwise regular demo
    demo_mode = args.demo or args.demo_screenshot
    dashboard = Dashboard(rotation_period=args.rotation, theme=args.theme, log_path=args.log_path, demo_mode=demo_mode)

    # Only show setup instructions if firewall logs are NOT configured
    if not args.demo and not args.demo_screenshot and not dashboard.use_real_logs:
        print("\033[2J\033[H")
        print("\033[31m")  # Red for error/warning

        # Check if file exists but is stale
        if os.path.exists(dashboard.log_parser.log_path):
            file_stat = os.stat(dashboard.log_parser.log_path)
            file_mtime = file_stat.st_mtime
            time_since_update = time.time() - file_mtime
            print(f"✗ Firewall log file exists but appears INACTIVE: {dashboard.log_parser.log_path}")
            print(f"  Last updated: {int(time_since_update / 60)} minutes ago")
            print(f"  File size: {file_stat.st_size} bytes")
        else:
            print(f"✗ Firewall log file not found: {dashboard.log_parser.log_path}")

        print("\033[33m")  # Yellow for instructions
        print("  Enable firewall logging to monitor real attacks")
        print()
        if sys.platform == 'win32':
            print("  To enable Windows Firewall logging:")
            print()
            print("  From Windows Security:")
            print("    1. Click 'Advanced settings' (blue link on left side)")
            print("       This opens 'Windows Defender Firewall with Advanced Security'")
            print()
            print("  In Advanced Security Window:")
            print("    2. Right-click 'Windows Defender Firewall with Advanced Security'")
            print("       (top of left sidebar)")
            print("    3. Select 'Properties'")
            print()
            print("  In Properties Dialog:")
            print("    4. Click each tab: Domain Profile, Private Profile, Public Profile")
            print("    5. Find 'Logging' section (near bottom)")
            print("    6. Click 'Customize...' button")
            print("    7. Change 'Log dropped packets' from No to YES")
            print("    8. Click OK")
            print("    9. Repeat steps 4-8 for all 3 profiles")
            print("    10. Click Apply, then OK")
            print()
            print("  Quick shortcut: Press Win+R, type 'wf.msc', press Enter")
        print()
        print("\033[36m")  # Cyan
        print("  OR run with --demo flag to see simulated traffic:")
        print("  python dashboard.py --demo")
        print("\033[0m")
        print()
        print("\033[33m")  # Yellow
        print("═" * 70)
        print("WARNING: Firewall logging appears to be DISABLED or INACTIVE")
        print("═" * 70)
        print("\033[0m")
        print()

        # Prompt user for confirmation
        print("\033[36mDo you want to:\033[0m")
        print("  \033[32m[1]\033[0m Continue to dashboard anyway (no real attack data)")
        print("  \033[31m[2]\033[0m Exit and configure firewall logging")
        print()

        try:
            choice = input("\033[33mEnter choice (1 or 2): \033[0m").strip()
            if choice == '2':
                print("\033[36m")
                print("Exiting... Please configure firewall logging and restart DEATH STAR.")
                print("Quick shortcut: Press Win+R, type 'wf.msc', press Enter")
                print("\033[0m")
                sys.exit(0)
            elif choice != '1':
                print("\033[31mInvalid choice. Exiting...\033[0m")
                sys.exit(1)
            # If choice is '1', enable demo mode and continue
            print("\033[33mContinuing in DEMO MODE (simulated traffic)...\033[0m")
            print()
            # Enable demo mode in the dashboard
            dashboard.demo_mode = True
            dashboard.log_parser.demo_mode = True
            # Start demo traffic generation
            import threading
            demo_thread = threading.Thread(target=dashboard.log_parser.generate_demo_traffic, daemon=True)
            demo_thread.start()
        except (KeyboardInterrupt, EOFError):
            print("\n\033[31mExiting...\033[0m")
            sys.exit(0)
    # If demo or real logs are working, start immediately without delay

    try:
        dashboard.run()
    finally:
        # Ensure cursor is always restored on exit
        print('\033[?25h', end='', flush=True)


if __name__ == "__main__":
    main()
