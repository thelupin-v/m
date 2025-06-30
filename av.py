#!/usr/bin/env python3
"""
VTX Antivirus - Sophisticated Real-time Protection System
A comprehensive antivirus solution with file scanning, web protection, and system monitoring.
"""

import sys
import os
import json
import time
import threading
import socket
import subprocess
import signal
import hashlib
import base64
import sqlite3
from pathlib import Path
from datetime import datetime
import logging
import configparser
from typing import Dict, List, Optional, Tuple

# GUI and System
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                              QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                              QProgressBar, QSystemTrayIcon, QMenu, QDialog,
                              QMessageBox, QFrame, QGridLayout, QListWidget,
                              QTabWidget, QGroupBox, QCheckBox, QSpinBox,
                              QFileDialog, QDialogButtonBox)
from PySide6.QtCore import (QTimer, QThread, Signal, QSystemSemaphore,
                           QSharedMemory, Qt, QPropertyAnimation, QRect,
                           QEasingCurve, QSequentialAnimationGroup, QSize)
from PySide6.QtGui import (QIcon, QPixmap, QPainter, QFont, QColor, QPen,
                          QBrush, QLinearGradient, QMovie, QPalette)

# Security and Networking
import requests
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Antivirus Components
try:
    import pyclamd
except ImportError:
    pyclamd = None

try:
    import tgcrypto
except ImportError:
    tgcrypto = None

try:
    import qtawesome as qta
    QTA_AVAILABLE = True
except ImportError:
    QTA_AVAILABLE = False

# Mitmproxy integration
try:
    from mitmproxy import options, master
    from mitmproxy.addons import core
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

# Configuration
CONFIG_DIR = Path.home() / '.vtx'
QUARANTINE_DIR = CONFIG_DIR / 'quarantine'
LOGS_DIR = CONFIG_DIR / 'logs'
DB_PATH = CONFIG_DIR / 'vtx.db'
CERT_PATH = Path.home() / 'Stažené' / 'mitmproxy-ca-cert.pem'

# Encryption key for quarantine
ENCRYPTION_KEY = bytes.fromhex('eeef64a99c54822173ddd8f895e0a43273dc0e4a44ca9560052fb5a76b2fd8f7')

# Known phishing URLs (sample from the request)
PHISHING_URLS = {
    'portfolio-trezor-cdn.webflow.io',
    'agodahotelmall.com',
    'refundagoda.life',
    'parmagicl.com',
    'shanghaianlong.com',
    'agodamall.net',
    'stmpx0-gm.myshopify.com',
    '888nyw.com',
    'verifications.smcavalier.com',
    'coupangshopag.shop',
    'thanhtoanhoahongcoupangltd.com',
    'galxboysa.com',
    'allegro.pi-993120462528302.rest'
}

# Warning injection script
WARNING_SCRIPT = """
<script>
(function() {
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(255,0,0,0.95)";
    overlay.style.zIndex = 999999;
    overlay.style.color = "#fff";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.style.fontFamily = "Arial, sans-serif";
    overlay.innerHTML = `
        <div style="text-align: center; max-width: 600px; padding: 40px;">
            <h1 style="font-size: 48px; margin: 0; color: #ff4444;">⚠️ DANGEROUS WEBSITE</h1>
            <p style="font-size: 24px; margin: 20px 0;">This website has been flagged as potentially malicious by VTX Antivirus.</p>
            <p style="font-size: 18px; margin: 20px 0; color: #ffaa00;">The site may contain phishing, malware, or other security threats.</p>
            <div style="margin-top: 40px;">
                <button onclick="history.back()" style="margin: 10px; padding: 15px 30px; font-size: 18px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer;">Go Back</button>
                <button onclick="location.href='https://www.google.com'" style="margin: 10px; padding: 15px 30px; font-size: 18px; background: #2196F3; color: white; border: none; border-radius: 5px; cursor: pointer;">Go to Google</button>
            </div>
            <p style="font-size: 14px; margin-top: 30px; color: #ccc;">Protected by VTX Antivirus</p>
        </div>
    `;
    document.body.appendChild(overlay);
})();
</script>
"""

# Setup logging
def setup_logging():
    """Setup comprehensive logging system"""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Configure main logger
    logger = logging.getLogger('vtx')
    logger.setLevel(logging.DEBUG)
    
    # File handler
    file_handler = logging.FileHandler(LOGS_DIR / 'vtx.log')
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

class DatabaseManager:
    """Manages SQLite database for threats, quarantine, and logs"""
    
    def __init__(self):
        self.db_path = DB_PATH
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                threat_name TEXT,
                detected_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_taken TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT
            )
        ''')
        
        # Quarantine table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                threat_name TEXT,
                quarantine_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER,
                hash_md5 TEXT,
                hash_sha256 TEXT
            )
        ''')
        
        # URL blocks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                block_reason TEXT,
                block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_action TEXT
            )
        ''')
        
        # System events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_threat(self, filename, filepath, threat_type, threat_name=None, action_taken=None):
        """Log detected threat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Calculate file hashes if file exists
        md5_hash = sha256_hash = None
        if os.path.exists(filepath):
            try:
                with open(filepath, 'rb') as f:
                    content = f.read()
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
            except Exception as e:
                logger.error(f"Error calculating hashes for {filepath}: {e}")
        
        cursor.execute('''
            INSERT INTO threats (filename, filepath, threat_type, threat_name, action_taken, hash_md5, hash_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (filename, filepath, threat_type, threat_name, action_taken, md5_hash, sha256_hash))
        
        conn.commit()
        conn.close()
    
    def log_quarantine(self, original_path, quarantine_path, threat_name=None):
        """Log quarantined file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        file_size = 0
        md5_hash = sha256_hash = None
        
        if os.path.exists(original_path):
            try:
                file_size = os.path.getsize(original_path)
                with open(original_path, 'rb') as f:
                    content = f.read()
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
            except Exception as e:
                logger.error(f"Error getting file info for {original_path}: {e}")
        
        cursor.execute('''
            INSERT INTO quarantine (original_path, quarantine_path, threat_name, file_size, hash_md5, hash_sha256)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (original_path, quarantine_path, threat_name, file_size, md5_hash, sha256_hash))
        
        conn.commit()
        conn.close()

class VirusTotalChecker:
    """VirusTotal API integration for URL and file checking"""
    
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key_here')
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
    
    def check_url(self, url: str) -> Dict:
        """Check URL against VirusTotal database"""
        try:
            params = {
                'apikey': self.api_key,
                'resource': url
            }
            
            response = requests.get(f'{self.base_url}/url/report', params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error checking URL with VirusTotal: {e}")
            return {}
    
    def check_file(self, file_path: str) -> Dict:
        """Check file against VirusTotal database"""
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(f'{self.base_url}/file/report', params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error checking file with VirusTotal: {e}")
            return {}

class QuarantineManager:
    """Handles file quarantine with AES-256-IGE encryption"""
    
    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        self.db = DatabaseManager()
    
    def quarantine_file(self, file_path: str, threat_name: str = None) -> bool:
        """Move file to quarantine with encryption"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found for quarantine: {file_path}")
                return False
            
            # Generate unique quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
            quarantine_filename = f"{timestamp}_{file_hash}.vtx"
            quarantine_path = QUARANTINE_DIR / quarantine_filename
            
            # Read original file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt with AES-256-IGE if tgcrypto available
            if tgcrypto:
                try:
                    # Pad data to 16-byte boundary
                    pad_length = 16 - (len(file_data) % 16)
                    if pad_length != 16:
                        file_data += bytes([pad_length]) * pad_length
                    
                    # Generate IV (16 bytes for AES)
                    iv = os.urandom(16)
                    
                    # Encrypt data
                    encrypted_data = tgcrypto.ige256_encrypt(file_data, ENCRYPTION_KEY, iv)
                    
                    # Store IV + encrypted data
                    final_data = iv + encrypted_data
                    
                except Exception as e:
                    logger.error(f"Encryption failed, storing unencrypted: {e}")
                    final_data = file_data
            else:
                logger.warning("tgcrypto not available, storing unencrypted")
                final_data = file_data
            
            # Write to quarantine
            with open(quarantine_path, 'wb') as f:
                f.write(final_data)
            
            # Log quarantine
            self.db.log_quarantine(file_path, str(quarantine_path), threat_name)
            
            # Remove original file
            os.remove(file_path)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def restore_file(self, quarantine_id: int, restore_path: str) -> bool:
        """Restore file from quarantine"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('SELECT quarantine_path FROM quarantine WHERE id = ?', (quarantine_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                logger.error(f"Quarantine record not found: {quarantine_id}")
                return False
            
            quarantine_path = result[0]
            
            if not os.path.exists(quarantine_path):
                logger.error(f"Quarantine file not found: {quarantine_path}")
                return False
            
            # Read quarantined file
            with open(quarantine_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt if tgcrypto available
            if tgcrypto and len(encrypted_data) > 16:
                try:
                    # Extract IV and encrypted data
                    iv = encrypted_data[:16]
                    encrypted_content = encrypted_data[16:]
                    
                    # Decrypt
                    decrypted_data = tgcrypto.ige256_decrypt(encrypted_content, ENCRYPTION_KEY, iv)
                    
                    # Remove padding
                    if len(decrypted_data) > 0:
                        pad_length = decrypted_data[-1]
                        if pad_length <= 16:
                            decrypted_data = decrypted_data[:-pad_length]
                    
                    file_data = decrypted_data
                    
                except Exception as e:
                    logger.error(f"Decryption failed, using raw data: {e}")
                    file_data = encrypted_data
            else:
                file_data = encrypted_data
            
            # Write restored file
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            with open(restore_path, 'wb') as f:
                f.write(file_data)
            
            logger.info(f"File restored: {quarantine_path} -> {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring file: {e}")
            return False

class ClamAVScanner:
    """ClamAV integration for file scanning"""
    
    def __init__(self):
        self.clamd = None
        self.available = False
        self.init_clamav()
    
    def init_clamav(self):
        """Initialize ClamAV connection"""
        if not pyclamd:
            logger.warning("pyclamd not available")
            return
        
        try:
            # Try different ClamAV socket paths
            socket_paths = [
                '/var/run/clamav/clamd.ctl',
                '/tmp/clamd.socket',
                '/var/run/clamd.scan/clamd.sock'
            ]
            
            for socket_path in socket_paths:
                try:
                    self.clamd = pyclamd.ClamdUnixSocket(socket_path)
                    if self.clamd.ping():
                        self.available = True
                        logger.info(f"ClamAV connected via {socket_path}")
                        return
                except:
                    continue
            
            # Try network connection
            try:
                self.clamd = pyclamd.ClamdNetworkSocket()
                if self.clamd.ping():
                    self.available = True
                    logger.info("ClamAV connected via network socket")
                    return
            except:
                pass
            
            logger.warning("ClamAV daemon not accessible")
            
        except Exception as e:
            logger.error(f"Error initializing ClamAV: {e}")
    
    def scan_file(self, file_path: str) -> Tuple[bool, str]:
        """Scan single file with ClamAV"""
        if not self.available:
            return False, "ClamAV not available"
        
        try:
            result = self.clamd.scan_file(file_path)
            
            if result is None:
                return False, "Clean"
            
            # Result format: {filepath: ('FOUND', 'threat_name')}
            for path, (status, threat) in result.items():
                if status == 'FOUND':
                    return True, threat
            
            return False, "Clean"
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return False, f"Scan error: {e}"

class NetworkMonitor:
    """Network monitoring and firewall functionality"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_domains = set()
        self.monitoring = False
    
    def start_monitoring(self):
        """Start network monitoring"""
        self.monitoring = True
        threading.Thread(target=self._monitor_connections, daemon=True).start()
        logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        logger.info("Network monitoring stopped")
    
    def _monitor_connections(self):
        """Monitor active network connections"""
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        
                        # Check against blocked IPs
                        if remote_ip in self.blocked_ips:
                            logger.warning(f"Blocked connection attempt to {remote_ip}")
                            # In real implementation, this would block the connection
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error monitoring connections: {e}")
                time.sleep(10)
    
    def block_ip(self, ip: str):
        """Add IP to block list"""
        self.blocked_ips.add(ip)
        logger.info(f"IP blocked: {ip}")
    
    def block_domain(self, domain: str):
        """Add domain to block list"""
        self.blocked_domains.add(domain)
        logger.info(f"Domain blocked: {domain}")

class HardwareMonitor:
    """Monitor webcam and microphone access"""
    
    def __init__(self, parent_window=None):
        self.monitoring = False
        self.parent_window = parent_window
        self.active_processes = set()
    
    def start_monitoring(self):
        """Start hardware access monitoring"""
        self.monitoring = True
        threading.Thread(target=self._monitor_hardware, daemon=True).start()
        logger.info("Hardware monitoring started")
    
    def stop_monitoring(self):
        """Stop hardware access monitoring"""
        self.monitoring = False
        logger.info("Hardware monitoring stopped")
    
    def _monitor_hardware(self):
        """Monitor processes accessing webcam/microphone"""
        while self.monitoring:
            try:
                current_processes = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        # Check for webcam/mic usage indicators
                        cmdline = ' '.join(proc.info['cmdline'] or [])
                        name = proc.info['name']
                        
                        # Common indicators of camera/mic usage
                        camera_indicators = [
                            '/dev/video', 'v4l2', 'camera', 'webcam',
                            'libv4l', 'uvcvideo'
                        ]
                        
                        mic_indicators = [
                            'alsa', 'pulse', 'microphone', 'audio',
                            '/dev/dsp', 'record'
                        ]
                        
                        hardware_access = False
                        access_type = ""
                        
                        for indicator in camera_indicators:
                            if indicator in cmdline.lower() or indicator in name.lower():
                                hardware_access = True
                                access_type = "camera"
                                break
                        
                        if not hardware_access:
                            for indicator in mic_indicators:
                                if indicator in cmdline.lower() or indicator in name.lower():
                                    hardware_access = True
                                    access_type = "microphone"
                                    break
                        
                        if hardware_access:
                            proc_id = (proc.info['pid'], name, access_type)
                            current_processes.add(proc_id)
                            
                            if proc_id not in self.active_processes:
                                self._notify_hardware_access(name, access_type, proc.info['pid'])
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self.active_processes = current_processes
                time.sleep(3)
                
            except Exception as e:
                logger.error(f"Error monitoring hardware: {e}")
                time.sleep(10)
    
    def _notify_hardware_access(self, process_name: str, access_type: str, pid: int):
        """Notify user of hardware access attempt"""
        message = f"Process '{process_name}' (PID: {pid}) is trying to access {access_type}"
        logger.warning(message)
        
        if self.parent_window:
            # Show notification dialog
            try:
                from PySide6.QtCore import QMetaObject, Qt
                QMetaObject.invokeMethod(
                    self.parent_window,
                    "_show_hardware_notification",
                    Qt.QueuedConnection,
                    message, process_name, access_type, pid
                )
            except Exception as e:
                logger.error(f"Error showing hardware notification: {e}")

class ProxyManager:
    """Manages mitmproxy for HTTPS/HTTP interception"""
    
    def __init__(self):
        self.proxy_process = None
        self.proxy_port = 8080
        self.cert_path = CERT_PATH
        self.running = False
    
    def start_proxy(self):
        """Start mitmproxy with certificate"""
        if not MITMPROXY_AVAILABLE:
            logger.error("mitmproxy not available")
            return False
        
        try:
            # Configure Firefox proxy
            self._configure_firefox_proxy()
            
            # Start proxy in separate process
            cmd = [
                'mitmdump',
                '--listen-port', str(self.proxy_port),
                '--set', f'confdir={CONFIG_DIR}',
                '--scripts', self._create_proxy_script()
            ]
            
            if self.cert_path.exists():
                cmd.extend(['--set', f'certs={self.cert_path}'])
            
            self.proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(CONFIG_DIR)
            )
            
            self.running = True
            logger.info(f"Proxy started on port {self.proxy_port}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting proxy: {e}")
            return False
    
    def stop_proxy(self):
        """Stop mitmproxy"""
        if self.proxy_process:
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=10)
                self.running = False
                logger.info("Proxy stopped")
                
                # Remove Firefox proxy
                self._remove_firefox_proxy()
                
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
                logger.warning("Proxy force killed")
            except Exception as e:
                logger.error(f"Error stopping proxy: {e}")
    
    def _create_proxy_script(self) -> str:
        """Create mitmproxy script for URL filtering"""
        script_path = CONFIG_DIR / 'proxy_script.py'
        
        script_content = f'''
import logging
from mitmproxy import http

# Phishing URLs to block
PHISHING_URLS = {PHISHING_URLS}

WARNING_SCRIPT = """{WARNING_SCRIPT}"""

def request(flow: http.HTTPFlow) -> None:
    """Intercept and check requests"""
    url = flow.request.pretty_url
    host = flow.request.pretty_host
    
    # Check against phishing database
    if any(phish_url in host for phish_url in PHISHING_URLS):
        logging.warning(f"Blocked phishing URL: {{url}}")
        
        # Return warning page
        flow.response = http.Response.make(
            200,
            f"<html><head><title>VTX Warning</title></head><body>{{WARNING_SCRIPT}}</body></html>",
            {{"Content-Type": "text/html"}}
        )
        return
    
    # Log URL access
    logging.info(f"URL accessed: {{url}}")

def response(flow: http.HTTPFlow) -> None:
    """Process responses"""
    # Additional response processing could go here
    pass
'''
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        return str(script_path)
    
    def _configure_firefox_proxy(self):
        """Configure Firefox to use our proxy"""
        try:
            # Find Firefox profile directory
            firefox_dir = Path.home() / '.mozilla' / 'firefox'
            
            if not firefox_dir.exists():
                logger.warning("Firefox profile directory not found")
                return
            
            # Find default profile
            profiles_ini = firefox_dir / 'profiles.ini'
            if profiles_ini.exists():
                config = configparser.ConfigParser()
                config.read(profiles_ini)
                
                for section in config.sections():
                    if 'Profile' in section and config.get(section, 'Default', fallback='') == '1':
                        profile_path = firefox_dir / config.get(section, 'Path')
                        self._set_firefox_proxy_prefs(profile_path)
                        break
        
        except Exception as e:
            logger.error(f"Error configuring Firefox proxy: {e}")
    
    def _set_firefox_proxy_prefs(self, profile_path: Path):
        """Set Firefox proxy preferences"""
        try:
            prefs_file = profile_path / 'user.js'
            
            proxy_prefs = f'''
// VTX Antivirus Proxy Configuration
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", {self.proxy_port});
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", {self.proxy_port});
user_pref("network.proxy.share_proxy_settings", true);
'''
            
            with open(prefs_file, 'w') as f:
                f.write(proxy_prefs)
            
            logger.info("Firefox proxy configured")
            
        except Exception as e:
            logger.error(f"Error setting Firefox proxy preferences: {e}")
    
    def _remove_firefox_proxy(self):
        """Remove Firefox proxy configuration"""
        try:
            firefox_dir = Path.home() / '.mozilla' / 'firefox'
            profiles_ini = firefox_dir / 'profiles.ini'
            
            if profiles_ini.exists():
                config = configparser.ConfigParser()
                config.read(profiles_ini)
                
                for section in config.sections():
                    if 'Profile' in section and config.get(section, 'Default', fallback='') == '1':
                        profile_path = firefox_dir / config.get(section, 'Path')
                        prefs_file = profile_path / 'user.js'
                        
                        if prefs_file.exists():
                            prefs_file.unlink()
                            logger.info("Firefox proxy configuration removed")
                        break
        
        except Exception as e:
            logger.error(f"Error removing Firefox proxy: {e}")

class FileSystemWatcher(FileSystemEventHandler):
    """Real-time file system monitoring"""
    
    def __init__(self, scanner_callback):
        super().__init__()
        self.scanner_callback = scanner_callback
        self.watch_dirs = [
            str(Path.home() / 'Downloads'),
            str(Path.home() / 'Stažené'),
            '/tmp',
            '/var/tmp'
        ]
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        # Schedule scan after short delay to ensure file is fully written
        threading.Timer(2.0, self._scan_file, args=[event.src_path]).start()
    
    def on_moved(self, event):
        """Handle file move events"""
        if event.is_directory:
            return
        
        threading.Timer(1.0, self._scan_file, args=[event.dest_path]).start()
    
    def _scan_file(self, file_path: str):
        """Scan file with callback"""
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                self.scanner_callback(file_path)
        except Exception as e:
            logger.error(f"Error in file scan callback: {e}")

class FloatingWatermark(QWidget):
    """Always-on-top floating watermark with STOP button"""
    
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.setup_ui()
        self.setup_animations()
    
    def setup_ui(self):
        """Setup floating watermark UI"""
        self.setWindowFlags(
            Qt.WindowStaysOnTopHint | 
            Qt.FramelessWindowHint | 
            Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(120, 40)
        
        # Position in top-right corner
        screen = QApplication.primaryScreen().availableGeometry()
        self.move(screen.width() - 130, 10)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # VTX label
        self.vtx_label = QLabel("🛡️ VTX")
        self.vtx_label.setStyleSheet("""
            QLabel {
                color: #00ff00;
                font-weight: bold;
                font-size: 12px;
                background: rgba(0, 0, 0, 150);
                border-radius: 3px;
                padding: 2px 5px;
            }
        """)
        
        # STOP button
        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setFixedSize(35, 25)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background: #ff4444;
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #ff6666;
            }
            QPushButton:pressed {
                background: #cc3333;
            }
        """)
        self.stop_btn.clicked.connect(self.parent_window.emergency_stop)
        
        layout.addWidget(self.vtx_label)
        layout.addWidget(self.stop_btn)
    
    def setup_animations(self):
        """Setup pulsing animation"""
        self.pulse_animation = QPropertyAnimation(self, b"windowOpacity")
        self.pulse_animation.setDuration(2000)
        self.pulse_animation.setStartValue(0.7)
        self.pulse_animation.setEndValue(1.0)
        self.pulse_animation.setEasingCurve(QEasingCurve.InOutSine)
        
        # Create looping animation
        self.animation_group = QSequentialAnimationGroup()
        
        # Fade in
        fade_in = QPropertyAnimation(self, b"windowOpacity")
        fade_in.setDuration(1000)
        fade_in.setStartValue(0.7)
        fade_in.setEndValue(1.0)
        
        # Fade out
        fade_out = QPropertyAnimation(self, b"windowOpacity")
        fade_out.setDuration(1000)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.7)
        
        self.animation_group.addAnimation(fade_in)
        self.animation_group.addAnimation(fade_out)
        self.animation_group.setLoopCount(-1)  # Infinite loop
        
        self.animation_group.start()

class ThreatDialog(QDialog):
    """Dialog for handling detected threats"""
    
    def __init__(self, threat_info, parent=None):
        super().__init__(parent)
        self.threat_info = threat_info
        self.user_action = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup threat dialog UI"""
        self.setWindowTitle("VTX - Threat Detected")
        self.setFixedSize(500, 350)
        self.setModal(True)
        
        # Make dialog stay on top
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
        
        layout = QVBoxLayout(self)
        
        # Warning header
        header = QLabel("⚠️ THREAT DETECTED")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                color: #ff4444;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                background: rgba(255, 68, 68, 20);
                border-radius: 5px;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(header)
        
        # Threat details
        details_group = QGroupBox("Threat Information")
        details_layout = QGridLayout(details_group)
        
        details_layout.addWidget(QLabel("File:"), 0, 0)
        details_layout.addWidget(QLabel(self.threat_info.get('filename', 'Unknown')), 0, 1)
        
        details_layout.addWidget(QLabel("Path:"), 1, 0)
        path_label = QLabel(self.threat_info.get('filepath', 'Unknown'))
        path_label.setWordWrap(True)
        details_layout.addWidget(path_label, 1, 1)
        
        details_layout.addWidget(QLabel("Threat:"), 2, 0)
        details_layout.addWidget(QLabel(self.threat_info.get('threat_name', 'Unknown')), 2, 1)
        
        details_layout.addWidget(QLabel("Type:"), 3, 0)
        details_layout.addWidget(QLabel(self.threat_info.get('threat_type', 'Unknown')), 3, 1)
        
        layout.addWidget(details_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        # Quarantine button
        quarantine_btn = QPushButton("🔒 Quarantine")
        quarantine_btn.setStyleSheet("""
            QPushButton {
                background: #ff6600;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #ff8833;
            }
        """)
        quarantine_btn.clicked.connect(lambda: self.set_action('quarantine'))
        
        # Keep button
        keep_btn = QPushButton("📁 Keep File")
        keep_btn.setStyleSheet("""
            QPushButton {
                background: #4CAF50;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #66BB6A;
            }
        """)
        keep_btn.clicked.connect(lambda: self.set_action('keep'))
        
        # Delete button
        delete_btn = QPushButton("🗑️ Delete")
        delete_btn.setStyleSheet("""
            QPushButton {
                background: #f44336;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #e57373;
            }
        """)
        delete_btn.clicked.connect(lambda: self.set_action('delete'))
        
        button_layout.addWidget(quarantine_btn)
        button_layout.addWidget(keep_btn)
        button_layout.addWidget(delete_btn)
        
        layout.addLayout(button_layout)
        
        # Warning message
        warning_msg = QLabel("⚠️ Choose carefully! Keeping infected files may compromise your system security.")
        warning_msg.setWordWrap(True)
        warning_msg.setStyleSheet("""
            QLabel {
                color: #ff8800;
                font-style: italic;
                padding: 10px;
                background: rgba(255, 136, 0, 20);
                border-radius: 3px;
            }
        """)
        layout.addWidget(warning_msg)
    
    def set_action(self, action):
        """Set user action and close dialog"""
        self.user_action = action
        self.accept()

class AVMainWindow(QMainWindow):
    """Main antivirus window"""
    
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.scanner = ClamAVScanner()
        self.quarantine = QuarantineManager()
        self.network_monitor = NetworkMonitor()
        self.hardware_monitor = HardwareMonitor(self)
        self.proxy_manager = ProxyManager()
        self.vt_checker = VirusTotalChecker()
        
        # File system monitoring
        self.file_watcher = FileSystemWatcher(self.scan_file_callback)
        self.observer = Observer()
        
        # GUI state
        self.scanning = False
        self.protection_enabled = True
        
        self.setup_ui()
        self.setup_system_tray()
        self.start_protection()
        
        # Create floating watermark
        self.watermark = FloatingWatermark(self)
        self.watermark.show()
    
    def setup_ui(self):
        """Setup main window UI"""
        self.setWindowTitle("VTX Antivirus - Professional Protection")
        self.setFixedSize(900, 700)
        
        # Set window icon
        if QTA_AVAILABLE:
            try:
                self.setWindowIcon(qta.icon('mdi.shield-check', color='blue'))
            except:
                # Fallback if icon fails
                pass
        
        # Central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background: white;
            }
            QTabBar::tab {
                background: #f0f0f0;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #007acc;
                color: white;
            }
        """)
        
        # Add tabs
        self.tab_widget.addTab(self.create_dashboard_tab(), "🏠 Dashboard")
        self.tab_widget.addTab(self.create_scan_tab(), "🔍 Scan")
        self.tab_widget.addTab(self.create_quarantine_tab(), "🔒 Quarantine")
        self.tab_widget.addTab(self.create_protection_tab(), "🛡️ Protection")
        self.tab_widget.addTab(self.create_logs_tab(), "📋 Logs")
        self.tab_widget.addTab(self.create_settings_tab(), "⚙️ Settings")
        
        layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_label = QLabel("VTX Antivirus Ready")
        self.statusBar().addWidget(self.status_label)
        
        # Apply modern styling
        self.apply_modern_style()
    
    def create_header(self):
        """Create modern header with logo and status"""
        header_widget = QWidget()
        header_widget.setFixedHeight(80)
        header_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1e3c72, stop:1 #2a5298);
                border-radius: 10px;
                margin-bottom: 10px;
            }
        """)
        
        layout = QHBoxLayout(header_widget)
        
        # Logo and title
        title_layout = QVBoxLayout()
        
        title_label = QLabel("VTX ANTIVIRUS")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                background: transparent;
            }
        """)
        
        subtitle_label = QLabel("Professional Security Suite")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: #ccddff;
                font-size: 12px;
                background: transparent;
            }
        """)
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        # Status indicators
        status_layout = QVBoxLayout()
        
        self.protection_status = QLabel("🛡️ PROTECTED")
        self.protection_status.setStyleSheet("""
            QLabel {
                color: #00ff88;
                font-weight: bold;
                font-size: 14px;
                background: transparent;
            }
        """)
        
        self.scan_status = QLabel("💡 Ready to scan")
        self.scan_status.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 12px;
                background: transparent;
            }
        """)
        
        status_layout.addWidget(self.protection_status)
        status_layout.addWidget(self.scan_status)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        layout.addLayout(status_layout)
        
        return header_widget
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Quick stats
        stats_group = QGroupBox("Security Overview")
        stats_layout = QGridLayout(stats_group)
        
        # Threat count
        threat_count = self.get_threat_count()
        threats_label = QLabel(f"🚨 Threats Detected Today: {threat_count}")
        threats_label.setStyleSheet("font-size: 14px; color: #ff4444; font-weight: bold;")
        
        # Files scanned
        scanned_label = QLabel("📊 Files Scanned: Calculating...")
        scanned_label.setStyleSheet("font-size: 14px; color: #0066cc;")
        
        # System status
        system_label = QLabel("💻 System Status: Protected")
        system_label.setStyleSheet("font-size: 14px; color: #00cc44; font-weight: bold;")
        
        stats_layout.addWidget(threats_label, 0, 0)
        stats_layout.addWidget(scanned_label, 1, 0)
        stats_layout.addWidget(system_label, 2, 0)
        
        layout.addWidget(stats_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QGridLayout(actions_group)
        
        # Quick scan button
        quick_scan_btn = QPushButton("🔍 Quick Scan")
        quick_scan_btn.setMinimumHeight(50)
        quick_scan_btn.setStyleSheet("""
            QPushButton {
                background: #007acc;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:hover {
                background: #0099ff;
            }
        """)
        quick_scan_btn.clicked.connect(self.start_quick_scan)
        
        # Full scan button
        full_scan_btn = QPushButton("🔍 Full Scan")
        full_scan_btn.setMinimumHeight(50)
        full_scan_btn.setStyleSheet("""
            QPushButton {
                background: #ff6600;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:hover {
                background: #ff8833;
            }
        """)
        full_scan_btn.clicked.connect(self.start_full_scan)
        
        # Update button
        update_btn = QPushButton("📡 Update Definitions")
        update_btn.setMinimumHeight(50)
        update_btn.setStyleSheet("""
            QPushButton {
                background: #4CAF50;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:hover {
                background: #66BB6A;
            }
        """)
        update_btn.clicked.connect(self.update_definitions)
        
        actions_layout.addWidget(quick_scan_btn, 0, 0)
        actions_layout.addWidget(full_scan_btn, 0, 1)
        actions_layout.addWidget(update_btn, 1, 0, 1, 2)
        
        layout.addWidget(actions_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_list = QListWidget()
        self.activity_list.setMaximumHeight(200)
        self.update_activity_list()
        
        activity_layout.addWidget(self.activity_list)
        layout.addWidget(activity_group)
        
        layout.addStretch()
        return widget
    
    def create_scan_tab(self):
        """Create scan tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Scan controls
        controls_group = QGroupBox("Scan Controls")
        controls_layout = QVBoxLayout(controls_group)
        
        # Scan type selection
        scan_type_layout = QHBoxLayout()
        
        self.quick_scan_radio = QCheckBox("Quick Scan (Downloads, Temp)")
        self.quick_scan_radio.setChecked(True)
        
        self.full_scan_radio = QCheckBox("Full System Scan")
        
        self.custom_scan_radio = QCheckBox("Custom Directory")
        
        scan_type_layout.addWidget(self.quick_scan_radio)
        scan_type_layout.addWidget(self.full_scan_radio)
        scan_type_layout.addWidget(self.custom_scan_radio)
        
        controls_layout.addLayout(scan_type_layout)
        
        # Custom directory selection
        custom_layout = QHBoxLayout()
        self.custom_path_edit = QTextEdit()
        self.custom_path_edit.setMaximumHeight(30)
        self.custom_path_edit.setPlaceholderText("Select custom directory...")
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_custom_directory)
        
        custom_layout.addWidget(self.custom_path_edit)
        custom_layout.addWidget(browse_btn)
        
        controls_layout.addLayout(custom_layout)
        
        # Scan button
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setMinimumHeight(50)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #007acc;
                color: white;
                font-size: 18px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #0099ff;
            }
            QPushButton:disabled {
                background: #cccccc;
            }
        """)
        self.scan_btn.clicked.connect(self.start_manual_scan)
        
        controls_layout.addWidget(self.scan_btn)
        
        layout.addWidget(controls_group)
        
        # Progress
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        
        self.scan_status_label = QLabel("Ready to scan")
        
        progress_layout.addWidget(self.scan_progress)
        progress_layout.addWidget(self.scan_status_label)
        
        layout.addWidget(progress_group)
        
        # Results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        
        results_layout.addWidget(self.scan_results)
        layout.addWidget(results_group)
        
        return widget
    
    def create_quarantine_tab(self):
        """Create quarantine tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Quarantine list
        quarantine_group = QGroupBox("Quarantined Files")
        quarantine_layout = QVBoxLayout(quarantine_group)
        
        self.quarantine_list = QListWidget()
        self.update_quarantine_list()
        
        quarantine_layout.addWidget(self.quarantine_list)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        restore_btn = QPushButton("📤 Restore File")
        restore_btn.setStyleSheet("""
            QPushButton {
                background: #4CAF50;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #66BB6A;
            }
        """)
        restore_btn.clicked.connect(self.restore_quarantined_file)
        
        delete_quarantine_btn = QPushButton("🗑️ Delete Permanently")
        delete_quarantine_btn.setStyleSheet("""
            QPushButton {
                background: #f44336;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #e57373;
            }
        """)
        delete_quarantine_btn.clicked.connect(self.delete_quarantined_file)
        
        controls_layout.addWidget(restore_btn)
        controls_layout.addWidget(delete_quarantine_btn)
        controls_layout.addStretch()
        
        quarantine_layout.addLayout(controls_layout)
        layout.addWidget(quarantine_group)
        
        return widget
    
    def create_protection_tab(self):
        """Create real-time protection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Protection status
        status_group = QGroupBox("Protection Status")
        status_layout = QGridLayout(status_group)
        
        # Real-time protection
        self.realtime_status = QLabel("🛡️ Real-time Protection: ENABLED")
        self.realtime_status.setStyleSheet("color: #00cc44; font-weight: bold; font-size: 14px;")
        
        # Web protection
        self.web_status = QLabel("🌐 Web Protection: ENABLED")
        self.web_status.setStyleSheet("color: #00cc44; font-weight: bold; font-size: 14px;")
        
        # Hardware monitoring
        self.hardware_status = QLabel("📹 Hardware Monitor: ENABLED")
        self.hardware_status.setStyleSheet("color: #00cc44; font-weight: bold; font-size: 14px;")
        
        status_layout.addWidget(self.realtime_status, 0, 0)
        status_layout.addWidget(self.web_status, 1, 0)
        status_layout.addWidget(self.hardware_status, 2, 0)
        
        layout.addWidget(status_group)
        
        # Protection controls
        controls_group = QGroupBox("Protection Controls")
        controls_layout = QVBoxLayout(controls_group)
        
        # Toggle protection button
        self.toggle_protection_btn = QPushButton("🛡️ Disable Protection")
        self.toggle_protection_btn.setMinimumHeight(50)
        self.toggle_protection_btn.setStyleSheet("""
            QPushButton {
                background: #ff6600;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #ff8833;
            }
        """)
        self.toggle_protection_btn.clicked.connect(self.toggle_protection)
        
        controls_layout.addWidget(self.toggle_protection_btn)
        layout.addWidget(controls_group)
        
        # Protection settings
        settings_group = QGroupBox("Protection Settings")
        settings_layout = QGridLayout(settings_group)
        
        # File monitoring
        self.monitor_downloads = QCheckBox("Monitor Downloads Directory")
        self.monitor_downloads.setChecked(True)
        
        self.monitor_temp = QCheckBox("Monitor Temporary Files")
        self.monitor_temp.setChecked(True)
        
        self.monitor_system = QCheckBox("Monitor System Files")
        self.monitor_system.setChecked(False)
        
        # Web protection
        self.block_phishing = QCheckBox("Block Phishing Sites")
        self.block_phishing.setChecked(True)
        
        self.check_downloads = QCheckBox("Scan Downloads Automatically")
        self.check_downloads.setChecked(True)
        
        settings_layout.addWidget(self.monitor_downloads, 0, 0)
        settings_layout.addWidget(self.monitor_temp, 1, 0)
        settings_layout.addWidget(self.monitor_system, 2, 0)
        settings_layout.addWidget(self.block_phishing, 0, 1)
        settings_layout.addWidget(self.check_downloads, 1, 1)
        
        layout.addWidget(settings_group)
        
        layout.addStretch()
        return widget
    
    def create_logs_tab(self):
        """Create logs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Log display
        logs_group = QGroupBox("System Logs")
        logs_layout = QVBoxLayout(logs_group)
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        self.logs_display.setFont(QFont("Courier", 9))
        
        # Load recent logs
        self.load_logs()
        
        logs_layout.addWidget(self.logs_display)
        
        # Log controls
        controls_layout = QHBoxLayout()
        
        refresh_logs_btn = QPushButton("🔄 Refresh")
        refresh_logs_btn.clicked.connect(self.load_logs)
        
        clear_logs_btn = QPushButton("🗑️ Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        
        export_logs_btn = QPushButton("📄 Export Logs")
        export_logs_btn.clicked.connect(self.export_logs)
        
        controls_layout.addWidget(refresh_logs_btn)
        controls_layout.addWidget(clear_logs_btn)
        controls_layout.addWidget(export_logs_btn)
        controls_layout.addStretch()
        
        logs_layout.addLayout(controls_layout)
        layout.addWidget(logs_group)
        
        return widget
    
    def create_settings_tab(self):
        """Create settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QGridLayout(general_group)
        
        # Scan sensitivity
        general_layout.addWidget(QLabel("Scan Sensitivity:"), 0, 0)
        self.scan_sensitivity = QSpinBox()
        self.scan_sensitivity.setRange(1, 10)
        self.scan_sensitivity.setValue(7)
        general_layout.addWidget(self.scan_sensitivity, 0, 1)
        
        # Auto-quarantine
        self.auto_quarantine = QCheckBox("Automatically quarantine threats")
        self.auto_quarantine.setChecked(True)
        general_layout.addWidget(self.auto_quarantine, 1, 0, 1, 2)
        
        # Notifications
        self.show_notifications = QCheckBox("Show threat notifications")
        self.show_notifications.setChecked(True)
        general_layout.addWidget(self.show_notifications, 2, 0, 1, 2)
        
        layout.addWidget(general_group)
        
        # Update settings
        update_group = QGroupBox("Update Settings")
        update_layout = QVBoxLayout(update_group)
        
        self.auto_update = QCheckBox("Automatically update virus definitions")
        self.auto_update.setChecked(True)
        
        update_layout.addWidget(self.auto_update)
        layout.addWidget(update_group)
        
        # Service settings
        service_group = QGroupBox("Service Settings")
        service_layout = QVBoxLayout(service_group)
        
        # Service controls
        service_controls = QHBoxLayout()
        
        install_service_btn = QPushButton("📦 Install Service")
        install_service_btn.clicked.connect(self.install_service)
        
        uninstall_service_btn = QPushButton("🗑️ Uninstall Service")
        uninstall_service_btn.clicked.connect(self.uninstall_service)
        
        service_controls.addWidget(install_service_btn)
        service_controls.addWidget(uninstall_service_btn)
        
        service_layout.addLayout(service_controls)
        layout.addWidget(service_group)
        
        layout.addStretch()
        return widget
    
    def apply_modern_style(self):
        """Apply modern styling to the application"""
        self.setStyleSheet("""
            QMainWindow {
                background: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
            QListWidget {
                border: 1px solid #ddd;
                border-radius: 5px;
                background: white;
            }
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 5px;
                background: white;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #007acc;
                border-radius: 3px;
            }
        """)
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(self)
            
            if QTA_AVAILABLE:
                try:
                    icon = qta.icon('mdi.shield-check', color='green')
                    self.tray_icon.setIcon(icon)
                except:
                    pass
            
            # Tray menu
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction("Show VTX")
            show_action.triggered.connect(self.show)
            
            tray_menu.addSeparator()
            
            scan_action = tray_menu.addAction("Quick Scan")
            scan_action.triggered.connect(self.start_quick_scan)
            
            tray_menu.addSeparator()
            
            quit_action = tray_menu.addAction("Exit VTX")
            quit_action.triggered.connect(self.emergency_stop)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            
            # Tray notifications
            self.tray_icon.showMessage(
                "VTX Antivirus",
                "Real-time protection is active",
                QSystemTrayIcon.Information,
                3000
            )
    
    def start_protection(self):
        """Start all protection services"""
        try:
            # Start file system monitoring
            for watch_dir in self.file_watcher.watch_dirs:
                if os.path.exists(watch_dir):
                    self.observer.schedule(self.file_watcher, watch_dir, recursive=True)
            
            self.observer.start()
            
            # Start network monitoring
            self.network_monitor.start_monitoring()
            
            # Start hardware monitoring
            self.hardware_monitor.start_monitoring()
            
            # Start proxy
            self.proxy_manager.start_proxy()
            
            logger.info("All protection services started")
            
        except Exception as e:
            logger.error(f"Error starting protection services: {e}")
    
    def stop_protection(self):
        """Stop all protection services"""
        try:
            # Stop file system monitoring
            self.observer.stop()
            self.observer.join()
            
            # Stop network monitoring
            self.network_monitor.stop_monitoring()
            
            # Stop hardware monitoring
            self.hardware_monitor.stop_monitoring()
            
            # Stop proxy
            self.proxy_manager.stop_proxy()
            
            logger.info("All protection services stopped")
            
        except Exception as e:
            logger.error(f"Error stopping protection services: {e}")
    
    def scan_file_callback(self, file_path: str):
        """Callback for real-time file scanning"""
        try:
            logger.info(f"Scanning file: {file_path}")
            
            # Scan with ClamAV
            is_infected, threat_name = self.scanner.scan_file(file_path)
            
            if is_infected:
                threat_info = {
                    'filename': os.path.basename(file_path),
                    'filepath': file_path,
                    'threat_name': threat_name,
                    'threat_type': 'Virus/Malware'
                }
                
                # Log threat
                self.db.log_threat(
                    threat_info['filename'],
                    threat_info['filepath'],
                    threat_info['threat_type'],
                    threat_info['threat_name']
                )
                
                # Show threat dialog
                QMetaObject.invokeMethod(
                    self,
                    "_show_threat_dialog",
                    Qt.QueuedConnection,
                    threat_info
                )
            
            # Check with VirusTotal if available
            vt_result = self.vt_checker.check_file(file_path)
            if vt_result.get('positives', 0) > 0:
                threat_info = {
                    'filename': os.path.basename(file_path),
                    'filepath': file_path,
                    'threat_name': f"VirusTotal: {vt_result.get('positives', 0)} detections",
                    'threat_type': 'Suspicious File'
                }
                
                QMetaObject.invokeMethod(
                    self,
                    "_show_threat_dialog",
                    Qt.QueuedConnection,
                    threat_info
                )
        
        except Exception as e:
            logger.error(f"Error in scan callback: {e}")
    
    def _show_threat_dialog(self, threat_info):
        """Show threat detection dialog (called from callback)"""
        try:
            dialog = ThreatDialog(threat_info, self)
            result = dialog.exec()
            
            if result == QDialog.Accepted:
                action = dialog.user_action
                
                if action == 'quarantine':
                    success = self.quarantine.quarantine_file(
                        threat_info['filepath'],
                        threat_info['threat_name']
                    )
                    
                    if success:
                        self.show_notification("Threat Quarantined", 
                                             f"File has been safely quarantined: {threat_info['filename']}")
                    else:
                        self.show_notification("Quarantine Failed", 
                                             f"Failed to quarantine file: {threat_info['filename']}")
                
                elif action == 'delete':
                    try:
                        os.remove(threat_info['filepath'])
                        self.show_notification("Threat Deleted", 
                                             f"File has been deleted: {threat_info['filename']}")
                    except Exception as e:
                        logger.error(f"Error deleting file: {e}")
                        self.show_notification("Delete Failed", 
                                             f"Failed to delete file: {threat_info['filename']}")
                
                elif action == 'keep':
                    self.show_notification("File Kept", 
                                         f"File kept (WARNING: May be dangerous): {threat_info['filename']}")
                
                # Update database with action
                self.db.log_threat(
                    threat_info['filename'],
                    threat_info['filepath'],
                    threat_info['threat_type'],
                    threat_info['threat_name'],
                    action
                )
                
                # Update UI
                self.update_activity_list()
        
        except Exception as e:
            logger.error(f"Error showing threat dialog: {e}")
    
    def _show_hardware_notification(self, message, process_name, access_type, pid):
        """Show hardware access notification"""
        try:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("VTX - Hardware Access Detected")
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setText(f"Hardware Access Detected\n\n{message}")
            msg_box.setInformativeText("Do you want to allow this access?")
            
            allow_btn = msg_box.addButton("Allow", QMessageBox.AcceptRole)
            block_btn = msg_box.addButton("Block", QMessageBox.RejectRole)
            
            msg_box.exec()
            
            if msg_box.clickedButton() == block_btn:
                # In a real implementation, this would block the process
                logger.info(f"User chose to block hardware access for {process_name}")
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    self.show_notification("Hardware Access Blocked", 
                                         f"Blocked {access_type} access for {process_name}")
                except:
                    pass
            else:
                logger.info(f"User allowed hardware access for {process_name}")
        
        except Exception as e:
            logger.error(f"Error showing hardware notification: {e}")
    
    def show_notification(self, title: str, message: str):
        """Show system tray notification"""
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.Information, 5000)
    
    def toggle_protection(self):
        """Toggle real-time protection"""
        if self.protection_enabled:
            self.stop_protection()
            self.protection_enabled = False
            self.toggle_protection_btn.setText("🛡️ Enable Protection")
            self.toggle_protection_btn.setStyleSheet("""
                QPushButton {
                    background: #4CAF50;
                    color: white;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 8px;
                }
                QPushButton:hover {
                    background: #66BB6A;
                }
            """)
            self.protection_status.setText("⚠️ PROTECTION DISABLED")
            self.protection_status.setStyleSheet("color: #ff4444; font-weight: bold; font-size: 14px;")
        else:
            self.start_protection()
            self.protection_enabled = True
            self.toggle_protection_btn.setText("🛡️ Disable Protection")
            self.toggle_protection_btn.setStyleSheet("""
                QPushButton {
                    background: #ff6600;
                    color: white;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 8px;
                }
                QPushButton:hover {
                    background: #ff8833;
                }
            """)
            self.protection_status.setText("🛡️ PROTECTED")
            self.protection_status.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
    
    def start_quick_scan(self):
        """Start quick scan of downloads and temp directories"""
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
        # Start scan in thread
        scan_thread = threading.Thread(target=self._perform_quick_scan, daemon=True)
        scan_thread.start()
    
    def start_full_scan(self):
        """Start full system scan"""
        if self.scanning:
            return
        
        self.scanning = True
        self.scan_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
        # Start scan in thread
        scan_thread = threading.Thread(target=self._perform_full_scan, daemon=True)
        scan_thread.start()
    
    def start_manual_scan(self):
        """Start manual scan based on selection"""
        if self.quick_scan_radio.isChecked():
            self.start_quick_scan()
        elif self.full_scan_radio.isChecked():
            self.start_full_scan()
        elif self.custom_scan_radio.isChecked():
            custom_path = self.custom_path_edit.toPlainText().strip()
            if custom_path and os.path.exists(custom_path):
                self._perform_custom_scan(custom_path)
    
    def _perform_quick_scan(self):
        """Perform quick scan"""
        try:
            scan_dirs = [
                str(Path.home() / 'Downloads'),
                str(Path.home() / 'Stažené'),
                '/tmp',
                '/var/tmp'
            ]
            
            total_files = 0
            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        total_files += len(files)
            
            scanned_files = 0
            threats_found = 0
            
            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue
                
                for root, dirs, files in os.walk(scan_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Update status
                        QMetaObject.invokeMethod(
                            self.scan_status_label,
                            "setText",
                            Qt.QueuedConnection,
                            f"Scanning: {file}"
                        )
                        
                        # Scan file
                        is_infected, threat_name = self.scanner.scan_file(file_path)
                        
                        if is_infected:
                            threats_found += 1
                            threat_info = {
                                'filename': file,
                                'filepath': file_path,
                                'threat_name': threat_name,
                                'threat_type': 'Virus/Malware'
                            }
                            
                            # Log threat
                            self.db.log_threat(
                                threat_info['filename'],
                                threat_info['filepath'],
                                threat_info['threat_type'],
                                threat_info['threat_name']
                            )
                            
                            # Auto-quarantine if enabled
                            if self.auto_quarantine.isChecked():
                                self.quarantine.quarantine_file(file_path, threat_name)
                        
                        scanned_files += 1
                        progress = int((scanned_files / total_files) * 100) if total_files > 0 else 0
                        
                        QMetaObject.invokeMethod(
                            self.scan_progress,
                            "setValue",
                            Qt.QueuedConnection,
                            progress
                        )
            
            # Scan complete
            result_text = f"Quick scan completed.\n\nFiles scanned: {scanned_files}\nThreats found: {threats_found}"
            
            QMetaObject.invokeMethod(
                self.scan_results,
                "setText",
                Qt.QueuedConnection,
                result_text
            )
            
            QMetaObject.invokeMethod(
                self.scan_status_label,
                "setText",
                Qt.QueuedConnection,
                "Scan completed"
            )
            
        except Exception as e:
            logger.error(f"Error in quick scan: {e}")
        
        finally:
            self.scanning = False
            QMetaObject.invokeMethod(
                self.scan_btn,
                "setEnabled",
                Qt.QueuedConnection,
                True
            )
    
    def _perform_full_scan(self):
        """Perform full system scan"""
        try:
            scan_dirs = ['/home', '/usr', '/opt', '/var']
            
            total_files = 0
            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    try:
                        for root, dirs, files in os.walk(scan_dir):
                            total_files += len(files)
                    except PermissionError:
                        continue
            
            scanned_files = 0
            threats_found = 0
            
            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue
                
                try:
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            try:
                                # Update status
                                QMetaObject.invokeMethod(
                                    self.scan_status_label,
                                    "setText",
                                    Qt.QueuedConnection,
                                    f"Scanning: {file}"
                                )
                                
                                # Scan file
                                is_infected, threat_name = self.scanner.scan_file(file_path)
                                
                                if is_infected:
                                    threats_found += 1
                                    
                                    # Log threat
                                    self.db.log_threat(file, file_path, 'Virus/Malware', threat_name)
                                    
                                    # Auto-quarantine if enabled
                                    if self.auto_quarantine.isChecked():
                                        self.quarantine.quarantine_file(file_path, threat_name)
                                
                                scanned_files += 1
                                progress = int((scanned_files / total_files) * 100) if total_files > 0 else 0
                                
                                QMetaObject.invokeMethod(
                                    self.scan_progress,
                                    "setValue",
                                    Qt.QueuedConnection,
                                    progress
                                )
                            
                            except PermissionError:
                                continue
                            except Exception as e:
                                logger.error(f"Error scanning {file_path}: {e}")
                                continue
                
                except PermissionError:
                    continue
            
            # Scan complete
            result_text = f"Full system scan completed.\n\nFiles scanned: {scanned_files}\nThreats found: {threats_found}"
            
            QMetaObject.invokeMethod(
                self.scan_results,
                "setText",
                Qt.QueuedConnection,
                result_text
            )
            
        except Exception as e:
            logger.error(f"Error in full scan: {e}")
        
        finally:
            self.scanning = False
            QMetaObject.invokeMethod(
                self.scan_btn,
                "setEnabled",
                Qt.QueuedConnection,
                True
            )
    
    def browse_custom_directory(self):
        """Browse for custom scan directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if directory:
            self.custom_path_edit.setText(directory)
    
    def update_definitions(self):
        """Update virus definitions"""
        try:
            # In a real implementation, this would update ClamAV definitions
            result = subprocess.run(['freshclam'], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.show_notification("Update Complete", "Virus definitions updated successfully")
                logger.info("Virus definitions updated")
            else:
                self.show_notification("Update Failed", "Failed to update virus definitions")
                logger.error(f"Update failed: {result.stderr}")
        
        except Exception as e:
            logger.error(f"Error updating definitions: {e}")
            self.show_notification("Update Error", f"Error updating definitions: {e}")
    
    def get_threat_count(self):
        """Get today's threat count"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE DATE(detected_time) = DATE('now')
            ''')
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else 0
        
        except Exception as e:
            logger.error(f"Error getting threat count: {e}")
            return 0
    
    def update_activity_list(self):
        """Update recent activity list"""
        try:
            self.activity_list.clear()
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT filename, threat_name, detected_time, action_taken
                FROM threats 
                ORDER BY detected_time DESC 
                LIMIT 10
            ''')
            
            results = cursor.fetchall()
            conn.close()
            
            for filename, threat_name, detected_time, action_taken in results:
                item_text = f"🚨 {filename} - {threat_name or 'Unknown'} ({action_taken or 'Detected'})"
                self.activity_list.addItem(item_text)
        
        except Exception as e:
            logger.error(f"Error updating activity list: {e}")
    
    def update_quarantine_list(self):
        """Update quarantine list"""
        try:
            self.quarantine_list.clear()
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, original_path, threat_name, quarantine_time
                FROM quarantine 
                ORDER BY quarantine_time DESC
            ''')
            
            results = cursor.fetchall()
            conn.close()
            
            for qid, original_path, threat_name, quarantine_time in results:
                item_text = f"ID:{qid} - {os.path.basename(original_path)} ({threat_name or 'Unknown'})"
                self.quarantine_list.addItem(item_text)
        
        except Exception as e:
            logger.error(f"Error updating quarantine list: {e}")
    
    def restore_quarantined_file(self):
        """Restore selected quarantined file"""
        current_item = self.quarantine_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
            return
        
        # Extract ID from item text
        item_text = current_item.text()
        try:
            qid = int(item_text.split(" - ")[0].replace("ID:", ""))
        except (ValueError, IndexError):
            QMessageBox.error(self, "Error", "Invalid selection.")
            return
        
        # Ask for restore path
        restore_path, ok = QFileDialog.getSaveFileName(self, "Restore File As")
        if ok and restore_path:
            success = self.quarantine.restore_file(qid, restore_path)
            
            if success:
                self.show_notification("File Restored", f"File restored to: {restore_path}")
                self.update_quarantine_list()
            else:
                QMessageBox.error(self, "Restore Failed", "Failed to restore file.")
    
    def delete_quarantined_file(self):
        """Permanently delete quarantined file"""
        current_item = self.quarantine_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
            return
        
        reply = QMessageBox.question(
            self, 
            "Confirm Delete", 
            "Are you sure you want to permanently delete this file?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Extract ID and delete
            item_text = current_item.text()
            try:
                qid = int(item_text.split(" - ")[0].replace("ID:", ""))
                
                # Get quarantine path and delete
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                cursor.execute('SELECT quarantine_path FROM quarantine WHERE id = ?', (qid,))
                result = cursor.fetchone()
                
                if result:
                    quarantine_path = result[0]
                    if os.path.exists(quarantine_path):
                        os.remove(quarantine_path)
                    
                    # Remove from database
                    cursor.execute('DELETE FROM quarantine WHERE id = ?', (qid,))
                    conn.commit()
                    
                    self.show_notification("File Deleted", "Quarantined file permanently deleted.")
                    self.update_quarantine_list()
                
                conn.close()
                
            except Exception as e:
                logger.error(f"Error deleting quarantined file: {e}")
                QMessageBox.error(self, "Delete Failed", "Failed to delete file.")
    
    def load_logs(self):
        """Load and display logs"""
        try:
            log_file = LOGS_DIR / 'vtx.log'
            
            if log_file.exists():
                with open(log_file, 'r') as f:
                    # Read last 1000 lines
                    lines = f.readlines()
                    recent_lines = lines[-1000:] if len(lines) > 1000 else lines
                    
                    self.logs_display.setText(''.join(recent_lines))
            else:
                self.logs_display.setText("No logs available.")
        
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            self.logs_display.setText(f"Error loading logs: {e}")
    
    def clear_logs(self):
        """Clear log files"""
        reply = QMessageBox.question(
            self, 
            "Clear Logs", 
            "Are you sure you want to clear all logs?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                log_file = LOGS_DIR / 'vtx.log'
                if log_file.exists():
                    log_file.unlink()
                
                self.logs_display.clear()
                logger.info("Logs cleared by user")
                
            except Exception as e:
                logger.error(f"Error clearing logs: {e}")
                QMessageBox.error(self, "Error", f"Failed to clear logs: {e}")
    
    def export_logs(self):
        """Export logs to file"""
        try:
            export_path, ok = QFileDialog.getSaveFileName(
                self, 
                "Export Logs", 
                f"vtx_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                "Text Files (*.txt)"
            )
            
            if ok and export_path:
                log_file = LOGS_DIR / 'vtx.log'
                
                if log_file.exists():
                    import shutil
                    shutil.copy2(log_file, export_path)
                    self.show_notification("Export Complete", f"Logs exported to: {export_path}")
                else:
                    QMessageBox.warning(self, "No Logs", "No logs available to export.")
        
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            QMessageBox.error(self, "Export Failed", f"Failed to export logs: {e}")
    
    def install_service(self):
        """Install VTX as system service"""
        try:
            service_script = str(Path(__file__).parent / 'vtx.service')
            
            if not os.path.exists(service_script):
                QMessageBox.error(self, "Service Error", "Service file not found. Please ensure vtx.service exists.")
                return
            
            # Copy service file
            result = subprocess.run([
                'sudo', 'cp', service_script, '/etc/systemd/system/'
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                QMessageBox.error(self, "Install Failed", f"Failed to install service: {result.stderr}")
                return
            
            # Reload systemd and enable service
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
            subprocess.run(['sudo', 'systemctl', 'enable', 'vtx.service'])
            
            QMessageBox.information(self, "Service Installed", "VTX service installed successfully. It will start automatically on boot.")
            logger.info("VTX service installed")
        
        except Exception as e:
            logger.error(f"Error installing service: {e}")
            QMessageBox.error(self, "Install Error", f"Failed to install service: {e}")
    
    def uninstall_service(self):
        """Uninstall VTX system service"""
        try:
            # Stop and disable service
            subprocess.run(['sudo', 'systemctl', 'stop', 'vtx.service'])
            subprocess.run(['sudo', 'systemctl', 'disable', 'vtx.service'])
            
            # Remove service file
            result = subprocess.run([
                'sudo', 'rm', '/etc/systemd/system/vtx.service'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
                QMessageBox.information(self, "Service Uninstalled", "VTX service uninstalled successfully.")
                logger.info("VTX service uninstalled")
            else:
                QMessageBox.error(self, "Uninstall Failed", "Failed to remove service file.")
        
        except Exception as e:
            logger.error(f"Error uninstalling service: {e}")
            QMessageBox.error(self, "Uninstall Error", f"Failed to uninstall service: {e}")
    
    def emergency_stop(self):
        """Emergency stop - shut down everything"""
        try:
            logger.info("Emergency stop initiated")
            
            # Hide watermark
            if hasattr(self, 'watermark'):
                self.watermark.hide()
            
            # Stop all protection services
            self.stop_protection()
            
            # Close application
            if hasattr(self, 'tray_icon'):
                self.tray_icon.hide()
            
            QApplication.quit()
        
        except Exception as e:
            logger.error(f"Error in emergency stop: {e}")
            QApplication.quit()
    
    def closeEvent(self, event):
        """Handle close event - minimize to tray instead of closing"""
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                "VTX Antivirus",
                "Application minimized to tray. Protection remains active.",
                QSystemTrayIcon.Information,
                2000
            )
            event.ignore()
        else:
            self.emergency_stop()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("VTX Antivirus")
    app.setApplicationVersion("1.0")
    app.setQuitOnLastWindowClosed(False)
    
    # Check for single instance
    shared_memory = QSharedMemory("VTXAntivirus")
    
    if not shared_memory.create(1):
        QMessageBox.critical(None, "VTX Antivirus", "VTX Antivirus is already running!")
        sys.exit(1)
    
    try:
        # Create and show main window
        window = AVMainWindow()
        window.show()
        
        # Start application
        sys.exit(app.exec())
    
    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        QMessageBox.critical(None, "Critical Error", f"Critical error: {e}")
        sys.exit(1)
    
    finally:
        shared_memory.detach()

if __name__ == "__main__":
    main()
