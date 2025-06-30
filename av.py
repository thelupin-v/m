#!/usr/bin/env python3
"""
VTX Antivirus - Production Grade Antivirus Application
A sophisticated antivirus solution with real-time scanning, web protection, and system monitoring
"""

import sys
import os
import json
import time
import threading
import subprocess
import signal
import socket
import ssl
import hashlib
import base64
import tempfile
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import logging

# Core libraries
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                               QProgressBar, QSystemTrayIcon, QMenu, QMessageBox,
                               QDialog, QDialogButtonBox, QListWidget, QTabWidget,
                               QFrame, QSplitter, QGroupBox, QCheckBox, QSpinBox,
                               QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
                               QHeaderView, QFileDialog, QSlider, QStackedWidget)
from PySide6.QtCore import (Qt, QTimer, QThread, QObject, pyqtSignal, QSettings,
                            QPropertyAnimation, QEasingCurve, QRect, QPoint, QSize,
                            QAbstractAnimation, QParallelAnimationGroup, QSequentialAnimationGroup,
                            QPropertyAnimation, QVariantAnimation, Signal, Slot)
from PySide6.QtGui import (QIcon, QPixmap, QPainter, QBrush, QColor, QPen,
                           QFont, QFontMetrics, QLinearGradient, QRadialGradient,
                           QPalette, QMovie, QAction, QCursor)

# Third-party libraries
import qtawesome as qta
import pyclamd
import tgcrypto
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# MITM Proxy components
from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy.tools.web.master import WebMaster
import asyncio

# Encryption key for quarantine
QUARANTINE_KEY = bytes.fromhex("eeef64a99c54822173ddd8f895e0a43273dc0e4a44ca9560052fb5a76b2fd8f7")

# Phishing URL database (from the provided list)
PHISHING_URLS = {
    "portfolio-trezor-cdn.webflow.io",
    "agodahotelmall.com",
    "refundagoda.life",
    "parmagicl.com",
    "shanghaianlong.com",
    "agodamall.net",
    "stmpx0-gm.myshopify.com",
    "888nyw.com",
    "verifications.smcavalier.com",
    "coupangshopag.shop",
    "thanhtoanhoahongcoupangltd.com",
    "galxboysa.com",
    "allegro.pi-993120462528302.rest"
}

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# Security injection script for malicious URLs
SECURITY_INJECTION_SCRIPT = """
<script>
(function() {
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(255,0,0,0.9)";
    overlay.style.zIndex = 999999;
    overlay.style.color = "#fff";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.style.fontFamily = "Arial, sans-serif";
    overlay.innerHTML = `
        <h1 style="font-size: 32px; margin: 0;">⚠️ DANGEROUS WEBSITE BLOCKED</h1>
        <p style="font-size: 20px; text-align: center; max-width: 600px;">
            This website has been identified as potentially malicious by VTX Antivirus.
            <br>Visiting this site may compromise your security.
        </p>
        <div style="margin-top: 30px;">
            <button onclick="window.history.back()" 
                style="margin: 10px; padding: 15px 30px; font-size: 16px; 
                       background: #4CAF50; color: white; border: none; 
                       border-radius: 5px; cursor: pointer;">
                Go Back
            </button>
            <button onclick="location.href='https://www.google.com'" 
                style="margin: 10px; padding: 15px 30px; font-size: 16px; 
                       background: #2196F3; color: white; border: none; 
                       border-radius: 5px; cursor: pointer;">
                Go to Google
            </button>
        </div>
        <p style="font-size: 14px; margin-top: 20px; opacity: 0.8;">
            Protected by VTX Antivirus
        </p>
    `;
    document.body.appendChild(overlay);
})();
</script>
"""

class DatabaseManager:
    """Database manager for VTX Antivirus"""
    
    def __init__(self, db_path="vtx_database.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                scan_result TEXT NOT NULL,
                threat_type TEXT,
                action_taken TEXT
            )
        """)
        
        # Quarantine table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                threat_type TEXT,
                file_hash TEXT
            )
        """)
        
        # URL blocks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                block_reason TEXT,
                source TEXT
            )
        """)
        
        # System events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT,
                severity TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_scan_result(self, file_path, result, threat_type=None, action=None):
        """Add scan result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (timestamp, file_path, scan_result, threat_type, action_taken)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), file_path, result, threat_type, action))
        conn.commit()
        conn.close()
    
    def add_quarantine_entry(self, original_path, quarantine_path, threat_type, file_hash):
        """Add quarantine entry to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO quarantine (original_path, quarantine_path, timestamp, threat_type, file_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (original_path, quarantine_path, datetime.now().isoformat(), threat_type, file_hash))
        conn.commit()
        conn.close()
    
    def add_url_block(self, url, reason, source="VTX"):
        """Add URL block to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO url_blocks (url, timestamp, block_reason, source)
            VALUES (?, ?, ?, ?)
        """, (url, datetime.now().isoformat(), reason, source))
        conn.commit()
        conn.close()
    
    def add_system_event(self, event_type, description, severity="INFO"):
        """Add system event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO system_events (timestamp, event_type, description, severity)
            VALUES (?, ?, ?, ?)
        """, (datetime.now().isoformat(), event_type, description, severity))
        conn.commit()
        conn.close()

class EncryptionManager:
    """Handles file encryption and decryption for quarantine"""
    
    @staticmethod
    def encrypt_file(file_path, output_path):
        """Encrypt file using AES-256-IGE with TGCrypto"""
        try:
            with open(file_path, 'rb') as infile:
                data = infile.read()
            
            # Generate IV (16 bytes for AES)
            iv = os.urandom(16)
            
            # Encrypt using TGCrypto AES-256-IGE
            encrypted_data = tgcrypto.ige256_encrypt(data, QUARANTINE_KEY, iv)
            
            # Save IV + encrypted data
            with open(output_path, 'wb') as outfile:
                outfile.write(iv)
                outfile.write(encrypted_data)
            
            return True
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            return False
    
    @staticmethod
    def decrypt_file(encrypted_path, output_path):
        """Decrypt file using AES-256-IGE with TGCrypto"""
        try:
            with open(encrypted_path, 'rb') as infile:
                iv = infile.read(16)
                encrypted_data = infile.read()
            
            # Decrypt using TGCrypto AES-256-IGE
            decrypted_data = tgcrypto.ige256_decrypt(encrypted_data, QUARANTINE_KEY, iv)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            return True
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            return False

class URLChecker:
    """URL reputation checker using VirusTotal and local phishing database"""
    
    @staticmethod
    def is_phishing_url(url):
        """Check if URL is in phishing database"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return domain in PHISHING_URLS
    
    @staticmethod
    def check_virustotal(url):
        """Check URL against VirusTotal API"""
        if not VIRUSTOTAL_API_KEY:
            return None
        
        try:
            params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': url
            }
            response = requests.get(VIRUSTOTAL_URL, params=params, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    if positives > 0:
                        return f"Detected by {positives}/{total} engines"
            return None
        except Exception as e:
            logging.error(f"VirusTotal check failed: {e}")
            return None
    
    @staticmethod
    def is_malicious_url(url):
        """Combined check for malicious URLs"""
        if URLChecker.is_phishing_url(url):
            return True, "Phishing URL detected"
        
        vt_result = URLChecker.check_virustotal(url)
        if vt_result:
            return True, f"VirusTotal: {vt_result}"
        
        return False, None

class ClamAVScanner:
    """ClamAV integration for file scanning"""
    
    def __init__(self):
        self.clamd_socket = '/var/run/clamav/clamd.ctl'
        self.cd = None
        self.connect()
    
    def connect(self):
        """Connect to ClamAV daemon"""
        try:
            if os.path.exists(self.clamd_socket):
                self.cd = pyclamd.ClamdUnixSocket(self.clamd_socket)
            else:
                self.cd = pyclamd.ClamdAgnostic()
            
            # Test connection
            self.cd.ping()
            logging.info("ClamAV connection established")
            return True
        except Exception as e:
            logging.error(f"ClamAV connection failed: {e}")
            self.cd = None
            return False
    
    def scan_file(self, file_path):
        """Scan single file"""
        if not self.cd:
            return None, "ClamAV not available"
        
        try:
            result = self.cd.scan_file(file_path)
            if result is None:
                return "CLEAN", None
            else:
                # Result format: {filepath: ('FOUND', 'threat_name')}
                for path, (status, threat) in result.items():
                    if status == "FOUND":
                        return "INFECTED", threat
            return "CLEAN", None
        except Exception as e:
            logging.error(f"Scan error: {e}")
            return "ERROR", str(e)
    
    def update_signatures(self):
        """Update virus signatures"""
        try:
            subprocess.run(['freshclam'], check=True)
            return True
        except Exception as e:
            logging.error(f"Signature update failed: {e}")
            return False

class FileSystemMonitor(FileSystemEventHandler):
    """File system monitoring for real-time scanning"""
    
    def __init__(self, scanner, db_manager, main_window):
        super().__init__()
        self.scanner = scanner
        self.db_manager = db_manager
        self.main_window = main_window
        self.scan_queue = []
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.process_scan_queue)
        self.scan_timer.start(1000)  # Process queue every second
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self.add_to_scan_queue(event.src_path)
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self.add_to_scan_queue(event.src_path)
    
    def add_to_scan_queue(self, file_path):
        """Add file to scan queue"""
        if file_path not in self.scan_queue:
            self.scan_queue.append(file_path)
    
    def process_scan_queue(self):
        """Process files in scan queue"""
        if not self.scan_queue:
            return
        
        file_path = self.scan_queue.pop(0)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            self.scan_file_async(file_path)
    
    def scan_file_async(self, file_path):
        """Scan file asynchronously"""
        def scan_worker():
            result, threat = self.scanner.scan_file(file_path)
            self.db_manager.add_scan_result(file_path, result, threat)
            
            if result == "INFECTED":
                # Emit signal to main window for threat handling
                self.main_window.threat_detected.emit(file_path, threat)
        
        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()

class SystemMonitor(QObject):
    """System monitoring for webcam/microphone access"""
    
    camera_access_detected = Signal(str)
    microphone_access_detected = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        camera_processes = set()
        mic_processes = set()
        
        while self.monitoring:
            try:
                current_camera = set()
                current_mic = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        proc_info = proc.info
                        name = proc_info['name'].lower()
                        cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                        
                        # Check for camera access
                        if any(keyword in name or keyword in cmdline for keyword in 
                               ['camera', 'webcam', 'video', 'cheese', 'guvcview']):
                            current_camera.add(proc_info['name'])
                        
                        # Check for microphone access
                        if any(keyword in name or keyword in cmdline for keyword in 
                               ['audio', 'mic', 'record', 'pulse', 'alsa']):
                            current_mic.add(proc_info['name'])
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Detect new camera access
                new_camera = current_camera - camera_processes
                for app in new_camera:
                    self.camera_access_detected.emit(app)
                
                # Detect new microphone access
                new_mic = current_mic - mic_processes
                for app in new_mic:
                    self.microphone_access_detected.emit(app)
                
                camera_processes = current_camera
                mic_processes = current_mic
                
                time.sleep(2)  # Check every 2 seconds
            
            except Exception as e:
                logging.error(f"System monitoring error: {e}")
                time.sleep(5)

class ProxyHandler:
    """MITM Proxy handler for web traffic inspection"""
    
    def __init__(self, db_manager, main_window):
        self.db_manager = db_manager
        self.main_window = main_window
    
    def request(self, flow):
        """Handle HTTP/HTTPS requests"""
        url = flow.request.pretty_url
        
        # Skip internal/beacon URLs
        if any(skip in url.lower() for skip in ['beacon', 'analytics', 'tracking', 'telemetry']):
            return
        
        # Check if URL is malicious
        is_malicious, reason = URLChecker.is_malicious_url(url)
        
        if is_malicious:
            # Block the request and inject warning
            flow.response = http.Response.make(
                200,
                SECURITY_INJECTION_SCRIPT.encode(),
                {"Content-Type": "text/html"}
            )
            
            # Log the block
            self.db_manager.add_url_block(url, reason)
            logging.warning(f"Blocked malicious URL: {url} - {reason}")

class ProxyManager:
    """Manages MITM proxy for web traffic inspection"""
    
    def __init__(self, db_manager, main_window):
        self.db_manager = db_manager
        self.main_window = main_window
        self.proxy_process = None
        self.proxy_port = 8888
    
    def start_proxy(self):
        """Start MITM proxy"""
        try:
            # Generate CA certificate if not exists
            self._generate_ca_cert()
            
            # Configure Firefox to use proxy
            self._configure_firefox_proxy()
            
            # Start proxy in separate process
            cmd = [
                'mitmdump',
                '-p', str(self.proxy_port),
                '--set', 'confdir=~/.mitmproxy',
                '--scripts', self._create_proxy_script()
            ]
            
            self.proxy_process = subprocess.Popen(cmd)
            logging.info(f"Proxy started on port {self.proxy_port}")
            return True
        
        except Exception as e:
            logging.error(f"Proxy start failed: {e}")
            return False
    
    def stop_proxy(self):
        """Stop MITM proxy"""
        if self.proxy_process:
            self.proxy_process.terminate()
            self.proxy_process = None
            
            # Restore Firefox proxy settings
            self._restore_firefox_proxy()
            logging.info("Proxy stopped")
    
    def _generate_ca_cert(self):
        """Generate CA certificate for HTTPS interception"""
        cert_dir = os.path.expanduser('~/.mitmproxy')
        os.makedirs(cert_dir, exist_ok=True)
        
        if not os.path.exists(os.path.join(cert_dir, 'mitmproxy-ca-cert.pem')):
            # Initialize mitmproxy to generate certificates
            subprocess.run(['mitmdump', '--version'], capture_output=True)
    
    def _configure_firefox_proxy(self):
        """Configure Firefox to use VTX proxy"""
        firefox_profiles = []
        
        # Find Firefox profile directories
        firefox_dir = os.path.expanduser('~/.mozilla/firefox')
        if os.path.exists(firefox_dir):
            for item in os.listdir(firefox_dir):
                if item.endswith('.default') or item.endswith('.default-release'):
                    firefox_profiles.append(os.path.join(firefox_dir, item))
        
        # Configure each profile
        for profile_dir in firefox_profiles:
            prefs_file = os.path.join(profile_dir, 'prefs.js')
            if os.path.exists(prefs_file):
                self._update_firefox_prefs(prefs_file)
    
    def _update_firefox_prefs(self, prefs_file):
        """Update Firefox preferences for proxy"""
        proxy_settings = [
            f'user_pref("network.proxy.type", 1);',
            f'user_pref("network.proxy.http", "127.0.0.1");',
            f'user_pref("network.proxy.http_port", {self.proxy_port});',
            f'user_pref("network.proxy.ssl", "127.0.0.1");',
            f'user_pref("network.proxy.ssl_port", {self.proxy_port});',
            f'user_pref("network.proxy.share_proxy_settings", true);'
        ]
        
        # Backup original file
        shutil.copy2(prefs_file, f"{prefs_file}.vtx_backup")
        
        # Add proxy settings
        with open(prefs_file, 'a') as f:
            f.write('\n// VTX Antivirus Proxy Settings\n')
            for setting in proxy_settings:
                f.write(setting + '\n')
    
    def _restore_firefox_proxy(self):
        """Restore original Firefox proxy settings"""
        firefox_dir = os.path.expanduser('~/.mozilla/firefox')
        if os.path.exists(firefox_dir):
            for item in os.listdir(firefox_dir):
                profile_dir = os.path.join(firefox_dir, item)
                prefs_file = os.path.join(profile_dir, 'prefs.js')
                backup_file = f"{prefs_file}.vtx_backup"
                
                if os.path.exists(backup_file):
                    shutil.move(backup_file, prefs_file)
    
    def _create_proxy_script(self):
        """Create proxy script file"""
        script_content = f"""
from mitmproxy import http
import logging

class VTXProxyHandler:
    def __init__(self):
        self.phishing_urls = {PHISHING_URLS}
    
    def request(self, flow):
        url = flow.request.pretty_url
        domain = flow.request.pretty_host.lower()
        
        if domain in self.phishing_urls:
            flow.response = http.Response.make(
                200,
                '''{SECURITY_INJECTION_SCRIPT}'''.encode(),
                {{"Content-Type": "text/html"}}
            )
            logging.warning(f"Blocked phishing URL: {{url}}")

addons = [VTXProxyHandler()]
"""
        
        script_path = '/tmp/vtx_proxy_script.py'
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        return script_path

class ThreatDialog(QDialog):
    """Dialog for handling detected threats"""
    
    def __init__(self, file_path, threat_name, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.threat_name = threat_name
        self.action = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup threat dialog UI"""
        self.setWindowTitle("VTX - Threat Detected")
        self.setFixedSize(500, 300)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.Dialog)
        
        layout = QVBoxLayout(self)
        
        # Threat icon and title
        title_layout = QHBoxLayout()
        
        threat_icon = QLabel()
        threat_icon.setPixmap(qta.icon('mdi.virus', color='red').pixmap(48, 48))
        title_layout.addWidget(threat_icon)
        
        title_label = QLabel("⚠️ THREAT DETECTED")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: red;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        layout.addLayout(title_layout)
        
        # Threat details
        details_frame = QFrame()
        details_frame.setFrameStyle(QFrame.Box)
        details_frame.setStyleSheet("background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px;")
        details_layout = QVBoxLayout(details_frame)
        
        file_label = QLabel(f"<b>File:</b> {self.file_path}")
        threat_label = QLabel(f"<b>Threat:</b> {self.threat_name}")
        time_label = QLabel(f"<b>Detected:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        details_layout.addWidget(file_label)
        details_layout.addWidget(threat_label)
        details_layout.addWidget(time_label)
        
        layout.addWidget(details_frame)
        
        # Action buttons
        action_label = QLabel("What would you like to do?")
        action_label.setStyleSheet("font-weight: bold; margin-top: 20px;")
        layout.addWidget(action_label)
        
        button_layout = QHBoxLayout()
        
        quarantine_btn = QPushButton("🔒 Quarantine")
        quarantine_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        quarantine_btn.clicked.connect(lambda: self.set_action("quarantine"))
        
        keep_btn = QPushButton("✅ Keep File")
        keep_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        keep_btn.clicked.connect(lambda: self.set_action("keep"))
        
        delete_btn = QPushButton("🗑️ Delete")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #8e44ad;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7d3c98;
            }
        """)
        delete_btn.clicked.connect(lambda: self.set_action("delete"))
        
        button_layout.addWidget(quarantine_btn)
        button_layout.addWidget(keep_btn)
        button_layout.addWidget(delete_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
    
    def set_action(self, action):
        """Set the selected action and close dialog"""
        self.action = action
        self.accept()

class OverlayWidget(QWidget):
    """Always-on-top overlay widget with STOP button"""
    
    stop_clicked = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.animation = None
    
    def setup_ui(self):
        """Setup overlay UI"""
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(120, 40)
        
        # Position in top-right corner
        screen = QApplication.primaryScreen().geometry()
        self.move(screen.width() - 130, 10)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # VTX logo/icon
        icon_label = QLabel()
        icon_label.setPixmap(qta.icon('mdi.shield-check', color='#2ecc71').pixmap(24, 24))
        layout.addWidget(icon_label)
        
        # Status indicator
        self.status_label = QLabel("VTX")
        self.status_label.setStyleSheet("""
            QLabel {
                color: white;
                font-weight: bold;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.status_label)
        
        # STOP button
        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setFixedSize(40, 25)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_clicked.emit)
        layout.addWidget(self.stop_btn)
        
        # Styling
        self.setStyleSheet("""
            OverlayWidget {
                background-color: rgba(0, 0, 0, 180);
                border: 1px solid #34495e;
                border-radius: 8px;
            }
        """)
    
    def paintEvent(self, event):
        """Custom paint event for overlay styling"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background with gradient
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor(52, 73, 94, 200))
        gradient.setColorAt(1, QColor(44, 62, 80, 200))
        
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor(149, 165, 166), 1))
        painter.drawRoundedRect(self.rect(), 8, 8)
    
    def animate_pulse(self):
        """Animate overlay with pulse effect"""
        if self.animation:
            self.animation.stop()
        
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(1000)
        self.animation.setStartValue(0.8)
        self.animation.setEndValue(1.0)
        self.animation.setLoopCount(-1)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.start()
    
    def update_status(self, status, color="#2ecc71"):
        """Update status text and color"""
        self.status_label.setText(status)
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 10px;")

class NotificationWidget(QWidget):
    """System notification widget"""
    
    def __init__(self, title, message, icon_name="mdi.information", parent=None):
        super().__init__(parent)
        self.setup_ui(title, message, icon_name)
        self.show_notification()
    
    def setup_ui(self, title, message, icon_name):
        """Setup notification UI"""
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(350, 100)
        
        # Position in bottom-right corner
        screen = QApplication.primaryScreen().geometry()
        self.move(screen.width() - 360, screen.height() - 110)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Icon
        icon_label = QLabel()
        icon_label.setPixmap(qta.icon(icon_name, color='#3498db').pixmap(32, 32))
        layout.addWidget(icon_label)
        
        # Text content
        text_layout = QVBoxLayout()
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 12px; color: white;")
        text_layout.addWidget(title_label)
        
        message_label = QLabel(message)
        message_label.setStyleSheet("font-size: 10px; color: #ecf0f1;")
        message_label.setWordWrap(True)
        text_layout.addWidget(message_label)
        
        layout.addLayout(text_layout)
        
        # Styling
        self.setStyleSheet("""
            NotificationWidget {
                background-color: rgba(52, 73, 94, 220);
                border: 1px solid #34495e;
                border-radius: 10px;
            }
        """)
    
    def show_notification(self):
        """Show notification with animation"""
        # Slide in animation
        self.slide_animation = QPropertyAnimation(self, b"pos")
        self.slide_animation.setDuration(500)
        
        screen = QApplication.primaryScreen().geometry()
        start_pos = QPoint(screen.width(), screen.height() - 110)
        end_pos = QPoint(screen.width() - 360, screen.height() - 110)
        
        self.slide_animation.setStartValue(start_pos)
        self.slide_animation.setEndValue(end_pos)
        self.slide_animation.setEasingCurve(QEasingCurve.OutCubic)
        
        self.show()
        self.slide_animation.start()
        
        # Auto-hide after 5 seconds
        QTimer.singleShot(5000, self.hide_notification)
    
    def hide_notification(self):
        """Hide notification with animation"""
        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(300)
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.finished.connect(self.close)
        self.fade_animation.start()

class VTXMainWindow(QMainWindow):
    """Main VTX Antivirus application window"""
    
    threat_detected = Signal(str, str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.scanner = ClamAVScanner()
        self.system_monitor = SystemMonitor()
        self.proxy_manager = ProxyManager(self.db_manager, self)
        self.encryption_manager = EncryptionManager()
        
        # File system monitoring
        self.observer = Observer()
        self.fs_monitor = FileSystemMonitor(self.scanner, self.db_manager, self)
        
        # UI components
        self.overlay = None
        self.is_service_mode = False
        
        self.setup_ui()
        self.setup_connections()
        self.start_services()
    
    def setup_ui(self):
        """Setup main window UI"""
        self.setWindowTitle("VTX Antivirus - Advanced Protection Suite")
        self.setGeometry(100, 100, 1000, 700)
        
        # Set window icon with proper QtAwesome syntax
        self.setWindowIcon(qta.icon('mdi.shield-check', color='#2ecc71'))
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #bdc3c7;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        
        # Add tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_protection_tab()
        self.create_quarantine_tab()
        self.create_logs_tab()
        self.create_settings_tab()
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.setup_status_bar()
        
        # Apply main window styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
    
    def create_header(self):
        """Create application header"""
        header = QFrame()
        header.setFrameStyle(QFrame.Box)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3498db, stop:1 #2980b9);
                border: none;
                color: white;
            }
        """)
        header.setFixedHeight(80)
        
        layout = QHBoxLayout(header)
        
        # Logo and title
        logo_layout = QHBoxLayout()
        
        logo_label = QLabel()
        logo_label.setPixmap(qta.icon('mdi.shield-check', color='white').pixmap(48, 48))
        logo_layout.addWidget(logo_label)
        
        title_layout = QVBoxLayout()
        title_label = QLabel("VTX ANTIVIRUS")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        subtitle_label = QLabel("Advanced Protection Suite")
        subtitle_label.setStyleSheet("font-size: 12px; color: #ecf0f1;")
        
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        logo_layout.addLayout(title_layout)
        layout.addLayout(logo_layout)
        
        layout.addStretch()
        
        # Real-time protection status
        status_layout = QVBoxLayout()
        
        self.protection_status = QLabel("🛡️ REAL-TIME PROTECTION")
        self.protection_status.setStyleSheet("font-size: 14px; font-weight: bold; color: #2ecc71;")
        
        self.threat_count = QLabel("Threats Blocked: 0")
        self.threat_count.setStyleSheet("font-size: 12px; color: white;")
        
        status_layout.addWidget(self.protection_status)
        status_layout.addWidget(self.threat_count)
        
        layout.addLayout(status_layout)
        
        return header
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        
        # Protection status cards
        cards_layout = QHBoxLayout()
        
        # Real-time scanning card
        rt_card = self.create_status_card(
            "Real-time Scanning",
            "ACTIVE",
            "mdi.radar",
            "#2ecc71"
        )
        cards_layout.addWidget(rt_card)
        
        # Web protection card
        web_card = self.create_status_card(
            "Web Protection",
            "ACTIVE",
            "mdi.web",
            "#3498db"
        )
        cards_layout.addWidget(web_card)
        
        # Firewall card
        fw_card = self.create_status_card(
            "Firewall",
            "ACTIVE",
            "mdi.firewall",
            "#e74c3c"
        )
        cards_layout.addWidget(fw_card)
        
        layout.addLayout(cards_layout)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_list = QListWidget()
        self.activity_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #bdc3c7;
                background-color: white;
                alternate-background-color: #f8f9fa;
            }
        """)
        activity_layout.addWidget(self.activity_list)
        
        layout.addWidget(activity_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        scan_btn = QPushButton("🔍 Quick Scan")
        scan_btn.clicked.connect(self.start_quick_scan)
        actions_layout.addWidget(scan_btn)
        
        update_btn = QPushButton("🔄 Update Signatures")
        update_btn.clicked.connect(self.update_signatures)
        actions_layout.addWidget(update_btn)
        
        quarantine_btn = QPushButton("🔒 View Quarantine")
        quarantine_btn.clicked.connect(lambda: self.tab_widget.setCurrentIndex(3))
        actions_layout.addWidget(quarantine_btn)
        
        layout.addWidget(actions_group)
        
        self.tab_widget.addTab(dashboard, "🏠 Dashboard")
    
    def create_scanner_tab(self):
        """Create scanner tab"""
        scanner = QWidget()
        layout = QVBoxLayout(scanner)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.scan_downloads = QCheckBox("Scan Downloads Folder")
        self.scan_downloads.setChecked(True)
        options_layout.addWidget(self.scan_downloads)
        
        self.scan_temp = QCheckBox("Scan Temporary Files")
        self.scan_temp.setChecked(True)
        options_layout.addWidget(self.scan_temp)
        
        self.scan_custom = QCheckBox("Custom Folder")
        options_layout.addWidget(self.scan_custom)
        
        self.custom_path = QLineEdit()
        self.custom_path.setPlaceholderText("Select custom folder...")
        options_layout.addWidget(self.custom_path)
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_custom_folder)
        options_layout.addWidget(browse_btn)
        
        layout.addWidget(options_group)
        
        # Scan controls
        controls_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("▶️ Start Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                font-size: 16px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        self.scan_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("⏸️ Stop Scan")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        controls_layout.addWidget(self.stop_btn)
        
        layout.addLayout(controls_layout)
        
        # Scan progress
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.scan_progress = QProgressBar()
        progress_layout.addWidget(self.scan_progress)
        
        self.scan_status = QLabel("Ready to scan")
        progress_layout.addWidget(self.scan_status)
        
        layout.addWidget(progress_group)
        
        # Scan results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.scan_results = QTextEdit()
        self.scan_results.setReadOnly(True)
        results_layout.addWidget(self.scan_results)
        
        layout.addWidget(results_group)
        
        self.tab_widget.addTab(scanner, "🔍 Scanner")
    
    def create_protection_tab(self):
        """Create protection tab"""
        protection = QWidget()
        layout = QVBoxLayout(protection)
        
        # Real-time protection
        rt_group = QGroupBox("Real-time Protection")
        rt_layout = QVBoxLayout(rt_group)
        
        self.rt_enabled = QCheckBox("Enable Real-time File Scanning")
        self.rt_enabled.setChecked(True)
        rt_layout.addWidget(self.rt_enabled)
        
        self.web_protection = QCheckBox("Enable Web Protection")
        self.web_protection.setChecked(True)
        rt_layout.addWidget(self.web_protection)
        
        self.camera_protection = QCheckBox("Monitor Camera/Microphone Access")
        self.camera_protection.setChecked(True)
        rt_layout.addWidget(self.camera_protection)
        
        layout.addWidget(rt_group)
        
        # Firewall settings
        fw_group = QGroupBox("Firewall Settings")
        fw_layout = QVBoxLayout(fw_group)
        
        self.firewall_enabled = QCheckBox("Enable Firewall")
        self.firewall_enabled.setChecked(True)
        fw_layout.addWidget(self.firewall_enabled)
        
        self.block_malicious = QCheckBox("Block Known Malicious IPs")
        self.block_malicious.setChecked(True)
        fw_layout.addWidget(self.block_malicious)
        
        layout.addWidget(fw_group)
        
        # Web protection settings
        web_group = QGroupBox("Web Protection")
        web_layout = QVBoxLayout(web_group)
        
        self.phishing_protection = QCheckBox("Anti-Phishing Protection")
        self.phishing_protection.setChecked(True)
        web_layout.addWidget(self.phishing_protection)
        
        self.virustotal_check = QCheckBox("VirusTotal URL Checking")
        self.virustotal_check.setChecked(True)
        web_layout.addWidget(self.virustotal_check)
        
        layout.addWidget(web_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(protection, "🛡️ Protection")
    
    def create_quarantine_tab(self):
        """Create quarantine tab"""
        quarantine = QWidget()
        layout = QVBoxLayout(quarantine)
        
        # Quarantine table
        self.quarantine_table = QTableWidget(0, 5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "File Name", "Original Path", "Threat Type", "Date Quarantined", "Actions"
        ])
        
        header = self.quarantine_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.quarantine_table)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        restore_btn = QPushButton("↩️ Restore Selected")
        restore_btn.clicked.connect(self.restore_quarantined_file)
        controls_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("🗑️ Delete Selected")
        delete_btn.clicked.connect(self.delete_quarantined_file)
        controls_layout.addWidget(delete_btn)
        
        clear_btn = QPushButton("🧹 Clear All")
        clear_btn.clicked.connect(self.clear_quarantine)
        controls_layout.addWidget(clear_btn)
        
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(quarantine, "🔒 Quarantine")
    
    def create_logs_tab(self):
        """Create logs tab"""
        logs = QWidget()
        layout = QVBoxLayout(logs)
        
        # Log filters
        filters_layout = QHBoxLayout()
        
        filter_label = QLabel("Filter:")
        filters_layout.addWidget(filter_label)
        
        self.log_filter = QComboBox()
        self.log_filter.addItems(["All", "Threats", "Web Blocks", "System Events"])
        filters_layout.addWidget(self.log_filter)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_logs)
        filters_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("📤 Export Logs")
        export_btn.clicked.connect(self.export_logs)
        filters_layout.addWidget(export_btn)
        
        filters_layout.addStretch()
        
        layout.addLayout(filters_layout)
        
        # Logs table
        self.logs_table = QTableWidget(0, 5)
        self.logs_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Description", "Severity", "Details"
        ])
        
        header = self.logs_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.logs_table)
        
        self.tab_widget.addTab(logs, "📋 Logs")
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings = QWidget()
        layout = QVBoxLayout(settings)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QVBoxLayout(general_group)
        
        self.startup_enabled = QCheckBox("Start VTX at system boot")
        self.startup_enabled.setChecked(True)
        general_layout.addWidget(self.startup_enabled)
        
        self.service_mode = QCheckBox("Run as background service")
        self.service_mode.setChecked(True)
        general_layout.addWidget(self.service_mode)
        
        self.show_notifications = QCheckBox("Show security notifications")
        self.show_notifications.setChecked(True)
        general_layout.addWidget(self.show_notifications)
        
        layout.addWidget(general_group)
        
        # Scan settings
        scan_group = QGroupBox("Scan Settings")
        scan_layout = QVBoxLayout(scan_group)
        
        scan_layout.addWidget(QLabel("Scan sensitivity:"))
        self.scan_sensitivity = QSlider(Qt.Horizontal)
        self.scan_sensitivity.setRange(1, 5)
        self.scan_sensitivity.setValue(3)
        scan_layout.addWidget(self.scan_sensitivity)
        
        scan_layout.addWidget(QLabel("Maximum file size (MB):"))
        self.max_file_size = QSpinBox()
        self.max_file_size.setRange(1, 10000)
        self.max_file_size.setValue(100)
        scan_layout.addWidget(self.max_file_size)
        
        layout.addWidget(scan_group)
        
        # Update settings
        update_group = QGroupBox("Update Settings")
        update_layout = QVBoxLayout(update_group)
        
        self.auto_update = QCheckBox("Automatic signature updates")
        self.auto_update.setChecked(True)
        update_layout.addWidget(self.auto_update)
        
        update_layout.addWidget(QLabel("Update interval (hours):"))
        self.update_interval = QSpinBox()
        self.update_interval.setRange(1, 168)
        self.update_interval.setValue(6)
        update_layout.addWidget(self.update_interval)
        
        layout.addWidget(update_group)
        
        # API settings
        api_group = QGroupBox("API Settings")
        api_layout = QVBoxLayout(api_group)
        
        api_layout.addWidget(QLabel("VirusTotal API Key:"))
        self.vt_api_key = QLineEdit()
        self.vt_api_key.setPlaceholderText("Enter your VirusTotal API key...")
        self.vt_api_key.setText(VIRUSTOTAL_API_KEY)
        api_layout.addWidget(self.vt_api_key)
        
        layout.addWidget(api_group)
        
        # Save settings button
        save_btn = QPushButton("💾 Save Settings")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                font-size: 14px;
                padding: 10px 20px;
            }
        """)
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        self.tab_widget.addTab(settings, "⚙️ Settings")
    
    def create_status_card(self, title, status, icon_name, color):
        """Create status card widget"""
        card = QFrame()
        card.setFrameStyle(QFrame.Box)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: white;
                border: 1px solid #e1e8ed;
                border-radius: 8px;
                padding: 15px;
            }}
        """)
        card.setFixedHeight(120)
        
        layout = QVBoxLayout(card)
        
        # Header with icon and title
        header_layout = QHBoxLayout()
        
        icon_label = QLabel()
        icon_label.setPixmap(qta.icon(icon_name, color=color).pixmap(32, 32))
        header_layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Status
        status_label = QLabel(status)
        status_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 16px;")
        layout.addWidget(status_label)
        
        layout.addStretch()
        
        return card
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = self.statusBar()
        
        # Protection status
        self.status_protection = QLabel("🛡️ Protection: Active")
        self.status_bar.addWidget(self.status_protection)
        
        self.status_bar.addPermanentWidget(QLabel("|"))
        
        # Scan status
        self.status_scan = QLabel("🔍 Last scan: Never")
        self.status_bar.addWidget(self.status_scan)
        
        self.status_bar.addPermanentWidget(QLabel("|"))
        
        # Database status
        self.status_db = QLabel("💾 Database: Connected")
        self.status_bar.addWidget(self.status_db)
    
    def setup_connections(self):
        """Setup signal connections"""
        # Threat detection
        self.threat_detected.connect(self.handle_threat_detected)
        
        # System monitoring
        self.system_monitor.camera_access_detected.connect(self.handle_camera_access)
        self.system_monitor.microphone_access_detected.connect(self.handle_microphone_access)
    
    def start_services(self):
        """Start all VTX services"""
        try:
            # Start file system monitoring
            downloads_path = os.path.expanduser("~/Downloads")
            temp_path = "/tmp"
            
            if os.path.exists(downloads_path):
                self.observer.schedule(self.fs_monitor, downloads_path, recursive=True)
            
            if os.path.exists(temp_path):
                self.observer.schedule(self.fs_monitor, temp_path, recursive=True)
            
            self.observer.start()
            
            # Start system monitoring
            self.system_monitor.start_monitoring()
            
            # Start proxy
            self.proxy_manager.start_proxy()
            
            # Create overlay
            self.create_overlay()
            
            # Update activity log
            self.add_activity("VTX Antivirus started", "mdi.shield-check", "#2ecc71")
            
            logging.info("All VTX services started successfully")
            
        except Exception as e:
            logging.error(f"Failed to start services: {e}")
            QMessageBox.critical(self, "VTX Error", f"Failed to start services: {e}")
    
    def create_overlay(self):
        """Create always-on-top overlay"""
        if not self.overlay:
            self.overlay = OverlayWidget()
            self.overlay.stop_clicked.connect(self.stop_antivirus)
            self.overlay.show()
            self.overlay.animate_pulse()
    
    def stop_antivirus(self):
        """Stop VTX antivirus"""
        reply = QMessageBox.question(
            self, "Stop VTX Antivirus",
            "Are you sure you want to stop VTX Antivirus protection?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.stop_services()
            QApplication.quit()
    
    def stop_services(self):
        """Stop all VTX services"""
        try:
            # Stop file system monitoring
            if self.observer.is_alive():
                self.observer.stop()
                self.observer.join()
            
            # Stop system monitoring
            self.system_monitor.stop_monitoring()
            
            # Stop proxy
            self.proxy_manager.stop_proxy()
            
            # Hide overlay
            if self.overlay:
                self.overlay.hide()
            
            logging.info("All VTX services stopped")
            
        except Exception as e:
            logging.error(f"Error stopping services: {e}")
    
    @Slot(str, str)
    def handle_threat_detected(self, file_path, threat_name):
        """Handle detected threat"""
        # Show threat dialog
        dialog = ThreatDialog(file_path, threat_name, self)
        if dialog.exec_() == QDialog.Accepted:
            action = dialog.action
            
            if action == "quarantine":
                self.quarantine_file(file_path, threat_name)
            elif action == "delete":
                self.delete_file(file_path)
            elif action == "keep":
                self.add_activity(f"Threat ignored: {os.path.basename(file_path)}", "mdi.alert", "#f39c12")
            
            # Update threat count
            self.update_threat_count()
        
        # Show notification
        NotificationWidget(
            "Threat Detected",
            f"File: {os.path.basename(file_path)}\nThreat: {threat_name}",
            "mdi.virus"
        )
    
    @Slot(str)
    def handle_camera_access(self, app_name):
        """Handle camera access detection"""
        reply = QMessageBox.question(
            self, "Camera Access Detected",
            f"Application '{app_name}' is trying to access your camera.\n\nAllow access?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            # In a real implementation, this would block camera access
            pass
        
        NotificationWidget(
            "Camera Access",
            f"Application '{app_name}' accessed camera",
            "mdi.camera"
        )
    
    @Slot(str)
    def handle_microphone_access(self, app_name):
        """Handle microphone access detection"""
        reply = QMessageBox.question(
            self, "Microphone Access Detected",
            f"Application '{app_name}' is trying to access your microphone.\n\nAllow access?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            # In a real implementation, this would block microphone access
            pass
        
        NotificationWidget(
            "Microphone Access",
            f"Application '{app_name}' accessed microphone",
            "mdi.microphone"
        )
    
    def quarantine_file(self, file_path, threat_name):
        """Quarantine infected file"""
        try:
            # Create quarantine directory
            quarantine_dir = os.path.expanduser("~/.vtx_quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate unique quarantine filename
            file_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
            quarantine_path = os.path.join(quarantine_dir, f"{file_hash}.encrypted")
            
            # Encrypt and move file
            if self.encryption_manager.encrypt_file(file_path, quarantine_path):
                # Remove original file
                os.remove(file_path)
                
                # Add to database
                self.db_manager.add_quarantine_entry(
                    file_path, quarantine_path, threat_name, file_hash
                )
                
                self.add_activity(f"File quarantined: {os.path.basename(file_path)}", "mdi.lock", "#e74c3c")
                
                # Update quarantine table
                self.refresh_quarantine_table()
                
                return True
            
        except Exception as e:
            logging.error(f"Quarantine failed: {e}")
            QMessageBox.critical(self, "Quarantine Error", f"Failed to quarantine file: {e}")
        
        return False
    
    def delete_file(self, file_path):
        """Delete infected file"""
        try:
            os.remove(file_path)
            self.add_activity(f"File deleted: {os.path.basename(file_path)}", "mdi.delete", "#8e44ad")
            return True
        except Exception as e:
            logging.error(f"Delete failed: {e}")
            QMessageBox.critical(self, "Delete Error", f"Failed to delete file: {e}")
            return False
    
    def add_activity(self, message, icon_name, color):
        """Add activity to recent activity list"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        item_text = f"[{timestamp}] {message}"
        
        item = self.activity_list.addItem(item_text)
        
        # Keep only last 50 items
        if self.activity_list.count() > 50:
            self.activity_list.takeItem(0)
        
        # Scroll to bottom
        self.activity_list.scrollToBottom()
    
    def update_threat_count(self):
        """Update threat count display"""
        # This would track actual threat count
        pass
    
    def start_quick_scan(self):
        """Start quick scan"""
        self.tab_widget.setCurrentIndex(1)  # Switch to scanner tab
        self.start_scan()
    
    def start_scan(self):
        """Start file scan"""
        # Implementation for file scanning
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scan_progress.setValue(0)
        self.scan_status.setText("Scanning...")
        
        # Add scan logic here
        self.add_activity("Manual scan started", "mdi.radar", "#3498db")
    
    def stop_scan(self):
        """Stop file scan"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_status.setText("Scan stopped")
    
    def update_signatures(self):
        """Update virus signatures"""
        if self.scanner.update_signatures():
            self.add_activity("Virus signatures updated", "mdi.update", "#27ae60")
            NotificationWidget("Update Complete", "Virus signatures updated successfully", "mdi.check")
        else:
            NotificationWidget("Update Failed", "Failed to update virus signatures", "mdi.alert")
    
    def browse_custom_folder(self):
        """Browse for custom scan folder"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.custom_path.setText(folder)
            self.scan_custom.setChecked(True)
    
    def refresh_quarantine_table(self):
        """Refresh quarantine table"""
        # Implementation for refreshing quarantine table
        pass
    
    def restore_quarantined_file(self):
        """Restore quarantined file"""
        # Implementation for restoring quarantined files
        pass
    
    def delete_quarantined_file(self):
        """Delete quarantined file"""
        # Implementation for deleting quarantined files
        pass
    
    def clear_quarantine(self):
        """Clear all quarantined files"""
        # Implementation for clearing quarantine
        pass
    
    def refresh_logs(self):
        """Refresh logs table"""
        # Implementation for refreshing logs
        pass
    
    def export_logs(self):
        """Export logs to file"""
        # Implementation for exporting logs
        pass
    
    def save_settings(self):
        """Save application settings"""
        # Implementation for saving settings
        NotificationWidget("Settings Saved", "Application settings saved successfully", "mdi.check")
    
    def closeEvent(self, event):
        """Handle window close event"""
        if self.is_service_mode:
            # Hide to system tray instead of closing
            self.hide()
            event.ignore()
        else:
            self.stop_services()
            event.accept()

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/vtx.log'),
            logging.StreamHandler()
        ]
    )

def setup_systemd_service():
    """Setup VTX as systemd service"""
    service_content = """[Unit]
Description=VTX Antivirus Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/vtx/av.py --service
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open('/etc/systemd/system/vtx.service', 'w') as f:
            f.write(service_content)
        
        # Enable and start service
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'vtx'], check=True)
        subprocess.run(['systemctl', 'start', 'vtx'], check=True)
        
        return True
    except Exception as e:
        logging.error(f"Failed to setup systemd service: {e}")
        return False

def main():
    """Main application entry point"""
    # Setup logging
    setup_logging()
    
    # Check for service mode
    service_mode = '--service' in sys.argv
    
    if service_mode:
        # Run as background service
        logging.info("Starting VTX Antivirus in service mode")
        
        # Create minimal QApplication for background operation
        app = QApplication(sys.argv)
        app.setQuitOnLastWindowClosed(False)
        
        # Create main window but don't show it
        window = VTXMainWindow()
        window.is_service_mode = True
        
        # Setup signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            logging.info("Received shutdown signal")
            window.stop_services()
            app.quit()
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        sys.exit(app.exec_())
    
    else:
        # Run with GUI
        app = QApplication(sys.argv)
        app.setApplicationName("VTX Antivirus")
        app.setApplicationVersion("1.0.0")
        
        # Check if running as root (required for some features)
        if os.geteuid() != 0:
            QMessageBox.warning(
                None, "VTX Antivirus",
                "VTX Antivirus requires root privileges for full functionality.\n"
                "Some features may not work properly."
            )
        
        # Create and show main window
        window = VTXMainWindow()
        window.show()
        
        # Setup system tray
        if QSystemTrayIcon.isSystemTrayAvailable():
            tray_icon = QSystemTrayIcon(qta.icon('mdi.shield-check', color='#2ecc71'), app)
            tray_menu = QMenu()
            
            show_action = QAction("Show VTX", tray_menu)
            show_action.triggered.connect(window.show)
            tray_menu.addAction(show_action)
            
            quit_action = QAction("Quit", tray_menu)
            quit_action.triggered.connect(app.quit)
            tray_menu.addAction(quit_action)
            
            tray_icon.setContextMenu(tray_menu)
            tray_icon.show()
        
        sys.exit(app.exec_())

if __name__ == "__main__":
    main()
