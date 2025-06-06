import socket
import sys
import json
import threading
import hashlib
import base64
import time
import secrets
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel, QFileDialog, QMessageBox, QScrollArea, QFrame)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QTextCursor, QIcon, QFont

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- DH-2048/Signal-Inspired Classes (Custom) -----------
class DH2048:
    prime_hex = (
        "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
        "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
        "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
        "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
        "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
        "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
        "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
        "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B"
    )
    g = 7

    def __init__(self):
        self.p = int(self.prime_hex, 16)
        self.g = DH2048.g
        self.priv = secrets.randbelow(self.p-2) + 2
        self.pub = pow(self.g, self.priv, self.p)

    def get_public(self):
        return self.pub

    def compute_shared(self, other_pub):
        if not (2 <= other_pub <= self.p-2):
            raise Exception("Invalid DH public value")
        return pow(other_pub, self.priv, self.p)

# ---------- RSA-2048 (for signatures/auth) ----------
def gen_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

# ---------- HKDF (RFC 5869) ----------
def hkdf_sha256(secret, salt, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(secret)

# ---------- AES-256-GCM ----------
def aesgcm_encrypt(key, plaintext, aad=b""):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext

def aesgcm_decrypt(key, enc, aad=b""):
    aesgcm = AESGCM(key)
    nonce = enc[:12]
    ct = enc[12:]
    return aesgcm.decrypt(nonce, ct, aad)

# ---------- HMAC-SHA256 ----------
def hmac_sha256(key, msg):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()

# ---------- AUTH KEY/SESSION (inspired by MTProto 2.0) ----------
class AuthKey:
    """Permanent and Temporary session keys for PFS, as in MTProto 2.0."""
    def __init__(self):
        self.perm_dh = DH2048()
        self.perm_pub = self.perm_dh.get_public()
        self.temp_dh = DH2048()
        self.temp_pub = self.temp_dh.get_public()
        self.perm_shared = None
        self.temp_shared = None
        self.session_id = secrets.token_bytes(8)
        self.salt = secrets.token_bytes(8)
        self.expires_at = int(time.time()) + 8 * 3600  # valid for 8h

    def compute_perm_shared(self, peer_pub):
        self.perm_shared = self.perm_dh.compute_shared(peer_pub)

    def compute_temp_shared(self, peer_temp_pub):
        self.temp_shared = self.temp_dh.compute_shared(peer_temp_pub)

    def get_perm_auth_key(self):
        # 256 bytes (2048 bits) for permanent key
        return self.perm_shared.to_bytes(256, "big") if self.perm_shared else None

    def get_temp_auth_key(self):
        return self.temp_shared.to_bytes(256, "big") if self.temp_shared else None

    def fingerprint(self, key=None):
        if key is None:
            key = self.get_temp_auth_key()
        return hashlib.sha256(key).hexdigest()[:32] if key else None

# ---------- PySide6 GUI/Client Logic ----------
class ChatClient(QWidget):
    message_signal = Signal(str, str)        # (text, sender)
    status_signal = Signal(str)              # status/system messages
    fingerprint_signal = Signal(str)         # fingerprint string
    enable_input_signal = Signal(bool)       # enable/disable input

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secret Chat - E2EE (MTProto2/Signal/PFS)")
        self.setWindowIcon(QIcon())
        self.setMinimumSize(600, 600)
        font = QFont("Arial", 11)
        self.setFont(font)
        self.peer_pub = None
        self.peer_temp_pub = None
        self.room = None
        self.sock = None
        self.authkey = AuthKey()
        self.shared_key = None
        self.temp_key = None
        self.aes_key = None
        self.connected = False
        self.ready = False
        self.updater_timer = QTimer()
        self.init_ui()
        # Connect signals
        self.message_signal.connect(self.show_message)
        self.status_signal.connect(self.show_status)
        self.fingerprint_signal.connect(self.set_fingerprint)
        self.enable_input_signal.connect(self.set_input_enabled)
        self.show()
        self.start_auto_updater()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.top_label = QLabel("<b>Secret Chat - End-to-End Encrypted (MTProto2/Signal/PFS)</b>")
        self.layout.addWidget(self.top_label)

        self.room_input = QLineEdit()
        self.room_input.setPlaceholderText("Enter room name to join/create...")
        self.layout.addWidget(self.room_input)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_to_server)
        self.layout.addWidget(self.connect_btn)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.chat_frame = QFrame()
        self.chat_layout = QVBoxLayout()
        self.chat_frame.setLayout(self.chat_layout)
        self.scroll.setWidget(self.chat_frame)
        self.layout.addWidget(self.scroll, stretch=1)

        self.fingerprint_label = QLabel("Key fingerprint: <i>Not established</i>")
        self.layout.addWidget(self.fingerprint_label)

        hl = QHBoxLayout()
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type your secret message here...")
        self.msg_input.setEnabled(False)
        self.send_btn = QPushButton("Send")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_msg)
        hl.addWidget(self.msg_input)
        hl.addWidget(self.send_btn)
        self.layout.addLayout(hl)
        self.setLayout(self.layout)

    def show_message(self, text, sender="me"):
        bubble = QLabel()
        html = (
            '<div style="background:#e2f0cb; border-radius:12px; padding:8px 16px; margin:8px;'
            'max-width:65%%;display:inline-block; float:%s;"><b>%s</b><br>%s</div>'
        ) % ("right" if sender == "me" else "left", "Me" if sender == "me" else "Peer", text)
        bubble.setTextFormat(Qt.RichText)
        bubble.setText(html)
        bubble.setWordWrap(True)
        bubble.setAlignment(Qt.AlignLeft if sender=="peer" else Qt.AlignRight)
        self.chat_layout.addWidget(bubble)
        self.chat_frame.adjustSize()
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def show_status(self, text):
        self.show_message(f"<i>{text}</i>", sender="system")

    def set_fingerprint(self, fp):
        self.fingerprint_label.setText(f"Key fingerprint (verify with peer!): <b>{fp}</b>")

    def set_input_enabled(self, enabled):
        self.msg_input.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def connect_to_server(self):
        room = self.room_input.text().strip()
        if not room:
            QMessageBox.warning(self, "Room", "Please enter a room name!")
            return
        self.room = room
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect(("127.0.0.1", 9988))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to connect: {e}")
            return
        self.sock.send(json.dumps({"room": self.room}).encode())
        self.room_input.setEnabled(False)
        self.connect_btn.setEnabled(False)
        t = threading.Thread(target=self.receive_loop, daemon=True)
        t.start()

    def receive_loop(self):
        while True:
            try:
                data = self.sock.recv(65536)
                if not data:
                    break
                try:
                    msg = json.loads(data.decode())
                    if msg.get("redirect"):
                        self.room = msg["redirect"]
                        self.sock.close()
                        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.sock.connect(("127.0.0.1", 9988))
                        self.sock.send(json.dumps({"room": self.room}).encode())
                        continue
                    if msg.get("status") == "waiting":
                        self.status_signal.emit("Waiting for peer...")
                        continue
                    if msg.get("status") == "ready":
                        self.connected = True
                        self.status_signal.emit("Peer found! Starting key exchange...")
                        self.start_handshake()
                        continue
                except Exception:
                    pass  # Not JSON, treat as encrypted msg

                # If not JSON, it's encrypted: treat as chat payload
                if self.aes_key:
                    try:
                        plaintext = aesgcm_decrypt(self.aes_key, data)
                        self.message_signal.emit(plaintext.decode(), "peer")
                    except Exception:
                        self.status_signal.emit("[!] Failed to decrypt message")
            except Exception:
                break

    def start_handshake(self):
        # 1. Send our permanent and temp DH public keys
        payload = {
            "perm_pub": str(self.authkey.perm_pub),
            "temp_pub": str(self.authkey.temp_pub),
            "expires_at": self.authkey.expires_at,
        }
        self.sock.send(json.dumps({"keyx": payload}).encode())
        threading.Thread(target=self.handshake_recv, daemon=True).start()

    def handshake_recv(self):
        while not (self.peer_pub and self.peer_temp_pub):
            try:
                data = self.sock.recv(65536)
                if not data:
                    break
                msg = json.loads(data.decode())
                if msg.get("keyx"):
                    peer = msg["keyx"]
                    self.peer_pub = int(peer["perm_pub"])
                    self.peer_temp_pub = int(peer["temp_pub"])
                    self.authkey.compute_perm_shared(self.peer_pub)
                    self.authkey.compute_temp_shared(self.peer_temp_pub)
                    temp_key = hkdf_sha256(
                        self.authkey.get_temp_auth_key(),
                        b"mtproto2-e2ee", b"chat-session", 32
                    )
                    self.aes_key = temp_key
                    fp = self.authkey.fingerprint(self.authkey.get_temp_auth_key())
                    self.fingerprint_signal.emit(fp)
                    self.status_signal.emit("Secure session established! You can now chat.")
                    self.enable_input_signal.emit(True)
                    break
            except Exception:
                break

    def send_msg(self):
        text = self.msg_input.text().strip()
        if not text or not self.aes_key:
            return
        try:
            enc = aesgcm_encrypt(self.aes_key, text.encode())
            self.sock.sendall(enc)
            self.message_signal.emit(text, "me")
            self.msg_input.clear()
        except Exception as e:
            self.status_signal.emit(f"Failed to send: {e}")

    # ------- Auto-updater logic -----------
    def start_auto_updater(self):
        self.updater_timer.timeout.connect(self.check_update)
        self.updater_timer.start(60000)  # check every 60s

    def check_update(self):
        import requests
        VERSION = "1.0.0"
        VERSION_URL = "http://127.0.0.1/version.txt"
        UPDATE_URL = "http://127.0.0.1/chat_new.py"
        try:
            remote_version = requests.get(VERSION_URL, timeout=2).text.strip()
            if remote_version != VERSION:
                r = requests.get(UPDATE_URL, timeout=5)
                if r.status_code == 200:
                    with open("chat_new.py", "wb") as f:
                        f.write(r.content)
                    QMessageBox.information(self, "Update", "A new version is available and downloaded. Please restart the app.")
        except Exception:
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ChatClient()
    sys.exit(app.exec())
