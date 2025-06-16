import socket
from urllib.parse import urlparse
from datetime import datetime
from threading import Thread, Lock
from queue import Queue

NUM_THREADS = 100
print_lock = Lock()
q = Queue()

# Basic vulnerability hints for common ports/services
VULN_HINTS = {
    21: "FTP - Check for anonymous login and weak credentials.",
    22: "SSH - Check for weak passwords and outdated versions.",
    23: "Telnet - Insecure protocol, avoid using.",
    25: "SMTP - Open relay misconfiguration possible.",
    53: "DNS - Possible DNS amplification attack vector.",
    80: "HTTP - Check for outdated software and common web vulnerabilities.",
    110: "POP3 - Check for weak authentication.",
    139: "NetBIOS - Often vulnerable to SMB exploits.",
    143: "IMAP - Check for weak authentication.",
    443: "HTTPS - Check SSL/TLS configuration and vulnerabilities.",
    445: "SMB - Vulnerable to exploits like EternalBlue.",
    3306: "MySQL - Check for weak/default credentials.",
    3389: "RDP - Check for brute-force vulnerabilities.",
    5900: "VNC - Check for weak authentication.",
    8080: "HTTP Proxy - Check for open proxy vulnerabilities."
}

def get_hostname_from_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed_url = urlparse(url)
    return parsed_url.hostname

def grab_banner(target, port, timeout=1.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target, port))
        # Try to receive banner (up to 1024 bytes)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except:
        return ""

def port_scan(target, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(target, port, timeout)
            with print_lock:
                print(f"[+] Port {port} is open")
                if banner:
                    print(f"    Banner: {banner}")
                if port in VULN_HINTS:
                    print(f"    [!] Vulnerability hint: {VULN_HINTS[port]}")
                else:
                    # Basic banner keyword checks for vulnerability hints
                    banner_lower = banner.lower()
                    if "ftp" in banner_lower:
                        print("    [!] FTP service detected - check for anonymous login.")
                    elif "ssh" in banner_lower:
                        print("    [!] SSH service detected - check for weak credentials.")
                    elif "http" in banner_lower:
                        print("    [!] HTTP service detected - check for web vulnerabilities.")
    except socket.error:
        pass
    finally:
        s.close()

def worker(target, timeout):
    while True:
        port = q.get()
        if port is None:
            break
        port_scan(target, port, timeout)
        q.task_done()

def main():
    url_input = input("Enter the target URL or hostname (e.g., http://example.com or 192.168.1.1): ").strip()
    start_port = int(input("Enter the start port number (e.g., 1): ").strip())
    end_port = int(input("Enter the end port number (e.g., 1024): ").strip())
    timeout = 1.0

    target_host = get_hostname_from_url(url_input)
    print(f"Scanning {target_host} from port {start_port} to {end_port} with timeout {timeout}s using {NUM_THREADS} threads")
    print("=" * 50)

    start_time = datetime.now()

    threads = []
    for _ in range(NUM_THREADS):
        t = Thread(target=worker, args=(target_host, timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    for port in range(start_port, end_port + 1):
        q.put(port)

    q.join()

    for _ in range(NUM_THREADS):
        q.put(None)
    for t in threads:
        t.join()

    end_time = datetime.now()
    print("=" * 50)
    print(f"Scanning completed in: {end_time - start_time}")

if __name__ == "__main__":
    main()
