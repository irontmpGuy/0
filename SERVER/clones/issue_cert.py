#!/usr/bin/env python3
import subprocess
import os
import sys
import re

# ---------------- CONFIG ----------------
CERTBOT_PATH = "/home/ubuntu/certbot-env/bin/certbot"
CLOUDFLARE_CRED = "/etc/letsencrypt/cloudflare.ini"
CONFIG_DIR = "/home/ubuntu/certbot-config"
WORK_DIR = "/home/ubuntu/certbot-work"
LOGS_DIR = "/home/ubuntu/certbot-logs"
NGINX_COMMON_CONF = "/etc/nginx/sites-available/files"  # all domains in this file
EMAIL = "youremail@example.com"
SSL_OPTIONS = "/etc/letsencrypt/options-ssl-nginx.conf"
SSL_DHPARAM = "/etc/letsencrypt/ssl-dhparams.pem"
DEFAULT_WEBROOT = "/home/ubuntu/Server/clones/epic-nitro"
# ----------------------------------------

if len(sys.argv) < 2:
    print("Usage: python3 issue_cert.py full.domain.example.com [webroot]")
    sys.exit(1)

domain = sys.argv[1]

# Optional webroot argument
if len(sys.argv) >= 3:
    webroot = os.path.expanduser(sys.argv[2])
    webroot = os.path.abspath(webroot)
else:
    webroot = DEFAULT_WEBROOT

cert_name = domain.replace(".", "_")  # unique log names

# 0️⃣ Ensure webroot exists and is accessible by nginx
print(f"[+] Ensuring webroot exists and is readable: {webroot}")

os.makedirs(webroot, exist_ok=True)

# Ensure traversal permissions up the tree
path_parts = webroot.strip("/").split("/")
current = "/"
for part in path_parts:
    current = os.path.join(current, part)
    try:
        os.chmod(current, 0o755)
    except PermissionError:
        pass  # might not own all parents

# Ensure files are world-readable (nginx = www-data)
for root_dir, dirs, files in os.walk(webroot):
    for d in dirs:
        try:
            os.chmod(os.path.join(root_dir, d), 0o755)
        except PermissionError:
            pass
    for f in files:
        try:
            os.chmod(os.path.join(root_dir, f), 0o644)
        except PermissionError:
            pass

# 1️⃣ Issue or expand certificate (wildcard included)
print(f"[+] Requesting certificate for {domain} and *.{domain}...")
cmd = [
    CERTBOT_PATH, "certonly",
    "--authenticator", "dns-cloudflare",
    "--dns-cloudflare-credentials", CLOUDFLARE_CRED,
    "-d", domain,
    "-d", f"*.{domain}",
    "--config-dir", CONFIG_DIR,
    "--work-dir", WORK_DIR,
    "--logs-dir", LOGS_DIR,
    "--non-interactive",
    "--agree-tos",
    "--expand",
    "-m", EMAIL,
    "--dns-cloudflare-propagation-seconds", "80"
]
subprocess.run(cmd, check=True)

# 2️⃣ Read existing /files content
if os.path.exists(NGINX_COMMON_CONF):
    with open(NGINX_COMMON_CONF, "r") as f:
        content = f.read()
else:
    content = ""

# 3️⃣ Check if a server block for this domain already exists
pattern = re.compile(rf"server\s*\{{[^}}]*server_name\s+.*\b{re.escape(domain)}\b.*\}}", re.DOTALL)
if pattern.search(content):
    print(f"[+] Server block for {domain} already exists in /files. Skipping addition.")
    add_block = False
else:
    add_block = True

# 4️⃣ Prepare server block content
server_block = f"""
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name {domain} *.{domain};

    ssl_certificate {CONFIG_DIR}/live/{domain}/fullchain.pem;
    ssl_certificate_key {CONFIG_DIR}/live/{domain}/privkey.pem;
    include {SSL_OPTIONS};
    ssl_dhparam {SSL_DHPARAM};

    root {webroot};
    index index.html;
    charset utf-8;

    access_log /var/log/nginx/{cert_name}_access.log;
    error_log /var/log/nginx/{cert_name}_error.log warn;

    error_page 404 /index.html;

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""

# 5️⃣ Append server block if needed
if add_block:
    new_content = content.strip() + "\n\n" + server_block.strip() if content else server_block.strip()
    with open(NGINX_COMMON_CONF, "w") as f:
        f.write(new_content + "\n")
    print(f"[+] Added new server block for {domain} in /files...")
else:
    print(f"[+] No changes made to /files for {domain}.")

# 6️⃣ Test and reload NGINX
print("[+] Testing NGINX config...")
try:
    subprocess.run(["sudo", "nginx", "-t"], check=True)
except subprocess.CalledProcessError:
    print("[❌] NGINX test failed! Check the config manually.")
    sys.exit(1)

print("[+] Reloading NGINX...")
subprocess.run(["sudo", "systemctl", "reload", "nginx"], check=True)

print(f"[✅] Certificate issued/updated and NGINX configured for {domain}")
