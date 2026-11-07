# server-audit lab (RHEL family): AlmaLinux 9 with nginx, firewalld installed but stopped, SELinux off.
# Every secret below is generated at build time and FAKE. Never run this image anywhere reachable.
set -e
dnf -y -q install python3 nginx openssh-server sudo cronie iproute procps-ng git findutils which \
    firewalld libselinux-utils shadow-utils util-linux >/dev/null
useradd -m -u 1000 ops
useradd -m deploy
echo 'ops ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ops
chmod 440 /etc/sudoers.d/ops
echo 'deploy:winter2026' | chpasswd
ssh-keygen -A >/dev/null
# an old drop-in that sorts before the vendor default and wins
echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/40-legacy.conf

# nginx: an app with an open /admin, a protected /private, a directory listing, an HTTP-only admin site
mkdir -p /srv/www/files
echo hello > /srv/www/files/readme.txt
cat > /etc/nginx/conf.d/shop.conf <<'EOS'
server {
    listen 80;
    server_name shop.example.com;
    location / { proxy_pass http://127.0.0.1:8080; }
    location /admin/ { proxy_pass http://127.0.0.1:8080; }
    location /private/ {
        auth_basic "staff";
        auth_basic_user_file /etc/nginx/htpasswd;
        proxy_pass http://127.0.0.1:8080;
    }
    location /files/ { root /srv/www; autoindex on; }
}
server {
    listen 80;
    server_name grafana.example.com;
    location / { proxy_pass http://127.0.0.1:3000; }
}
EOS

# app secrets readable by everyone (fake)
mkdir -p /opt/shop
printf 'DB_PASSWORD=%s\n' "$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')" > /opt/shop/.env
chmod 644 /opt/shop/.env

# a SUID copy of find that no package owns
cp /usr/bin/find /usr/local/bin/findx && chmod 4755 /usr/local/bin/findx
dnf clean all >/dev/null
