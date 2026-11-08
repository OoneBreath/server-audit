# server-audit lab (RHEL family): AlmaLinux 9 with nginx, firewalld installed but stopped, SELinux off.
# Every secret below is generated at build time and FAKE. Never run this image anywhere reachable.
set -e
dnf -y -q install python3 nginx openssh-server sudo cronie iproute procps-ng git findutils which \
    firewalld libselinux-utils shadow-utils util-linux haproxy >/dev/null
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
# a PHP webmail that protects its internal directories with .htaccess only (nginx never reads it)
server {
    listen 80;
    server_name webmail.example.com;
    root /srv/webmail;
    index index.php;
    location ~ \.php$ { fastcgi_pass 127.0.0.1:9000; }
}
EOS
mkdir -p /srv/webmail/config /srv/webmail/logs /srv/webmail/skins
echo '<?php echo "webmail";' > /srv/webmail/index.php
echo 'Require all denied' > /srv/webmail/config/.htaccess
printf 'Order deny,allow\nDeny from all\n' > /srv/webmail/logs/.htaccess
echo 'Options -Indexes' > /srv/webmail/skins/.htaccess

# app secrets readable by everyone (fake)
mkdir -p /opt/shop
printf 'DB_PASSWORD=%s\n' "$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')" > /opt/shop/.env
chmod 644 /opt/shop/.env

# nightly offsite copy: rclone crypt over a cloud-drive remote (fake token), mirrored with `rclone sync`
mkdir -p /root/.config/rclone /var/backups/shop /var/log/shop
cat > /root/.config/rclone/rclone.conf <<EOS
[gdrive]
type = drive
scope = drive
token = {"access_token":"$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')","token_type":"Bearer"}

[gcrypt]
type = crypt
remote = gdrive:server-backups
password = $(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')
EOS
chmod 600 /root/.config/rclone/rclone.conf
cat > /usr/local/sbin/shop-offsite.sh <<'EOS'
#!/bin/sh
tar czf /var/backups/shop/shop-$(date +%F).tgz /opt/shop /srv/www
rclone sync /var/backups/shop gcrypt:web-01 >> /var/log/shop/offsite.log 2>&1 && echo "$(date -Is) offsite OK" >> /var/log/shop/offsite.log
echo "$(date -Is) shop-offsite: done"
EOS
chmod 755 /usr/local/sbin/shop-offsite.sh
# run the way many crontabs do: cd, then a relative script (the audit must still follow it)
# and cron keeps the job's stdout in a second log: one missed night shows in both (one finding, not two)
echo '30 3 * * * root cd /usr/local/sbin && ./shop-offsite.sh >> /var/log/shop/cron.log 2>&1' > /etc/cron.d/shop-offsite
tar czf /var/backups/shop/shop-2026-11-01.tgz /srv/www 2>/dev/null
# the job's log: a good run every night, except one night when the host was off (nothing alerted)
for d in 12 11 10 9 8 7 6 4 3 2 1; do
    echo "$(date -u -d "$d days ago" +%Y-%m-%dT03:30:00+00:00) offsite OK" >> /var/log/shop/offsite.log
    echo "$(date -u -d "$d days ago" +%Y-%m-%dT03:31:00+00:00) shop-offsite: done" >> /var/log/shop/cron.log
done

# HAProxy: the runtime API on the network, a stats page without auth, /admin routed without auth, a plain-text
# userlist password (FAKE) in a config every local user can read
cat > /etc/haproxy/haproxy.cfg <<EOS
global
    log /dev/log local0
    stats socket ipv4@0.0.0.0:9999 level admin
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
userlist staff
    user admin insecure-password $(python3 -c 'import secrets;print(secrets.token_urlsafe(14))')
frontend public
    bind *:8081
    acl is_admin path_beg /admin
    use_backend app if is_admin
    default_backend app
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats admin if TRUE
backend app
    server a1 127.0.0.1:8080
EOS
chmod 644 /etc/haproxy/haproxy.cfg

# a SUID copy of find that no package owns
cp /usr/bin/find /usr/local/bin/findx && chmod 4755 /usr/local/bin/findx
dnf clean all >/dev/null
