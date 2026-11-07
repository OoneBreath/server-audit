/usr/sbin/sshd
crond
nginx
su deploy -s /bin/sh -c 'cd /tmp && nohup python3 -m http.server 8080 >/dev/null 2>&1 &'
exec sleep infinity
