/usr/sbin/sshd
cron
su deploy -s /bin/sh -c 'cd /srv/shop && nohup python3 -m http.server 8080 >/var/log/shop/http.log 2>&1 &'
# a stand-in "cache" on the Redis port, open to every interface
su deploy -s /bin/sh -c 'cd /tmp && nohup python3 -m http.server 6379 >/dev/null 2>&1 &'
su deploy -s /bin/sh -c 'nohup python3 /srv/cdn/edge.py >/dev/null 2>&1 &'
exec sleep infinity
