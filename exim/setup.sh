#!/bin/bash
set -eu
D=/tmp/eximtest
CR=/tmp/eximtest-root
sudo mkdir -p "$D/spool" "$D/log" "$CR"
sudo chown -R Debian-exim:Debian-exim "$D"
sudo chown root:root "$CR"
sudo chmod 755 "$CR"
sudo openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/key.pem" \
  -out "$D/cert.pem" -days 1 -subj "/CN=test.local" >/dev/null 2>&1
sudo chmod 644 "$D/cert.pem"
sudo chmod 640 "$D/key.pem"
sudo chown Debian-exim:Debian-exim "$D/key.pem"
sudo tee "$CR/exim.conf" >/dev/null <<'EOF'
primary_hostname = test.local
domainlist local_domains = test.local
acl_smtp_mail = accept
acl_smtp_rcpt = accept
acl_smtp_predata = accept
acl_smtp_data = accept
tls_advertise_hosts = *
tls_certificate = /tmp/eximtest/cert.pem
tls_privatekey = /tmp/eximtest/key.pem
chunking_advertise_hosts = *
daemon_smtp_ports = 2525
local_interfaces = 127.0.0.1
spool_directory = /tmp/eximtest/spool
log_file_path = /tmp/eximtest/exim-%s.log
pid_file_path = /tmp/eximtest/exim.pid
EOF
sudo chmod 644 "$CR/exim.conf"
sudo cp /usr/sbin/exim4 "$CR/exim4-nosuid"
sudo chown root:root "$CR/exim4-nosuid"
sudo chmod 755 "$CR/exim4-nosuid"
sudo pkill -f '/tmp/eximtest-root/exim4-nosuid' 2>/dev/null || true
sudo pkill -9 -x exim4 2>/dev/null || true
sudo pkill -9 valgrind 2>/dev/null || true
sleep 0.3
sudo rm -f "$D"/vg-*.log "$D"/daemon-vg.log
sudo bash -c 'nohup valgrind --trace-children=yes --log-file=/tmp/eximtest/vg-%p.log /tmp/eximtest-root/exim4-nosuid -bd -C /tmp/eximtest-root/exim.conf -d > /tmp/eximtest/daemon-vg.log 2>&1 &'
sleep 4
if ! ss -ltn 2>/dev/null | grep -q 2525; then
  echo VALGRIND_START_FAILED | sudo tee -a "$D/daemon-vg.log"
  sudo pkill -9 valgrind 2>/dev/null || true
  sudo pkill -f '/tmp/eximtest-root/exim4-nosuid' 2>/dev/null || true
  sudo bash -c 'nohup /tmp/eximtest-root/exim4-nosuid -bd -C /tmp/eximtest-root/exim.conf -d >> /tmp/eximtest/daemon-vg.log 2>&1 &'
  sleep 2
  ss -ltn 2>/dev/null | grep -q 2525 || { tail -30 "$D/daemon-vg.log"; exit 1; }
  echo NATIVE_FALLBACK
fi
echo EXIM_UP
