#!/bin/sh
STANDBY_SERVER_IP="192.168.1.1"
for i in 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1; do
  if [ -f /home/alpine/pki.tar.gz.$i ]; then
    j=$((i+1))
    mv /home/alpine/pki.tar.gz.$i /home/alpine/pki.tar.gz.$j
    ssh ${STANDBY_SERVER_IP} mv /home/alpine/pki.tar.gz.$i /home/alpine/pki.tar.gz.$j
  fi
done
mv /home/alpine/pki.tar.gz /home/alpine/pki.tar.gz.1
ssh ${STANDBY_SERVER_IP} mv /home/alpine/pki.tar.gz /home/alpine/pki.tar.gz.1
sudo sqlite3 /var/pki/certs.db ".backup '/var/pki/certs.db.backup'"
sudo sqlite3 /var/pki/acme.db ".backup '/var/pki/acme.db.backup'"
tar -zcf /home/alpine/pki.tar.gz /var/pki/certs.db.backup /var/pki/acme.db.backup /var/www/pki/domains.txt
scp /home/alpine/pki.tar.gz ${STANDBY_SERVER_IP}:/home/alpine/
ssh ${STANDBY_SERVER_IP} sudo tar -C / -zxf /home/alpine/pki.tar.gz
ssh ${STANDBY_SERVER_IP} 'sudo sqlite3 /var/pki/certs.db ".restore /var/pki/certs.db.backup"'
ssh ${STANDBY_SERVER_IP} 'sudo sqlite3 /var/pki/acme.db ".restore /var/pki/acme.db.backup"'
