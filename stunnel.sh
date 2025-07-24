#!/bin/sh
cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
update-ca-certificates
cat /etc/ssl/fpm.pem /etc/ssl/root_ca.pem >> /etc/ssl/fpm_chain.pem
stunnel /etc/stunnel/stunnel.conf