#!/bin/sh
cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
update-ca-certificates
nginx -g "daemon off;"