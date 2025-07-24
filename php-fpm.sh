#!/bin/sh
cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
update-ca-certificates
cp /etc/ssl/private/signing_ca.k /etc/ssl/private/signing_ca.key
chown nobody:nobody /etc/ssl/private/signing_ca.key
chmod 400 /etc/ssl/private/signing_ca.key
exec php-fpm$PHP_VER -F -O