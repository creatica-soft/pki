#!/bin/sh
source vm.env
doas service php-fpm$PHP_VER stop
doas service nginx stop
doas rc-update del php-fpm$PHP_VER
doas rc-update del nginx
doas rm /var/log/php$PHP_VER/error.log
doas rm -rf /var/www/pki
doas rm -rf $DB_DIR
doas rm /etc/ssl/root_ca.pem /etc/ssl/private/root_ca.key /etc/ssl/root_ca.der
doas rm /etc/ssl/signing_ca.pem /etc/ssl/private/signing_ca.key /etc/ssl/signing_ca.der
doas rm /etc/ssl/ca_chain.pem
doas rm /etc/ssl/pki.pem /etc/ssl/private/pki.key /etc/ssl/pki.der
doas rm /usr/local/share/ca-certificates/root_ca.pem
doas update-ca-certificates
doas rm /etc/ssl/index.txt
doas rm /etc/ssl/crlnumber
doas apk del tzdata alpine-conf gettext-envsubst uuidgen logrotate coreutils openssl3 ca-certificates php$PHP_VER php$PHP_VER-openssl php$PHP_VER-fpm php$PHP_VER-curl php$PHP_VER-soap php$PHP_VER-xml php$PHP_VER-gmp php$PHP_VER-ldap php$PHP_VER-sqlite3 php$PHP_VER-mbstring nginx nginx-mod-http-headers-more sqlite certbot curl
unset PHP_VER PG_VER ROOT_CA_CN SIGNING_CA_CN SIGNING_CA_CN PKI_DNS RESOLVER FPM_DNS PG_DNS SSL_MODE SSL_ROOT_CERT SMTP_DNS TEST_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB_DIR DB LDAP_ENC_PASSWORD PG_ENC_PASSWORD
