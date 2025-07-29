#!/bin/sh
source vm.env
export PHP_VER SIGNING_CA_CN PKI_DNS RESOLVER FPM_DNS PG_DNS SSL_MODE SSL_ROOT_CERT SMTP_DNS TEST_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB_DIR DB
doas apk update
doas apk upgrade
doas apk add tzdata alpine-conf gettext-envsubst uuidgen logrotate coreutils openssl3 ca-certificates php$PHP_VER php$PHP_VER-openssl php$PHP_VER-fpm php$PHP_VER-curl php$PHP_VER-soap php$PHP_VER-xml php$PHP_VER-gmp php$PHP_VER-ldap php$PHP_VER-sqlite3 php$PHP_VER-mbstring nginx nginx-mod-http-headers-more sqlite certbot curl
doas setup-timezone $TZ
envsubst '$SMTP_DNS $PKI_DNS $PHP_VER' < etc/php$PHP_VER/php.ini | doas tee /etc/php$PHP_VER/php.ini
envsubst '$FPM_DNS' < etc/php$PHP_VER/php-fpm.d/www.conf | doas tee /etc/php$PHP_VER/php-fpm.d/www.conf
envsubst '$PKI_DNS' < etc/ssl/openssl.cnf | doas tee /etc/ssl/openssl.cnf
envsubst '$DB_DIR' < acme/globals.php | tee acme/globals.php
envsubst '$PKI_DNS' < certbot/certbot.conf | tee certbot/certbot.conf
envsubst '$PKI_DNS $TEST_DNS $PHP_VER' < certbot/tests.sh | tee certbot/tests.sh
envsubst '$PKI_DNS $PHP_VER $SIGNING_CA_CN' < cmp_client/openssl.conf | tee cmp_client/openssl.conf
envsubst '$PKI_DNS $TEST_DNS' < cmp_client/tests.php | tee cmp_client/tests.php
envsubst '$PKI_DNS $TEST_DNS' < domains.txt | tee domains.txt
envsubst '$PKI_DNS' < est_client/tests.php | tee est_client/tests.php
envsubst '$PHP_VER' < encrypt_pass.php | tee encrypt_pass.php
envsubst '$PKI_DNS $FPM_DNS $RESOLVER' < etc/nginx/http.d/pki.conf | doas tee /etc/nginx/http.d/pki.conf
doas touch /var/log/php$PHP_VER/error.log
doas chown nobody:nobody /var/log/php$PHP_VER/error.log
doas mkdir -p /var/www/pki/pki
doas cp -r acme certificates certbot cmp cmp_client crls est est_client lib mswstep msxcep ocsp domains.txt *.html *.php *.ico *.sql /var/www/pki/
doas chmod 755 /var/www/pki/certbot/*.sh
doas chown -R alpine /var/www/pki/certbot
doas chown -R alpine /var/www/pki/cmp_client
doas chown -R alpine /var/www/pki/est_client
doas openssl req -x509 -newkey rsa:4096 -subj /CN="$ROOT_CA_CN" -extensions v3_ca_root -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/root_ca.pem -keyout /etc/ssl/private/root_ca.key -noenc
doas openssl x509 -inform PEM -outform DER -in /etc/ssl/root_ca.pem -out /etc/ssl/root_ca.der
doas sed -i s/2048/4096/ /etc/ssl/openssl.cnf
doas openssl req -CA /etc/ssl/root_ca.pem -CAkey /etc/ssl/private/root_ca.key -subj /CN="$SIGNING_CA_CN" -extensions v3_ca_sub -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/signing_ca.pem -keyout /etc/ssl/private/signing_ca.key -noenc
doas cat /etc/ssl/signing_ca.pem /etc/ssl/root_ca.pem | doas tee /etc/ssl/ca_chain.pem
doas openssl x509 -inform PEM -outform DER -in /etc/ssl/signing_ca.pem -out /etc/ssl/signing_ca.der
doas sed -i s/4096/2048/ /etc/ssl/openssl.cnf
#create a temp cert, so nginx could start
doas openssl req -CA /etc/ssl/signing_ca.pem -CAkey /etc/ssl/private/signing_ca.key -subj /CN=$PKI_DNS -extensions usr_cert -addext "subjectAltName=DNS:$PKI_DNS" -config /etc/ssl/openssl.cnf -days 365 -out /etc/ssl/pki.pem -keyout /etc/ssl/private/pki.key -noenc
doas cat /etc/ssl/signing_ca.pem | doas tee -a /etc/ssl/pki.pem
#doas openssl x509 -inform PEM -outform DER -in /etc/ssl/pki.pem -out /etc/ssl/pki.der
#for public PKI domain use Let's Encrypt cert
doas mkdir -p /var/certbot/logs
doas mv /var/www/pki/certbot/auth-pki.sh /var/certbot/
doas mv /var/www/pki/certbot/cleanup-pki.sh /var/certbot/
doas mv /var/www/pki/certbot/pki.conf /var/certbot/
doas mkdir -p /var/www/pki/.well-known/acme-challenge
export CERTBOT_DOMAIN=$PKI_DNS
doas sed -i "s/return 301 https:\/\/$PKI_DNS\/;/#return 301 https:\/\/$PKI_DNS\/;/" /etc/nginx/http.d/pki.conf
doas nginx -s reload
if [ $? != 0 ]; then
  doas nginx
fi
cd /var/certbot
doas certbot -c pki.conf register
doas certbot -c pki.conf certonly --manual -d $CERTBOT_DOMAIN -v
doas rm /etc/ssl/pki.pem /etc/ssl/private/pki.key
doas ln -s /var/certbot/live/pki.creatica.org/fullchain.pem /etc/ssl/pki.pem
doas ln -s /var/certbot/live/pki.creatica.org/privkey.pem /etc/ssl/private/pki.key
doas sed -i "s/#return 301 https:\/\/$PKI_DNS\/;/return 301 https:\/\/$PKI_DNS\/;/" /etc/nginx/http.d/pki.conf
doas nginx -s reload
echo "0 0 1 1,3,5,7,9,11 * cd /var/certbot && doas certbot -c pki.conf renew --cert-name $CERTBOT_DOMAIN -v --force-renewal && doas nginx -s reload" | crontab -
cd ~/pki
doas chown root:nobody /etc/ssl/private/signing_ca.key
doas chmod 440 /etc/ssl/private/signing_ca.key
doas cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
doas update-ca-certificates
doas cp /etc/ssl/root_ca.der /var/www/pki/pki/root_ca.crt
doas cp /etc/ssl/signing_ca.der /var/www/pki/pki/signing_ca.crt
doas sed -i s/signing_ca.pem/root_ca.pem/g /etc/ssl/openssl.cnf
doas sed -i s/signing_ca.key/root_ca.key/g /etc/ssl/openssl.cnf
doas touch /etc/ssl/index.txt
echo 123456789ABCDEF0123456789ABCDEF0123456789ABCDE | doas tee /etc/ssl/crlnumber
doas openssl ca -gencrl -out /var/www/pki/pki/root_ca.crl -config /etc/ssl/openssl.cnf -crldays 3650
doas openssl crl -inform PEM -in /var/www/pki/pki/root_ca.crl -outform DER -out /var/www/pki/pki/root_ca.crl
doas sed -i s/root_ca.pem/signing_ca.pem/g /etc/ssl/openssl.cnf
doas sed -i s/root_ca.key/signing_ca.key/g /etc/ssl/openssl.cnf
doas mkdir -p $DB_DIR/sqlite
doas sqlite3 $DB_DIR/sqlite/certs.db < /var/www/pki/init-certs.sql
doas sqlite3 $DB_DIR/sqlite/acme.db < /var/www/pki/init-acme.sql
doas chown -R nobody:nobody $DB_DIR/sqlite
doas chmod 770 $DB_DIR/sqlite
doas chmod 660 $DB_DIR/sqlite/*.db
cd /var/www/pki
export LDAP_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $LDAP_PASSWORD)
export PG_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $PG_PASSWORD)
envsubst '$PKI_DNS $LDAP_AUTH $LDAP_DNS $LDAP_DNS2 $LDAP_BINDING_DN $OU_USERS $OU_SERVICE_ACCOUNTS $DB $DB_DIR $PG_DNS $SSL_MODE $SSL_ROOT_CERT $LDAP_ENC_PASSWORD $PG_ENC_PASSWORD' < lib/config.php | doas tee lib/config.php
#doas php$PHP_VER save_cert.php /etc/ssl/pki.der
doas rc-update add php-fpm$PHP_VER
doas rc-update add nginx
doas adduser alpine nobody
doas adduser nobody mail
doas service php-fpm$PHP_VER start
#doas service nginx start
