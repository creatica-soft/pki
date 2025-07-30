#!/bin/sh
echo "Sourcing vm.env file..."
source vm.env
echo "Sourcing vm.env file...done"
echo "Exporting PHP_VER SIGNING_CA_CN PKI_DNS RESOLVER FPM_DNS PG_DNS SSL_MODE SSL_ROOT_CERT SMTP_DNS TEST_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB_DIR DB from vm.env..."
export PHP_VER SIGNING_CA_CN PKI_DNS RESOLVER FPM_DNS PG_DNS SSL_MODE SSL_ROOT_CERT SMTP_DNS TEST_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB_DIR DB
echo "Exporting PHP_VER SIGNING_CA_CN PKI_DNS RESOLVER FPM_DNS PG_DNS SSL_MODE SSL_ROOT_CERT SMTP_DNS TEST_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB_DIR DB from vm.env...done"
echo "Adding community repo into /etc/apk/repositories..."
echo "http://dl-cdn.alpinelinux.org/alpine/v$VER/community" | doas tee -a /etc/apk/repositories
echo "Adding community repo into /etc/apk/repositories...done"
echo "Running apk update..."
doas apk update
echo "Running apk update...done"
echo "Running apk upgrade..."
doas apk upgrade
echo "Running apk upgrade...done"
echo "Installing necessary packages..."
doas apk add tzdata alpine-conf gettext-envsubst uuidgen logrotate coreutils openssl3 ca-certificates php$PHP_VER php$PHP_VER-openssl php$PHP_VER-fpm php$PHP_VER-curl php$PHP_VER-soap php$PHP_VER-xml php$PHP_VER-gmp php$PHP_VER-ldap php$PHP_VER-sqlite3 php$PHP_VER-mbstring nginx nginx-mod-http-headers-more sqlite certbot curl
echo "Installing necessary packages...done"
echo "Setting timezone to $TZ..."
doas setup-timezone $TZ
echo "Setting timezone to $TZ...done"
echo "Substituting SMTP_DNS PKI_DNS PHP_VER variables in /etc/php$PHP_VER/php.ini..."
envsubst '$SMTP_DNS $PKI_DNS $PHP_VER' < etc/php$PHP_VER/php.ini | doas tee /etc/php$PHP_VER/php.ini
echo "Substituting SMTP_DNS PKI_DNS PHP_VER variables in /etc/php$PHP_VER/php.ini...done"
echo "Substituting FPM_DNS variable in /etc/php$PHP_VER/php-fpm.d/www.conf..."
envsubst '$FPM_DNS' < etc/php$PHP_VER/php-fpm.d/www.conf | doas tee /etc/php$PHP_VER/php-fpm.d/www.conf
echo "Substituting FPM_DNS variable in /etc/php$PHP_VER/php-fpm.d/www.conf...done"
echo "Substituting PKI_DNS variable in /etc/ssl/openssl.cnf..."
envsubst '$PKI_DNS' < etc/ssl/openssl.cnf | doas tee /etc/ssl/openssl.cnf
echo "Substituting PKI_DNS variable in /etc/ssl/openssl.cnf...done"
echo "Substituting DB_DIR variable in acme/globals.php..."
envsubst '$DB_DIR' < acme/globals.php | tee acme/globals.php
echo "Substituting DB_DIR variable in acme/globals.php...done"
echo "Substituting PKI_DNS variable in certbot/certbot.conf..."
envsubst '$PKI_DNS' < certbot/certbot.conf | tee certbot/certbot.conf
echo "Substituting PKI_DNS variable in certbot/certbot.conf...done"
echo "Substituting PKI_DNS TEST_DNS PHP_VER variables in certbot/tests.sh..."
envsubst '$PKI_DNS $TEST_DNS $PHP_VER' < certbot/tests.sh | tee certbot/tests.sh
echo "Substituting PKI_DNS TEST_DNS PHP_VER variables in certbot/tests.sh...done"
echo "Substituting PKI_DNS PHP_VER SIGNING_CA_CN variables in cmp_client/openssl.conf..."
envsubst '$PKI_DNS $PHP_VER $SIGNING_CA_CN' < cmp_client/openssl.conf | tee cmp_client/openssl.conf
echo "Substituting PKI_DNS PHP_VER SIGNING_CA_CN variables in cmp_client/openssl.conf...done"
echo "Substituting PKI_DNS TEST_DNS variables in cmp_client/tests.php..."
envsubst '$PKI_DNS $TEST_DNS' < cmp_client/tests.php | tee cmp_client/tests.php
echo "Substituting PKI_DNS TEST_DNS variables in cmp_client/tests.php...done"
echo "Substituting PKI_DNS TEST_DNS variables in domains.txt..."
envsubst '$PKI_DNS $TEST_DNS' < domains.txt | tee domains.txt
echo "Substituting PKI_DNS TEST_DNS variables in domains.txt...done"
echo "Substituting PKI_DNS variable in est_client/tests.php..."
envsubst '$PKI_DNS' < est_client/tests.php | tee est_client/tests.php
echo "Substituting PKI_DNS variable in est_client/tests.php...done"
echo "Substituting PHP_VER variable in encrypt_pass.php..."
envsubst '$PHP_VER' < encrypt_pass.php | tee encrypt_pass.php
echo "Substituting PHP_VER variable in encrypt_pass.php...done"
echo "Substituting PKI_DNS FPM_DNS RESOLVER variables in /etc/nginx/http.d/pki.conf..."
envsubst '$PKI_DNS $FPM_DNS $RESOLVER' < etc/nginx/http.d/pki.conf | doas tee /etc/nginx/http.d/pki.conf
echo "Substituting PKI_DNS FPM_DNS RESOLVER variables in /etc/nginx/http.d/pki.conf...done"
echo "Creating /var/log/php$PHP_VER/error.log..."
doas touch /var/log/php$PHP_VER/error.log
echo "Creating /var/log/php$PHP_VER/error.log...done"
echo "Changing owner of /var/log/php$PHP_VER/error.log to user and group nobody..."
doas chown nobody:nobody /var/log/php$PHP_VER/error.log
echo "Changing ownership of /var/log/php$PHP_VER/error.log to user and group nobody...done"
echo "Creating /var/www/pki/pki..."
doas mkdir -p /var/www/pki/pki
echo "Creating /var/www/pki/pki...done"
echo "Copying files and folders from pki to /var/www/pki..."
doas cp -r acme certificates certbot cmp cmp_client crls est est_client lib mswstep msxcep ocsp domains.txt *.html *.php *.ico *.sql /var/www/pki/
echo "Copying files and folders from pki to /var/www/pki...done"
echo "Changing permissions for /var/www/pki/certbot/*.sh to 755..."
doas chmod 755 /var/www/pki/certbot/*.sh
echo "Changing permissions for /var/www/pki/certbot/*.sh to 755...done"
echo "Changing owner of client folders (certbot, cmp_client, est_client) to alpine..."
doas chown -R alpine /var/www/pki/certbot
doas chown -R alpine /var/www/pki/cmp_client
doas chown -R alpine /var/www/pki/est_client
echo "Changing owner of client folders (certbot, cmp_client, est_client) to alpine...done"
echo "Creating root CA certificate /etc/ssl/root_ca.pem..."
doas openssl req -x509 -newkey rsa:4096 -subj /CN="$ROOT_CA_CN" -extensions v3_ca_root -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/root_ca.pem -keyout /etc/ssl/private/root_ca.key -noenc
echo "Creating root CA certificate /etc/ssl/root_ca.pem...done"
echo "Saving root CA certificate /etc/ssl/root_ca.pem in DER format /etc/ssl/root_ca.der..."
doas openssl x509 -inform PEM -outform DER -in /etc/ssl/root_ca.pem -out /etc/ssl/root_ca.der
echo "Saving root CA certificate /etc/ssl/root_ca.pem in DER format /etc/ssl/root_ca.der...done"
echo "Temporarily changing key size from 2048 to 4096..."
doas sed -i s/2048/4096/ /etc/ssl/openssl.cnf
echo "Temporarily changing key size from 2048 to 4096...done"
echo "Creating signing CA certificate /etc/ssl/signing_ca.pem..."
doas openssl req -CA /etc/ssl/root_ca.pem -CAkey /etc/ssl/private/root_ca.key -subj /CN="$SIGNING_CA_CN" -extensions v3_ca_sub -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/signing_ca.pem -keyout /etc/ssl/private/signing_ca.key -noenc
echo "Creating signing CA certificate /etc/ssl/signing_ca.pem...done"
echo "Combining signing CA and root CA certificates into a chain /etc/ssl/ca_chain.pem..."
doas cat /etc/ssl/signing_ca.pem /etc/ssl/root_ca.pem | doas tee /etc/ssl/ca_chain.pem
echo "Combining signing CA and root CA certificates into a chain /etc/ssl/ca_chain.pem...done"
echo "Saving signing CA certificate /etc/ssl/signing_ca.pem in DER format /etc/ssl/signing_ca.der..."
doas openssl x509 -inform PEM -outform DER -in /etc/ssl/signing_ca.pem -out /etc/ssl/signing_ca.der
echo "Saving signing CA certificate /etc/ssl/signing_ca.pem in DER format /etc/ssl/signing_ca.der...done"
echo "Restoring key size to 2048..."
doas sed -i s/4096/2048/ /etc/ssl/openssl.cnf
echo "Restoring key size to 2048...done"
echo "Create nginx certificate /etc/ssl/pki.pem..."
doas openssl req -CA /etc/ssl/signing_ca.pem -CAkey /etc/ssl/private/signing_ca.key -subj /CN=$PKI_DNS -extensions usr_cert -addext "subjectAltName=DNS:$PKI_DNS" -config /etc/ssl/openssl.cnf -days 365 -out /etc/ssl/pki.pem -keyout /etc/ssl/private/pki.key -noenc
echo "Create nginx certificate /etc/ssl/pki.pem...done"
echo "Adding signing CA certificate /etc/ssl/signing_ca.pem to nginx certificate /etc/ssl/pki.pem to make a chain..."
doas cat /etc/ssl/signing_ca.pem | doas tee -a /etc/ssl/pki.pem
echo "Adding signing CA certificate /etc/ssl/signing_ca.pem to nginx certificate /etc/ssl/pki.pem to make a chain...done"
echo "Saving nginx certificate /etc/ssl/pki.pem in DER format /etc/ssl/pki.der..."
doas openssl x509 -inform PEM -outform DER -in /etc/ssl/pki.pem -out /etc/ssl/pki.der
echo "Saving nginx certificate /etc/ssl/pki.pem in DER format /etc/ssl/pki.der...done"
if [ "$LETS_ENCRYPT_CERT_REQUIRED" == "true" ]; then
    echo "Creating /var/certbot/logs foler..."
    doas mkdir -p /var/certbot/logs
    echo "Creating /var/certbot/logs foler...done"
    echo "Moving auth-pki.sh, cleanup-pki.sh and  pki.conf from /var/www/pki/certbot to /var/certbot..."
    doas mv /var/www/pki/certbot/auth-pki.sh /var/certbot/
    doas mv /var/www/pki/certbot/cleanup-pki.sh /var/certbot/
    doas mv /var/www/pki/certbot/pki.conf /var/certbot/
    echo "Moving auth-pki.sh, cleanup-pki.sh and  pki.conf from /var/www/pki/certbot to /var/certbot...done"
    echo "Creating a folder for ACME challenge /var/www/pki/.well-known/acme-challenge..."
    doas mkdir -p /var/www/pki/.well-known/acme-challenge
    echo "Creating a folder for ACME challenge /var/www/pki/.well-known/acme-challenge...done"
    echo "Exporting CERTBOT_DOMAIN vairable with a value of $PKI_DNS..."
    export CERTBOT_DOMAIN=$PKI_DNS
    echo "Exporting CERTBOT_DOMAIN vairable with a value of $PKI_DNS...done"
    echo "Temporarily commenting out a line return 301 https://$PKI_DNS/; in /etc/nginx/http.d/pki.conf..."
    doas sed -i "s/return 301 https:\/\/$PKI_DNS\/;/#return 301 https:\/\/$PKI_DNS\/;/" /etc/nginx/http.d/pki.conf
    echo "Temporarily commenting out a line return 301 https://$PKI_DNS/; in /etc/nginx/http.d/pki.conf...done"
    echo "Attempting to restart nginx if it's running..."
    doas nginx -s reload
    echo "Attempting to restart nginx if it's running...done"
    if [ $? != 0 ]; then
      echo "Attempting to start nginx if it's not running..."
      doas nginx
      echo "Attempting to start nginx if it's not running...done"
    fi
    echo "Changing directory to /var/certbot..."
    cd /var/certbot
    echo "Changing directory to /var/certbot...done"
    echo "Registering ACME account..."
    doas certbot -c pki.conf register
    echo "Registering ACME account...done"
    echo "Requesing Let's Encrypt certificate for $CERTBOT_DOMAIN..."
    doas certbot -c pki.conf certonly --manual -d $CERTBOT_DOMAIN -v
    echo "Requesing Let's Encrypt certificate for $CERTBOT_DOMAIN...done"
    echo "Deleting old nginx certificate..."
    doas rm /etc/ssl/pki.pem /etc/ssl/private/pki.key
    echo "Deleting old nginx certificate...done"
    echo "Linking new nginx certificate /var/certbot/live/pki.creatica.org/fullchain.pem to /etc/ssl/pki.pem..."
    doas ln -s /var/certbot/live/pki.creatica.org/fullchain.pem /etc/ssl/pki.pem
    echo "Linking new nginx certificate /var/certbot/live/pki.creatica.org/fullchain.pem to /etc/ssl/pki.pem...done"
    echo "Linking new nginx private key /var/certbot/live/pki.creatica.org/privkey.pem to /etc/ssl/private/pki.key..."
    doas ln -s /var/certbot/live/pki.creatica.org/privkey.pem /etc/ssl/private/pki.key
    echo "Linking new nginx private key /var/certbot/live/pki.creatica.org/privkey.pem to /etc/ssl/private/pki.key...done"
    echo "Removing the comment from line return 301 https://$PKI_DNS/; in /etc/nginx/http.d/pki.conf..."
    doas sed -i "s/#return 301 https:\/\/$PKI_DNS\/;/return 301 https:\/\/$PKI_DNS\/;/" /etc/nginx/http.d/pki.conf
    echo "Removing the comment from line return 301 https://$PKI_DNS/; in /etc/nginx/http.d/pki.conf...done"
    echo "Reloading nginx..."
    doas nginx -s reload
    echo "Reloading nginx...done"
    echo "Adding a script to renew nginx certificate every two months to crontab..."
    echo "0 0 1 1,3,5,7,9,11 * cd /var/certbot && doas certbot -c pki.conf renew --cert-name $CERTBOT_DOMAIN -v --force-renewal && doas nginx -s reload" | crontab -
    echo "Adding a script to renew nginx certificate every two months to crontab...done"
fi
echo "Changing working directory to /home/alpine/pki..."
cd ~/pki
echo "Changing working directory to /home/alpine/pki...done"
echo "Changing group of /etc/ssl/private/signing_ca.key to PHP-FPM user nobody..."
doas chown root:nobody /etc/ssl/private/signing_ca.key
echo "Changing group of /etc/ssl/private/signing_ca.key to PHP-FPM user nobody...done"
echo "Changing permission of /etc/ssl/private/signing_ca.key to 440..."
doas chmod 440 /etc/ssl/private/signing_ca.key
echo "Changing permission of /etc/ssl/private/signing_ca.key to 440...done"
echo "Updating trusted root CA certificates..."
doas cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
doas update-ca-certificates
echo "Updating trusted root CA certificates...done"
echo "Copying root CA and signing CA DER certificates to /var/www/pki/pki..."
doas cp /etc/ssl/root_ca.der /var/www/pki/pki/root_ca.crt
doas cp /etc/ssl/signing_ca.der /var/www/pki/pki/signing_ca.crt
echo "Copying root CA and signing CA DER certificates to /var/www/pki/pki...done"
echo "To generate CRL for root CA, temporarily changing signing CA to root CA in /etc/ssl/openssl.cnf..."
doas sed -i s/signing_ca.pem/root_ca.pem/g /etc/ssl/openssl.cnf
doas sed -i s/signing_ca.key/root_ca.key/g /etc/ssl/openssl.cnf
echo "To generate CRL for root CA, temporarily changing signing CA to root CA in /etc/ssl/openssl.cnf...done"
echo "To generate CRL for root CA, creating /etc/ssl/index.txt and /etc/ssl/crlnumber..."
doas touch /etc/ssl/index.txt
echo 123456789ABCDEF0123456789ABCDEF0123456789ABCDE | doas tee /etc/ssl/crlnumber
echo "To generate CRL for root CA, creating /etc/ssl/index.txt and /etc/ssl/crlnumber...done"
echo "Generating root CA CRL /var/www/pki/pki/root_ca.crl..."
doas openssl ca -gencrl -out /var/www/pki/pki/root_ca.crl -config /etc/ssl/openssl.cnf -crldays 3650
echo "Generating root CA CRL /var/www/pki/pki/root_ca.crl...done"
echo "Saving root CA CRL in DER format..."
doas openssl crl -inform PEM -in /var/www/pki/pki/root_ca.crl -outform DER -out /var/www/pki/pki/root_ca.crl
echo "Saving root CA CRL in DER format...done"
echo "Restoring signing CA in /etc/ssl/openssl.cnf..."
doas sed -i s/root_ca.pem/signing_ca.pem/g /etc/ssl/openssl.cnf
doas sed -i s/root_ca.key/signing_ca.key/g /etc/ssl/openssl.cnf
echo "Restoring signing CA in /etc/ssl/openssl.cnf...done"
echo "Creating a folder $DB_DIR/sqlite for SQLITE databases..."
doas mkdir -p $DB_DIR/sqlite
echo "Creating a folder $DB_DIR/sqlite for SQLITE databases...done"
echo "Creating $DB_DIR/sqlite/certs.db database..."
doas sqlite3 $DB_DIR/sqlite/certs.db < /var/www/pki/init-certs.sql
echo "Creating $DB_DIR/sqlite/certs.db database...done"
echo "Creating $DB_DIR/sqlite/acme.db database..."
doas sqlite3 $DB_DIR/sqlite/acme.db < /var/www/pki/init-acme.sql
echo "Creating $DB_DIR/sqlite/acme.db database...done"
echo "Changing owner and group of $DB_DIR/sqlite to nobody..."
doas chown -R nobody:nobody $DB_DIR/sqlite
echo "Changing owner and group of $DB_DIR/sqlite to nobody...done"
echo "Changing permissions of $DB_DIR/sqlite to 770..."
doas chmod 770 $DB_DIR/sqlite
echo "Changing permissions of $DB_DIR/sqlite to 770...done"
echo "Changing permissions of $DB_DIR/sqlite/certs.db and $DB_DIR/sqlite/acme.db to 660..."
doas chmod 660 $DB_DIR/sqlite/certs.db
doas chmod 660 $DB_DIR/sqlite/acme.db
echo "Changing permissions of $DB_DIR/sqlite/*.db to 660...done"
echo "Changing work directory to /var/www/pki..."
cd /var/www/pki
echo "Changing work directory to /var/www/pki...done"
echo "Encrypting LDAP and POSTGRES passwords..."
export LDAP_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $LDAP_PASSWORD)
export PG_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $PG_PASSWORD)
echo "Encrypting LDAP and POSTGRES passwords...done"
echo "Substituting PKI_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB DB_DIR PG_DNS SSL_MODE SSL_ROOT_CERT LDAP_ENC_PASSWORD PG_ENC_PASSWORD variables in lib/config.php..."
envsubst '$PKI_DNS $LDAP_AUTH $LDAP_DNS $LDAP_DNS2 $LDAP_BINDING_DN $OU_USERS $OU_SERVICE_ACCOUNTS $DB $DB_DIR $PG_DNS $SSL_MODE $SSL_ROOT_CERT $LDAP_ENC_PASSWORD $PG_ENC_PASSWORD' < lib/config.php | doas tee lib/config.php
echo "Substituting PKI_DNS LDAP_AUTH LDAP_DNS LDAP_DNS2 LDAP_BINDING_DN OU_USERS OU_SERVICE_ACCOUNTS DB DB_DIR PG_DNS SSL_MODE SSL_ROOT_CERT LDAP_ENC_PASSWORD PG_ENC_PASSWORD variables in lib/config.php...done"
echo "Saving nginx private certificate in sqlite database..."
doas php$PHP_VER save_cert.php /etc/ssl/pki.der
echo "Saving nginx private certificate in sqlite database...done"
echo "Adding php-fpm$PHP_VER and nginx to startup..."
doas rc-update add php-fpm$PHP_VER
doas rc-update add nginx
echo "Adding php-fpm$PHP_VER and nginx to startup...done"
echo "Addingg user alpine to group nobody..."
doas adduser alpine nobody
echo "Addingg user alpine to group nobody...done"
echo "Adding user nobody to group mail..."
doas adduser nobody mail
echo "Adding user nobody to group mail...done"
echo "Starting php-fpm$PHP_VER..."
doas service php-fpm$PHP_VER start
echo "Starting php-fpm$PHP_VER...done"
#doas service nginx start
