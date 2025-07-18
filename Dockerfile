# docker build -t alpine-pki --rm --secret id=ldap,env=LDAP_PASSWORD --secret id=pg,env=PG_PASSWORD .
ARG ALPINE_VER="3.22"
ARG ALPINE_ARCH="arm64v8"
FROM $ALPINE_ARCH/alpine:$ALPINE_VER
ARG TZ="Australia/Brisbane"
ARG PHP_VER="84"
ARG PG_VER="17"
ARG PKI_DNS="pki.example.org"
ARG FPM_DNS="127.0.0.1"
ARG PG_DNS="127.0.0.1"
ARG SSL_MODE="disable"
ARG SSL_ROOT_CERT="sslrootcert="
ARG SMTP_DNS="smtp.example.org"
ARG TEST_DNS="test.example.org"
ARG LDAP_DNS="ldap.example.org"
ARG LDAP_DNS2="ldap2.example.org"
ARG LDAP_BINDING_DN="CN=ldap,OU=SERVICE ACCOUNT,DC=example,DC=org"
ARG OU_USERS="OU=USERS,DC=example,DC=org"
ARG OU_SERVICE_ACCOUNTS="OU=SERVICE ACCOUNTS,DC=example,DC=org"
ARG DB_DIR="/var/pki"
ARG DB="postgres" # sqlite or postgres
COPY . /tmp
RUN  --mount=type=secret,id=ldap,env=LDAP_PASSWORD --mount=type=secret,id=pg,env=PG_PASSWORD \
    apk update && \
    apk upgrade && \
    apk add tzdata alpine-conf gettext-envsubst uuidgen logrotate coreutils sudo openssl3 php$PHP_VER php$PHP_VER-openssl php$PHP_VER-fpm php$PHP_VER-curl php$PHP_VER-soap php$PHP_VER-xml php$PHP_VER-gmp php$PHP_VER-ldap php$PHP_VER-sqlite3 php$PHP_VER-mbstring php$PHP_VER-pgsql postgresql$PG_VER nginx nginx-mod-http-headers-more sqlite certbot curl && \
    echo "alpine ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    setup-timezone $TZ && \
    adduser -G nobody -D alpine && \
    sed -i -e '/^alpine/s/!/*/' /etc/shadow && \
    adduser nobody mail && \
    sed -i "s/error_log .*/error_log stderr;/" /etc/nginx/nginx.conf && \
    cd /tmp && \
    envsubst '$SMTP_DNS $PKI_DNS $PHP_VER' < etc/php$PHP_VER/php.ini | tee /etc/php$PHP_VER/php.ini && \
    envsubst '$FPM_DNS' < etc/php$PHP_VER/php-fpm.d/www.conf | tee /etc/php$PHP_VER/php-fpm.d/www.conf && \
    envsubst '$PKI_DNS' < etc/ssl/openssl.cnf | tee /etc/ssl/openssl.cnf && \
    envsubst '$DB_DIR' < acme/globals.php | tee acme/globals.php && \
    envsubst '$PKI_DNS' < certbot/certbot.conf | tee certbot/certbot.conf && \
    envsubst '$PKI_DNS $TEST_DNS $PHP_VER' < certbot/tests.sh | tee certbot/tests.sh && \
    envsubst '$PKI_DNS $PHP_VER' < cmp_client/openssl.conf | tee cmp_client/openssl.conf && \
    envsubst '$PKI_DNS $TEST_DNS' < cmp_client/tests.php | tee cmp_client/tests.php && \
    envsubst '$PKI_DNS $TEST_DNS' < domains.txt | tee domains.txt && \
    envsubst '$PKI_DNS' < est_client/tests.php | tee est_client/tests.php && \
    envsubst '$PHP_VER $PKI_DNS' < encrypt_pass.php | tee encrypt_pass.php && \
    envsubst '$PKI_DNS $FPM_DNS' < etc/nginx/http.d/pki.example.com.conf | tee /etc/nginx/http.d/$PKI_DNS.conf && \
    envsubst '$PHP_VER $DB_DIR $DB' < go.sh |tee /usr/bin/go.sh && \
    chmod 755 /usr/bin/go.sh && \
    touch /var/log/php$PHP_VER/error.log && \
    chown nobody:nobody /var/log/php$PHP_VER/error.log && \
    mkdir -p /var/www/$PKI_DNS/pki && \
    cp -r acme certificates certbot cmp cmp_client crls est est_client lib mswstep msxcep ocsp domains.txt *.html *.php *.ico *.sql /var/www/$PKI_DNS/ && \
    rm -rf /tmp/* && \
    openssl req -x509 -newkey rsa:4096 -subj /CN=InternalRootCA -extensions v3_ca_root -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/root_ca.pem -keyout /etc/ssl/private/root_ca.key -noenc && \
    openssl x509 -inform PEM -outform DER -in /etc/ssl/root_ca.pem -out /etc/ssl/root_ca.der && \
    sed -i s/2048/4096/ /etc/ssl/openssl.cnf && \
    openssl req -CA /etc/ssl/root_ca.pem -CAkey /etc/ssl/private/root_ca.key -subj /CN=InternalSigningCA -extensions v3_ca_sub -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/signing_ca.pem -keyout /etc/ssl/private/signing_ca.key -noenc && \
    cat /etc/ssl/signing_ca.pem /etc/ssl/root_ca.pem | tee /etc/ssl/ca_chain.pem && \
    openssl x509 -inform PEM -outform DER -in /etc/ssl/signing_ca.pem -out /etc/ssl/signing_ca.der && \
    sed -i s/4096/2048/ /etc/ssl/openssl.cnf && \
    openssl req -CA /etc/ssl/signing_ca.pem -CAkey /etc/ssl/private/signing_ca.key -subj /CN=$PKI_DNS -extensions usr_cert -addext "subjectAltName=DNS:$PKI_DNS" -config /etc/ssl/openssl.cnf -days 365 -out /etc/ssl/$PKI_DNS.pem -keyout /etc/ssl/private/$PKI_DNS.key -noenc && \
    cat /etc/ssl/signing_ca.pem | tee -a /etc/ssl/$PKI_DNS.pem && \
    openssl x509 -inform PEM -outform DER -in /etc/ssl/$PKI_DNS.pem -out /etc/ssl/$PKI_DNS.der && \
    chown root:nobody /etc/ssl/private/signing_ca.key && \
    chmod 440 /etc/ssl/private/signing_ca.key && \
    cat /etc/ssl/root_ca.pem | tee -a /etc/ssl/certs/ca-certificates.crt && \
    cp /etc/ssl/root_ca.der /var/www/$PKI_DNS/pki/root_ca.crt && \
    cp /etc/ssl/signing_ca.der /var/www/$PKI_DNS/pki/signing_ca.crt && \
    sed -i s/signing_ca.pem/root_ca.pem/g /etc/ssl/openssl.cnf && \
    sed -i s/signing_ca.key/root_ca.key/g /etc/ssl/openssl.cnf && \
    touch /etc/ssl/index.txt && \
    echo 123456789ABCDEF0123456789ABCDEF0123456789ABCDF |tee /etc/ssl/crlnumber && \
    openssl ca -gencrl -out /var/www/$PKI_DNS/pki/root_ca.crl -config /etc/ssl/openssl.cnf -crldays 3650 && \
    openssl crl -inform PEM -in /var/www/$PKI_DNS/pki/root_ca.crl -outform DER -out /var/www/$PKI_DNS/pki/root_ca.crl && \
    sed -i s/root_ca.pem/signing_ca.pem/g /etc/ssl/openssl.cnf && \
    sed -i s/root_ca.key/signing_ca.key/g /etc/ssl/openssl.cnf && \
    chown -R alpine:nobody /var/www/$PKI_DNS && \
    chmod 755 /var/www/$PKI_DNS/certbot/*.sh && \
    mkdir -p $DB_DIR/pg && \
    mkdir $DB_DIR/sqlite && \
    sqlite3 --init /var/www/$PKI_DNS/init-certs.sql $DB_DIR/sqlite/certs.db && \
    sqlite3 --init /var/www/$PKI_DNS/init-acme.sql $DB_DIR/sqlite/acme.db && \
    chown -R nobody:nobody $DB_DIR/sqlite && \
    chmod 775 $DB_DIR/sqlite && \
    chmod 664 $DB_DIR/sqlite/*.db && \
    chown postgres:postgres $DB_DIR/pg && \
    chmod 750 $DB_DIR/pg && \
    mkdir /run/postgresql && \
    chown postgres:postgres /run/postgresql && \
    sudo -u postgres initdb -D $DB_DIR/pg && \
    sudo -u postgres pg_ctl start -D $DB_DIR/pg && \
    sudo -u postgres psql -c "ALTER USER postgres WITH ENCRYPTED PASSWORD '$PG_PASSWORD';" && \
    psql -f /var/www/$PKI_DNS/createdb.sql postgres postgres && \
    cd /var/www/$PKI_DNS && \
    echo $LDAP_PASSWORD | tee /tmp/ldap_password && \
    echo $PG_PASSWORD |tee /tmp/pg_password && \
    export LDAP_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $LDAP_PASSWORD) && \
    export PG_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $PG_PASSWORD) && \
    echo $LDAP_ENC_PASSWORD | tee /tmp/enc_ldap && \
    echo $PG_ENC_PASSWORD | tee /tmp/enc_pg && \
    envsubst '$PKI_DNS $LDAP_DNS $LDAP_DNS2 $LDAP_BINDING_DN $OU_USERS $OU_SERVICE_ACCOUNTS $DB $DB_DIR $PG_DNS $SSL_MODE $SSL_ROOT_CERT $LDAP_ENC_PASSWORD $PG_ENC_PASSWORD' < lib/config.php | tee lib/config.php && \
    php$PHP_VER save_cert.php /etc/ssl/$PKI_DNS.der && \
    sudo -u postgres pg_ctl stop -D $DB_DIR/pg
EXPOSE 80/tcp 443/tcp
USER alpine
WORKDIR /home/alpine
ENTRYPOINT ["/usr/bin/go.sh"]

