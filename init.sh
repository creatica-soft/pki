#!/bin/sh
cp /etc/ssl/private/signing_ca.k /etc/ssl/private/signing_ca.key
chown alpine:nobody /etc/ssl/private/signing_ca.key
chmod 400 /etc/ssl/private/signing_ca.key
cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
update-ca-certificates
echo "Creating a subdirectory pki on /var/www/pki..."
mkdir -p /var/www/pki/pki
ls -l /var/www/pki/pki
echo "Creating a subdirectory pki on /var/www/pki...done"
echo "Copying selected content of /tmp to /var/www/pki..."
cd /tmp
cp -r acme certificates certbot cmp cmp_client crls est est_client lib mswstep msxcep ocsp domains.txt *.html *.php *.ico *.sql /var/www/pki/
chown -R alpine:nobody /var/www/pki
ls -l /var/www/pki
echo "Copying content of /tmp to /var/www/pki...done"
echo "Making /var/www/pki/certbot/*.sh files executable..."
chmod 755 /var/www/pki/certbot/*.sh
ls -l /var/www/pki/certbot
echo "Making /var/www/pki/certbot/*.sh files executable...done"
echo "Creating directory $DB_DIR/sqlite and initializing sqlite databases..."
mkdir $DB_DIR/sqlite
sqlite3 --init /var/www/pki/init-certs.sql $DB_DIR/sqlite/certs.db
sqlite3 --init /var/www/pki/init-acme.sql $DB_DIR/sqlite/acme.db
chown -R nobody:nobody $DB_DIR/sqlite
chmod 770 $DB_DIR/sqlite
chmod 660 $DB_DIR/sqlite/*.db
ls -l $DB_DIR/sqlite
sqlite3 $DB_DIR/sqlite/certs.db '.schema'
sqlite3 $DB_DIR/sqlite/acme.db '.schema'
echo "Creating directory $DB_DIR/sqlite and initializing sqlite databases...done"
echo "Creating directory $DB_DIR/pg and initializing postgres database..."
mkdir -p $DB_DIR/pg
chown -R postgres:postgres $DB_DIR/pg
chmod 750 $DB_DIR/pg
mkdir /run/postgresql
chown postgres:postgres /run/postgresql
ls -l /run/postgresql
sudo -u postgres initdb -D $DB_DIR/pg
ls -l $DB_DIR/pg
echo "Creating directory $DB_DIR/pg and initializing postgres database...done"
echo "Update postgres database account password..."
sudo -u postgres pg_ctl start -D $DB_DIR/pg
sudo -u postgres psql -c "ALTER USER postgres WITH ENCRYPTED PASSWORD '$PG_PASSWORD';"
echo "Update postgres database account password...done"
echo "Creating PKI schema in postgress..."
psql -f /var/www/pki/createdb.sql postgres postgres
sudo -u postgres psql -c "\d certs"
sudo -u postgres psql -c "\d cert_req_ids"
sudo -u postgres psql -c "\d keys"
sudo -u postgres psql -c "\d nonces"
sudo -u postgres psql -c "\d accounts"
sudo -u postgres psql -c "\d orders"
sudo -u postgres psql -c "\d authorizations"
sudo -u postgres psql -c "\d challenges"
echo "Creating PKI schema in postgres...done"
echo "Encrypting postgres and LDAP account passwords and storing them in /var/www/pki/lib/config.php..."
cd /var/www/pki
export PG_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $PG_PASSWORD)
export LDAP_ENC_PASSWORD=$(php$PHP_VER encrypt_pass.php $LDAP_PASSWORD)
envsubst '$LDAP_ENC_PASSWORD $PG_ENC_PASSWORD' < lib/config.php | tee lib/config.php
echo "Encrypting postgres and LDAP account passwords and storing them in /var/www/pki/lib/config.php...done"
echo "Storing pki php-fpm and postgres SSL certificates in the database..."
PG_CON=$(grep '$pg_con' lib/config.php)
echo PG_CON=$PG_CON
sed -i 's/$pg_con .*/$pg_con = "host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres_password"/' lib/config.php
cat lib/config.php
php$PHP_VER save_cert.php /etc/ssl/pki.der
php$PHP_VER save_cert.php /etc/ssl/fpm.der
php$PHP_VER save_cert.php /etc/ssl/postgres.der
sed -i '/$pg_con .*/D' lib/config.php
echo $PG_CON >> lib/config.php
cat lib/config.php
sudo -u postgres pg_ctl stop -D $DB_DIR/pg
echo "Storing pki php-fpm and postgres SSL certificates in the database...done"
echo "Configuring postgres to listen on 0.0.0.0 and use SSL..."
echo "listen_addresses = '0.0.0.0'" >> /var/pki/pg/postgresql.conf
echo "ssl = on" >> /var/pki/pg/postgresql.conf
echo "ssl_cert_file = '/var/pki/pg/postgres.pem'" >> /var/pki/pg/postgresql.conf
echo "ssl_key_file = '/var/pki/pg/postgres.key'" >> /var/pki/pg/postgresql.conf
echo "ssl_ca_file = '/var/pki/pg/signing_ca.pem'" >> /var/pki/pg/postgresql.conf
cat /var/pki/pg/postgresql.conf
echo "hostssl all all 0.0.0.0/0 password" >> /var/pki/pg/pg_hba.conf
cat /var/pki/pg/pg_hba.conf
echo "Configuring postgres to listen on 0.0.0.0 and use SSL...done"
echo "Copying signing and root CA certificates and root CA CRL into /var/www/pki/pki..."
cp /etc/ssl/signing_ca.der /var/www/pki/pki/signing_ca.crt
cp /etc/ssl/root_ca.der /var/www/pki/pki/root_ca.crt
cp /etc/ssl/root_ca.crl /var/www/pki/pki/
echo "Copying signing and root CA certificates and root CA CRL into /var/www/pki/pki...done"
while true; do
  sleep 3600
done
