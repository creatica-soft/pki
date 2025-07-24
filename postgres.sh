#!/bin/sh
cp /etc/ssl/root_ca.pem /usr/local/share/ca-certificates/
update-ca-certificates
cp $DB_DIR/pg/postgres_ssl.key $DB_DIR/pg/postgres.key
chown postgres:postgres $DB_DIR/pg/postgres.key
chmod 400 $DB_DIR/pg/postgres.key
sudo -u postgres postgres$PG_VER -D $DB_DIR/pg