FROM arm64v8/alpine:3.22
ARG TZ="Australia/Brisbane"
RUN cat /etc/alpine-release
COPY etc/apk/repositories /etc/apk/
RUN apk update && apk upgrade && apk add tzdata alpine-conf php83 php83-openssl php83-fpm php83-curl php83-soap php83-xml uuidgen nginx git logrotate php83-gmp coreutils nginx-mod-http-headers-more php83-ldap php83-sqlite3 php83-mbstring sqlite openssl3 sudo
COPY etc/sudoers /etc/
RUN setup-timezone $TZ && \
    addgroup alpine && \
    adduser -G alpine -D alpine && \
    sed -i -e '/^alpine/s/!/*/' /etc/shadow && \
    adduser nobody mail
USER alpine
WORKDIR /home/alpine
RUN git clone https://github.com/creatica-soft/pki && \
    cd pki && \
    sudo cp -r etc/* /etc/ && \
    sudo openssl req -x509 -newkey rsa:4096 -subj /CN=InternalRootCA -extensions v3_ca_root -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/root_ca.pem -keyout /etc/ssl/private/root_ca.key -noenc && \
    sudo openssl x509 -inform PEM -outform DER -in /etc/ssl/root_ca.pem -out /etc/ssl/root_ca.der && \
    sudo sed -i s/2048/4096/ /etc/ssl/openssl.cnf && \
    sudo openssl req -CA /etc/ssl/root_ca.pem -CAkey /etc/ssl/private/root_ca.key -subj /CN=InternalSigningCA -extensions v3_ca_sub -config /etc/ssl/openssl.cnf -days 3650 -out /etc/ssl/signing_ca.pem -keyout /etc/ssl/private/signing_ca.key -noenc && \
    sudo openssl x509 -inform PEM -outform DER -in /etc/ssl/signing_ca.pem -out /etc/ssl/signing_ca.der && \
    sudo sed -i s/4096/2048/ /etc/ssl/openssl.cnf && \
    sudo openssl req -CA /etc/ssl/signing_ca.pem -CAkey /etc/ssl/private/signing_ca.key -subj /CN=pki.example.com -extensions usr_cert -addext "subjectAltName=DNS:pki.example.com" -config /etc/ssl/openssl.cnf -days 365 -out /etc/ssl/pki.example.com.pem -keyout /etc/ssl/private/pki.example.com.key -noenc && \
    sudo cat /etc/ssl/signing_ca.pem | sudo tee -a /etc/ssl/pki.example.com.pem && \
    sudo openssl x509 -inform PEM -outform DER -in /etc/ssl/pki.example.com.pem -out /etc/ssl/pki.example.com.der && \
    sudo chown root:nobody /etc/ssl/private/signing_ca.key && \
    sudo chmod 440 /etc/ssl/private/signing_ca.key && \
    sudo cat /etc/ssl/root_ca.pem | sudo tee -a /etc/ssl/certs/ca-certificates.crt && \
    sudo mkdir /var/www/pki.example.com && \
    sudo mkdir /var/www/pki.example.com/pki && \
    sudo cp /etc/ssl/root_ca.der /var/www/pki.example.com/pki/root_ca.crt && \
    sudo cp /etc/ssl/signing_ca.der /var/www/pki.example.com/pki/signing_ca.crt && \
    sudo sed -i s/signing_ca.pem/root_ca.pem/g /etc/ssl/openssl.cnf && \
    sudo sed -i s/signing_ca.key/root_ca.key/g /etc/ssl/openssl.cnf && \
    sudo touch /etc/ssl/index.txt && \
    sudo echo 123456789ABCDEF0123456789ABCDEF0123456789ABCDF |sudo tee /etc/ssl/crlnumber && \
    sudo openssl ca -gencrl -out /var/www/pki.example.com/pki/root_ca.crl -config /etc/ssl/openssl.cnf -crldays 3650 && \
    sudo openssl crl -inform PEM -in /var/www/pki.example.com/pki/root_ca.crl -outform DER -out /var/www/pki.example.com/pki/root_ca.crl && \
    sudo sed -i s/root_ca.pem/signing_ca.pem/g /etc/ssl/openssl.cnf && \
    sudo sed -i s/root_ca.key/signing_ca.key/g /etc/ssl/openssl.cnf && \
    sudo cp -r acme certificates cmp cmp_client crls est est_client lib mswstep msxcep ocsp domains.txt *.html *.php *.ico /var/www/pki.example.com/ && \
    sudo chown -R nobody:alpine /var/www/pki.example.com && \
    sudo cp go.sh /usr/bin && \
    sudo chmod 755 /usr/bin/go.sh && \
    sudo mkdir /var/pki && \
    sudo sqlite3 /var/pki/certs.db \
  'create table certs(serial TEXT PRIMARY KEY ASC, status INTEGER, revocationReason INTEGER, revocationDate INTEGER, notBefore INTEGER, notAfter INTEGER, subject TEXT, owner TEXT, role TEXT, cert BLOB, cn TEXT, fingerprint TEXT, sHash TEXT, iAndSHash TEXT, sKIDHash TEXT);' \
  'CREATE INDEX subj_idx on certs(subject); CREATE INDEX status_idx on certs(status); CREATE INDEX from_idx on certs(notBefore);' \
  'CREATE INDEX to_idx on certs(notAfter); CREATE INDEX owner_idx on certs(owner); CREATE INDEX role_idx on certs(role);' \
  'CREATE INDEX cn_idx on certs(cn); CREATE INDEX fingerprint_idx on certs(fingerprint); CREATE INDEX sHash_idx on certs(sHash);' \
  'CREATE INDEX iAndSHash_idx on certs(iAndSHash); CREATE INDEX sKIDHash_idx on certs(sKIDHash);' && \
    sudo sqlite3 /var/pki/certs.db \
  'create table cert_req_ids(serial TEXT PRIMARY KEY ASC, certReqId TEXT, timestamp INTEGER, nonce TEXT, transactionID TEXT);' \
  'CREATE INDEX certReqId_idx on cert_req_ids(certReqId); CREATE INDEX transactionID_idx on cert_req_ids(transactionID);' && \
    sudo sqlite3 /var/pki/certs.db 'create table keys(kid TEXT PRIMARY KEY ASC, key TEXT);' && \
    sudo sqlite3 /var/pki/acme.db \
  'create table nonces(nonce TEXT PRIMARY KEY ASC, ip TEXT, expires INTEGER);' \
  'create index ip_idx on nonces(ip);' \
  'create index expires_idx on nonces(expires);' && \
    sudo sqlite3 /var/pki/acme.db \
  'create table accounts(id TEXT PRIMARY KEY ASC, status INTEGER, termsOfServiceAgreed INTEGER, jwk_hash TEXT, kid TEXT, jwk BLOB, contacts BLOB, externalAccountBinding BLOB);' \
  'create index jwk_hash_idx on accounts(jwk_hash);' \
  'create index account_status_idx on accounts(status);' \
  'create index account_kid_idx on accounts(kid);' && \
    sudo sqlite3 /var/pki/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table orders(id TEXT PRIMARY KEY ASC, status INTEGER, expires INTEGER, identifiers BLOB, notBefore INTEGER, notAfter INTEGER, certSerial TEXT, account TEXT, foreign key(account) references accounts(id) ON DELETE CASCADE);' \
  'create index order_status_idx on orders(status);' \
  'create index order_expires_idx on orders(expires);' \
  'create index notBefore_idx on orders(notBefore);' \
  'create index notAfter_idx on orders(notAfter);' && \
    sudo sqlite3 /var/pki/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table authorizations(id TEXT PRIMARY KEY ASC, identifier BLOB, status INTEGER, expires INTEGER, wildcard INTEGER, "order" TEXT, foreign key("order") references orders(id) ON DELETE CASCADE);' \
  'create index authorization_status_idx on authorizations(status);' \
  'create index authorization_expires_idx on authorizations(expires);' && \
    sudo sqlite3 /var/pki/acme.db \
  'PRAGMA foreign_keys = ON;' \
  'create table challenges(id TEXT PRIMARY KEY ASC, type TEXT, url TEXT, status INTEGER, token TEXT, error TEXT, validated INTEGER, authorization TEXT, foreign key(authorization) references authorizations(id) ON DELETE CASCADE);' \
  'create index type_idx on challenges(type);' \
  'create index challenge_status_idx on challenges(status);' \
  'create index token_idx on challenges(token);' \
  'create index validated_idx on challenges(validated);' && \
    sudo chown -R nobody:alpine /var/pki && \
    cd /var/www/pki.example.com && \
    sudo -u nobody php83 save_cert.php /etc/ssl/pki.example.com.der
USER root
WORKDIR /
EXPOSE 80/tcp 443/tcp
ENTRYPOINT ["/usr/bin/go.sh"]

