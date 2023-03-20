<?php
$now = new DateTime("now", new DateTimeZone("+0000"));
$base_url = 'https://pki.example.com';

$master_users = ['admin'];

$domains_file = '/var/www/pki.example.com/domains.txt';
$allowed_ips_in_san = "/\A10\.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\z/";

//$signed_data_version = 3; //3 - for ms-wstep; 4 - for est - these are set in respective globals.php
$digest_algs = ['sha256'];
$default_digest_alg ='sha256';
$default_encrypting_alg = 'rsaEncryption';
$default_signing_alg = 'sha256WithRSAEncryption';

$signing_ca_path = '/etc/ssl/signing_ca.pem';
$signing_ca_der_path = '/etc/ssl/signing_ca.der';
$signing_ca_privkey_path = '/etc/ssl/private/signing_ca.key';
$root_ca_path = '/etc/ssl/root_ca.pem';
$root_ca_der_path = '/etc/ssl/root_ca.der';

$max_certs_per_cn = 10;
$max_certs_standard = 1000;
$max_certs_master = 100000;

$cert_serial_bytes = 20;
$cert_validity_days = 730;
$min_key_size = 2048; // for RSA keys
$min_dsakey_size = 1024; // for DSA keys
$min_eckey_size = 256; // for ECDSA keys (secp256r1)
$default_ec = 'secp384r1';
$max_san = 50; //there is no upper limit for the MAX number of GeneralNames; the implementation is free to choose what it likes
$default_key_usages = ['digitalSignature' => 1, 'nonRepudiation' => 0, 'keyEncipherment' => 1, 'dataEncipherment' => 0, 'keyAgreement' => 0, 'keyCertSign' => 0, 'crlSign' => 0, 'encipherOnly' => 0, 'decipherOnly' => 0];
$default_extended_key_usages = ['TLS Web Server Authentication', 'TLS Web Client Authentication'];
$default_extensions = ['X509v3 Subject Key Identifier', 'X509v3 Authority Key Identifier', 'X509v3 Key Usage', 'X509v3 Basic Constraints', 'X509v3 Extended Key Usage', 'X509v3 Subject Alternative Name', 'X509v3 CRL Distribution Points', 'Authority Information Access'];
$forbidden_extensions = ['X509v3 Subject Key Identifier', 'X509v3 Authority Key Identifier', 'X509v3 Basic Constraints', 'X509v3 CRL Distribution Points', 'Authority Information Access'];
$crl_distribution_points = ['http://pki.example.com/pki/signing_ca.crl'];
$aia_ca_issuers = ['http://pki.example.com/pki/signing_ca.crt'];
$aia_ocsp = ['http://pki.example.com/ocsp/'];

$crl_next_update_in_days = 30;
/* 
sudo sqlite3 /var/pki/certs.db \
  'create table certs(serial TEXT PRIMARY KEY ASC, status INTEGER, revocationReason INTEGER, revocationDate INTEGER, notBefore INTEGER, notAfter INTEGER, subject TEXT, owner TEXT, role TEXT, cert BLOB, cn TEXT, fingerprint TEXT, sHash TEXT, iAndSHash TEXT, sKIDHash TEXT);' \
  'CREATE INDEX subj_idx on certs(subject); CREATE INDEX status_idx on certs(status); CREATE INDEX from_idx on certs(notBefore);' \
  'CREATE INDEX to_idx on certs(notAfter); CREATE INDEX owner_idx on certs(owner); CREATE INDEX role_idx on certs(role);' \
  'CREATE INDEX cn_idx on certs(cn); CREATE INDEX fingerprint_idx on certs(fingerprint); CREATE INDEX sHash_idx on certs(sHash);' \
  'CREATE INDEX iAndSHash_idx on certs(iAndSHash); CREATE INDEX sKIDHash_idx on certs(sKIDHash);'

status: 0 - valid, 1 - expired, -1 - revoked

sudo sqlite3 /var/pki/certs.db \
  'create table cert_req_ids(serial TEXT PRIMARY KEY ASC, certReqId TEXT, timestamp INTEGER, nonce TEXT, transactionID TEXT);' \
  'CREATE INDEX certReqId_idx on cert_req_ids(certReqId); CREATE INDEX transactionID_idx on cert_req_ids(transactionID);'

cert_req_ids table is used by CMP only and has unconfirmed cert_req_ids; once confirmed (or denied) in CERTCONF message or unconfirmed within 
$confirm_wait_time_sec, the cert status should be updated in certs table from 2 (on-hold) to either 0 (valid) or revoked (-1) and the record 
in cert_req_ids should be deleted

//key is base64url_encoded key bytes
sudo sqlite3 /var/pki/certs.db \
  'create table keys(kid TEXT PRIMARY KEY ASC, key TEXT);'
*/
$sqlite_db = '/var/pki/certs.db';
$sqlite3_busy_timeoute_msec = 1000;

$ldap_uri = 'ldaps://ldap.example.com ldaps://ldap2.example.com';
$ldap_network_timeout_sec = 3;
$ldap_tls_require_cert = LDAP_OPT_X_TLS_DEMAND; // for expired certs such as KazootekRootCa in TDR use LDAP_OPT_X_TLS_NEVER
$ldap_tls_crl_check = LDAP_OPT_X_TLS_CRL_NONE; //other options LDAP_OPT_X_TLS_CRL_NONE,LDAP_OPT_X_TLS_CRL_PEER, LDAP_OPT_X_TLS_CRL_ALL
$ldap_base_dn = ['OU=Users,DC=Example,DC=Com',
                 'OU=SERVICE_ACCOUNTS,DC=Example,DC=Com'];
$ldap_ca_cert_file = '/etc/ssl/ca_chain.pem';
$ldap_binding_dn = 'CN=pki,OU=Users,DC=example,DC=com';
/*
 openssl_public_encrypt($pass, $ldap_encrypted_pass, openssl_x509_read("file://$signing_ca_path"));
 $ldap_encrypted_pass = bin2hex($ldap_encrypted_pass);
 to decrypt call openssl_private_decrypt(hex2bin($ldap_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
*/
$ldap_encrypted_pass = 'encrypted_pass';

?>