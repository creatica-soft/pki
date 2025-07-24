<?php
$now = new DateTime("now", new DateTimeZone("+0000"));
$base_url = "https://$PKI_DNS";

$master_users = ['admin'];

$domains_file = "/var/www/pki/domains.txt";
$allowed_ips_in_san = "/\A10\.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\z/";

$digest_algs = ['sha256'];
$default_digest_alg ='sha256';
$default_encrypting_alg = 'rsaEncryption';
$default_signing_alg = 'sha256WithRSAEncryption';

$signing_ca_path = "/etc/ssl/signing_ca.pem";
$signing_ca_der_path = "/etc/ssl/signing_ca.der";
$signing_ca_privkey_path = "/etc/ssl/private/signing_ca.key";
$root_ca_path = "/etc/ssl/root_ca.pem";
$root_ca_der_path = "/etc/ssl/root_ca.der";

//limits
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
$crl_distribution_points = ["http://$PKI_DNS/pki/signing_ca.crl"];
$aia_ca_issuers = ["http://$PKI_DNS/pki/signing_ca.crt"];
$aia_ocsp = ["http://$PKI_DNS/ocsp/"];

$crl_next_update_in_days = 30;
$sql_db = "$DB"; //'postgres' or 'sqlite'
$pg_con = "host=$PG_DNS port=5432 dbname=postgres user=postgres password=postgres_password sslmode=$SSL_MODE $SSL_ROOT_CERT"; //disable,allow,prefer,require,verify-ca,verify-full
$sqlite_db = "$DB_DIR/sqlite/certs.db";
$sqlite3_busy_timeoute_msec = 1000;

$ldap_auth = $LDAP_AUTH; //true for production or false for testing
$ldap_uri = "ldaps://$LDAP_DNS ldaps://$LDAP_DNS2";
$ldap_network_timeout_sec = 3;
$ldap_tls_require_cert = LDAP_OPT_X_TLS_DEMAND; // for expired certs use LDAP_OPT_X_TLS_NEVER
$ldap_tls_crl_check = LDAP_OPT_X_TLS_CRL_NONE; //other options LDAP_OPT_X_TLS_CRL_NONE, LDAP_OPT_X_TLS_CRL_PEER, LDAP_OPT_X_TLS_CRL_ALL
$ldap_base_dn = ["$OU_USERS", "$OU_SERVICE_ACCOUNTS"];
$ldap_ca_cert_file = '/etc/ssl/ca_chain.pem';
$ldap_binding_dn = "$LDAP_BINDING_DN";
/*
 openssl_public_encrypt($pass, $ldap_encrypted_pass, openssl_x509_read("file://$signing_ca_path"));
 $ldap_encrypted_pass = bin2hex($ldap_encrypted_pass);
 to decrypt call openssl_private_decrypt(hex2bin($ldap_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
*/
$ldap_encrypted_pass = "$LDAP_ENC_PASSWORD";
$pg_encrypted_pass = "$PG_ENC_PASSWORD";
