<?php
require_once '/var/www/$PKI_DNS/lib/config.php';
if ($argc == 2) {
  $ldap_encrypted_pass = ''; 
  openssl_public_encrypt($argv[1], $ldap_encrypted_pass, openssl_x509_read("file://$signing_ca_path"));
  $ldap_encrypted_pass = bin2hex($ldap_encrypted_pass);
  echo $ldap_encrypted_pass;
} else echo "usage: php$PHP_VER encrypt_pass.php <password>";
