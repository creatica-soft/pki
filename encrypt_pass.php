<?php
if ($argc == 2) {
  openssl_public_encrypt($argv[1], $ldap_encrypted_pass, openssl_x509_read("file:///etc/ssl/signing_ca.pem"));
  $ldap_encrypted_pass = bin2hex($ldap_encrypted_pass);
  echo $ldap_encrypted_pass;
} else echo "usage: php$PHP_VER encrypt_pass.php <password>"
?>