<?php
require_once 'config.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'certificate.php';

if ($argc < 2) {
  print "save_cert.php will save a certificate issued by the Signing CA into sqllit3 certs.db\n";
  print "Usage: php8 save_cert.php <certfile.der>\n";
  exit(1);
}

if (! file_exists($argv[1])) {
  print "File " . $argv[1] . " does not exist\n";
  exit(1);
}
$ca = new Certificate($signing_ca_der_path);
$cn = $ca->tbsCertificate->subject->getCN();
$der = file_get_contents($argv[1]);
$cert = new Certificate($argv[1]);
//verify our signature
while(openssl_error_string());
$encoded = $cert->tbsCertificate->encode();
$res = openssl_verify($encoded, hex2bin($cert->signature), openssl_x509_read('file://' . $signing_ca_path), oid2str($cert->signatureAlg->algorithm));
switch($res) {
  case 0: //invalid
    print "Invalid certificate signature, serialNumber " . $cert->tbsCertificate->serialNumber . ", subject " . $cert->tbsCertificate->subject . "\n";
    exit(1);
  break;
  case 1: //valid, need to verify the validity dates and revocation status
    $serial = $cert->tbsCertificate->serialNumber;
    $notBefore = $cert->tbsCertificate->validity->notBefore2timestamp();
    $notAfter = $cert->tbsCertificate->validity->notAfter2timestamp();
    $issuer = $cert->tbsCertificate->issuer->getCN();
    if ($issuer != $cn) {
      print "Certificate not issued by $cn\n";
      exit(1);
    }
    $owner = $cert->tbsCertificate->subject->getOwner();
    if (! $owner) $owner = '';
    $role = $cert->tbsCertificate->subject->getRole();
    if (! $role) $role = '';
    $ts = $now->getTimestamp();
    if ($notBefore <= $ts && $notAfter > $ts)
      $status = 0; //valid
    else $status = 1; //expired
  break;
  case -1: //error
    $error = "Certificate::verify() openssl verify error: ";
    while($err = openssl_error_string()) $error .= $err;
    print $error;
    exit(1);
}
$res = sqlSaveCert($serial, $status, $cert->tbsCertificate->subject, $notBefore, $notAfter, $owner, $role, $der);

if ($res)
  print "Certificate with sn $serial and subject " . $cert->tbsCertificate->subject . " saved in $sqlite_db\n";
else {
  print "Certificate with sn $serial and subject " . $cert->tbsCertificate->subject . " already exists in $sqlite_db\n";
  exit(1);
}

?>
