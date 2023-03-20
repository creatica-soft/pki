<?php
require_once 'sql.php';
require_once 'rev_rep.php';

$oldCrl = sqlGetCerts('CRL');
if (is_null($oldCrl)) {
  $crlNumber = gmp_import(chr(0) . openssl_random_pseudo_bytes($cert_serial_bytes - 1));
  $crlNumber = gmp_strval($crlNumber, 10);
} else {
  if (count($oldCrl) > 1) {
    error_log('More than one CRL is found in db');
    header('Content-type: application/problem+pkix-crl', true, 500);
    exit(1);
  }
  if (strlen($oldCrl[0]['cert']) == 0) {
    error_log('CRL DER string is empty');
    header('Content-type: application/problem+pkix-crl', true, 500);
    exit(1);
  }
  if ($oldCrl[0]['notAfter'] < $now->getTimestamp()) { //CRL has expired, generate a new one
    $crlNumber = gmp_init($oldCrl[0]['serial']);
    $crlNumber = gmp_add($crlNumber, 1);
    $crlNumber = gmp_strval($crlNumber, 10);
  } else {
    $len = strlen($oldCrl[0]['cert']);
    header('Content-Type: application/pkix-crl', true);
    header('Content-Length: ' . $len, true, 200);  
    echo $oldCrl[0]['cert'];
    exit;
  }
}

$crl = new CRL();
   
$encoded = $crl->encode();
$len = strlen($encoded);
header('Content-Type: application/pkix-crl', true);
header('Content-Length: ' . $len, true, 200);  
echo $encoded;

?>