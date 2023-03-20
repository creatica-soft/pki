<?php

require_once 'config.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'cert_rev_list.php';

function exception_handler($e) {
  errorLog($e);
  response(500, "PKI Directory Server error: " . $e->getMessage());
}

set_exception_handler('exception_handler');


if (! empty($_REQUEST["iHash"]))
  $iHash = bin2hex(base64_decode(rawurldecode($_REQUEST["iHash"]), $strict = true));
elseif (! empty($_REQUEST["sKIDHash"]))
  $sKIDHash = bin2hex(base64_decode(rawurldecode($_REQUEST["sKIDHash"]), $strict = true));

if (isset($iHash) && $iHash == 'ad879e9621d3fd0c67b2606d2c181ad041ebcca5') { //issuerHash in hex, b64 rYeeliHT/QxnsmBtLBga0EHrzKU
  $crls = sqlGetCerts($subject = 'CRL', $status = 0);
}
elseif (isset($sKIDHash) && $sKIDHash == '1c7aa5c69b5a4adf5a7fe17b5cb9665e0e718957') { //sha1 hash of subject KID octets in hex, b64 HHqlxptaSt9af+F7XLlmXg5xiVc
  $crls = sqlGetCerts($subject = 'CRL', $status = 0);
} else response(404, 'CRLs have not been found');

if (! $crls) {
    //generate new CRL
    $crl = new CRL();
    $crls = array();
    $crls[0]['cert'] = $crl->encode();
}

$crlNum = count($crls);

if ($crlNum >= 1) {
  header('Content-Type: application/pkix-crl', true, 200); //RFC-2585
  header('Content-Disposition: attachment; filename=signing_ca.crl', true, 200);
  echo $crls[0]['cert'];
}
?>