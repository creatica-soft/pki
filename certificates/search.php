<?php

require_once 'config.php';
require_once 'helper_functions.php';
require_once 'sql.php';

//$tmpDir = '/tmp/';
//$openssl_path = '/usr/bin/openssl3';
//$sqlite_db = '/var/pki/certs.db';
//$sqlite3_busy_timeoute_msec = 1000; //used in SLQLite3::busyTimeout() call

function exception_handler($e) {
  errorLog($e);
  response(500, "Internal PKI Directory Server error: " . $e->getMessage());
}

set_exception_handler('exception_handler');

if (! empty($_REQUEST["cn"]))
  $cn = sanitize($_REQUEST["cn"]);
elseif (! empty($_REQUEST["uri"]))
  $cn = sanitize($_REQUEST["uri"]);
elseif (! empty($_REQUEST["name"]))
  $cn = sanitize($_REQUEST["name"]);
elseif (! empty($_REQUEST["certHash"]))
  $fingerprint = base64_decode(rawurldecode($_REQUEST["certHash"]), $strict = true);
elseif (! empty($_REQUEST["sHash"]))
  $sHash = base64_decode(rawurldecode($_REQUEST["sHash"]), $strict = true);
elseif (! empty($_REQUEST["iHash"]))
  $iHash = bin2hex(base64_decode(rawurldecode($_REQUEST["iHash"]), $strict = true));
elseif (! empty($_REQUEST["iAndSHash"]))
  $iAndSHash = base64_decode(rawurldecode($_REQUEST["iAndSHash"]), $strict = true);
elseif (! empty($_REQUEST["sKIDHash"]))
  $sKIDHash = base64_decode(rawurldecode($_REQUEST["sKIDHash"]), $strict = true);

sqlUpdateAllCerts();

if (isset($cn)) {
  $certs = sqlSearchCertsByCN($cn, $status = 0);
  $formData = 'cn';
}
elseif (isset($fingerprint)) {
  $certs = sqlSearchCertsByFingerprint($fingerprint, $status = 0);
  $formData = 'fingerprint';
}
elseif (isset($sHash)) {
  $certs = sqlSearchCertsBySHash($sHash, $status = 0);
  $formData = 'sHash';
}
elseif (isset($iHash) && $iHash == 'ad879e9621d3fd0c67b2606d2c181ad041ebcca5') { //issuerHash in hex
  $certs = sqlGetCerts($subject = null, $status = 0);
  $formData = 'iHash';
}
elseif (isset($iAndSHash)) {
  $certs = sqlSearchCertsByIAndSHash($iAndSHash, $status = 0);
  $formData = 'iAndSHash';
}
elseif (isset($sKIDHash)) {
  $certs = sqlSearchCertsBySKIDHash($sKIDHash, $status = 0);
  $formData = 'sKIDHash';
}
if (! $certs)
  response(404, 'Certificates have not been found');

$certNum = count($certs);

if ($certNum == 1) {
  $cn = $certs[0]['cn'];
  header('Content-Type: application/pkix-cert', true, 200); //RFC-2585
  header('Content-Disposition: attachment; filename=' . "$cn.cer", true, 200);
  echo $certs[0]['cert'];
} else {
  header('Content-Type: multipart/form-data; boundary="0123456789"', true, 200); //RFC-2585
  header('Content-Disposition: attachment; filename=' . "bundle.pem", true, 200);

  $i = 0;
  foreach($certs as $cert) {
    if (key_exists('cn', $cert))
      $cn = $cert['cn'];
    elseif (key_exists('owner', $cert))
      $cn = $cert['owner'];    
    echo "--0123456789\r\n";
    echo 'Content-Disposition: form-data; name="' . $formData . '"; filename=' . "$cn-$i.pem\r\n"; //RFC-2585
    echo "Content-Type: application/x-pem-file\r\n\r\n"; //RFC-2585
    echo der2pem($cert['cert'], 'CERTIFICATE');

    $i++;
  }
  echo "\r\n--0123456789--";
}
?>