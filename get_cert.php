<?php

require_once 'config.php';
require_once 'sql.php';
require_once 'helper_functions.php';

$clientCertVerify = $_SERVER['CLIENT_CERT_VERIFY'];
switch ($clientCertVerify) {
  case 'SUCCESS':
  break;
  case 'NONE':
    response(401, 'Unauthorized: please use your client SSL certificate for authentication');
  break;
  default: //FAILED:reason
    response(401, 'Unauthorized: SSL authentication with your client certificate failed. Reason: ' . explode(':', $clientCertVerify)[1]);
}

$dn = $_SERVER['SUBJECT_DN'];
$attrs = explode(',', $dn);
foreach ($attrs as $attr) {
  list($type, $value) = explode('=', $attr);
  switch(strtolower($type)) {
    case 'role':
      $role = $value;
    break;
    case 'cn':
      $username = $value;
    break;
  }
}

if (! empty($_REQUEST["serial"])) {
  $serial = sanitize($_REQUEST["serial"]);
}
$cert = sqlGetCert($serial);
if (! $cert)
  response(404, 'Certificate has not been found');
if ($cert['owner'] != $username)
  response(401, 'Certificate owner is different from SSL client certificate subject CN');

$attrs = explode('/', $cert['subject']);
foreach ($attrs as $attr) {
  if (empty($attr)) continue;
  list($attrib, $value) = explode('=', $attr);
  switch(strtolower($attrib)) {
    case 'owner':
      $owner = $value;
    break;
    case 'cn':
      $cn = $value;
    break;
  }
}

header("Content-Disposition: attachment; filename=$cn.cer"); //RFC-2585
header('Content-Type: application/pkix-cert', true, 200); //RFC-2585
echo $cert['cert'];
