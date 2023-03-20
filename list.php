<?php

require_once 'config.php';
require_once 'helper_functions.php';
require_once 'sql.php';

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

if (!empty($_REQUEST["expire"])) {
  $expire = sanitize($_REQUEST["expire"]);
  if (is_numeric($expire)) {
    $expire = date_interval_create_from_date_string($expire . ' days');
    $expire = date_add($now, $expire)->getTimestamp();
  }
  else response(400, 'Usage: ' . full_request_uri() . '?type=<issued|revoked|expired|all>&expire=<DAYS>');
}

if (!empty($_REQUEST["type"])) {  
  $type = sanitize($_REQUEST["type"]);
  switch(strtolower($type)) {
    case 'issued':
      $status = 0;
      $type = 'issued';
    break;
    case 'revoked':
      $status = -1;
      $type = 'revoked';
    break;
    case 'expired':
      $status = 1;
      $type = 'expired';
    break;
    case 'all':
      $status = null;
      $type = 'all';
    break;
    default:
      response(400, 'Usage: ' . full_request_uri() . '?type=<issued|revoked|expired|all>&expire=<DAYS>');
  }
}

sqlUpdateAllCerts();

$certs = sqlGetOwnCerts($username, $status);
if (! $certs)
  response(404, 'No certificates have been found');

$certificates = array();
foreach ($certs as $cert) {
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
  $notBefore = new DateTime('@' . $cert['notBefore']);
  $notBefore = $notBefore->format("YmdHis") . 'Z';
  $notAfter = new DateTime('@' . $cert['notAfter']);
  $notAfter = $notAfter->format("YmdHis") . 'Z';
  switch ($cert['status']) {
    case 0: 
      $status = 'valid';
      if (! isset($expire))
        $certificates[] = array('Common Name' => $cn, 'Status' => $status, 'notBefore' => $notBefore, 'notAfter' => $notAfter, 'Serial Number' => $cert['serial']);
      else {
        if ($cert['notAfter'] <= $expire)
          $certificates[] = array('Common Name' => $cn, 'Status' => $status, 'notBefore' => $notBefore, 'notAfter' => $notAfter, 'Serial Number' => $cert['serial']);
      }
    break;
    case 1: 
      $status = 'expired'; 
      $certificates[] = array('Common Name' => $cn, 'Status' => $status, 'notBefore' => $notBefore, 'notAfter' => $notAfter, 'Serial Number' => $cert['serial']);
    break;
    case 2: 
      $status = 'on-hold'; 
      break;
    case -1: 
      $status = 'revoked';
      switch ($cert['revocationReason']) {
        case 0: $revReason = 'unspecified'; break;
        case 1: $revReason = 'keyCompromise'; break;
        case 2: $revReason = 'cACompromise'; break;
        case 3: $revReason = 'affiliationChanged'; break;
        case 4: $revReason = 'superseded'; break;
        case 5: $revReason = 'cessationOfOperation'; break;
        case 6: $revReason = 'certificateHold'; break;
        case 8: $revReason = 'removeFromCRL'; break;
        case 9: $revReason = 'privilegeWithdrawn'; break;
        case 10: $revReason = 'aACompromise'; break;
      }
      $revDate = new DateTime('@' . $cert['revocationDate']);
      $revDate = $revDate->format("YmdHis") . 'Z';
      $certificates[] = array('Common Name' => $cn, 'Status' => $status, 'notBefore' => $notBefore, 'notAfter' => $notAfter, 'Serial Number' => $cert['serial'], 'RevocationDate' => $revDate, 'RevocationReason' => $revReason);
    break;
  }
}

$result = array('status' => 200, 'detail' => 'Listing ' . $type . ' certificates');
header('Content-type: application/json', true, 200);
echo json_encode(array($result, $certificates), JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);

?>