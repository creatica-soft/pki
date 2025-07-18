<?php

require_once 'acme/globals.php';
require_once 'helper_functions.php';
require_once 'base64url.php';
require_once 'sql.php';

function acmeError($type, $detail, $statusCode) {
  global $acme_urn_error, $supported_jwk_algs;
  header('Cache-Control: no-store', true);
  header('Content-Type: application/problem+json', true);
  switch ($type) {
    case 'badSignatureAlgorithm':
      $encoded = json_encode(['type' => $acme_urn_error . $type, 'detail' => $detail, 'algorithms' => $supported_jwk_algs]);
    break;
    default:
      $encoded = json_encode(['type' => $acme_urn_error . $type, 'detail' => $detail]);
  }
  header('Content-Length: ' . strlen($encoded), true, $statusCode);
  echo $encoded;
  exit(1);
}

function exception_handler($e) {
  errorLog($e, 'exception');
  acmeError('exception', $e->getMessage(), 500);
}

set_exception_handler('exception_handler');

if (php_sapi_name() == 'cli') {
  if ($argc == 3) {
    $username = $argv[1];
    $password = $argv[2];
  } else {
    echo 'Usage: php key_request.php <username> <password>';
    exit(1);
  }
} else {
  if (empty($_REQUEST["username"]) || empty($_REQUEST["password"]))
    acmeError('usage', 'Usage: ' . full_request_uri() . '?username=<username>&password=<password>', 400);
  $username = sanitize($_REQUEST["username"]);
  $password = sanitize($_REQUEST["password"]);
}
//This is for testing only! Comment out "if" line in production
if ($username != "test")
  auth($username, $password);

//at this point we authenticated the user and can
//issue CMP and/or ACME client a shared key
//$username could be a service account

$key = base64url_encode(openssl_random_pseudo_bytes($hmac_key_length));

sqlSaveKey($username, $key);

// Return the ACME Client the key
if (php_sapi_name() == 'cli') {
  echo $key;
} else {
  $json = array('status' => 200, 'detail' => array('message' => 'PKI ACME Client External Account Binding key request is successful', 'key' => $key));
  header('Content-type: application/json', true, 200);
  echo json_encode($json);
}

