<?php
// can be tested with curl client using Avifors AD username and password for authentication for /.well-known/est/simpleenroll and
// .well-known/est/simplereenroll POST requests. POST must include appropriate CSR
// GET requests to /.well-known/est/cacerts do not require authentication
// CURL_CA_BUNDLE envvar can be set to point to internal_ca_bundle.pem

require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'general_name.php';
require_once 'cert_template.php';
require_once 'certificate.php';
require_once 'extension.php';
require_once 'signed_data.php';

function headers($len, $code = 200) {
  http_response_code($code);
  header('Cache-Control: no-store', true, $code);
  header('Content-Type: application/pkcs7-mime; certs-only', true, $code);
  header('Content-Transfer-Encoding: base64', true, $code);
  header('Content-Length: ' . $len, true, $code);
}

function estError($detail, $statusCode) {
  header('Cache-Control: no-store', true);
  header('Content-Type: text/plain', true);
  header('Content-Length: ' . strlen($detail), true, $statusCode);
  echo $detail;
  exit(1);
}

function exception_handler($e) {
  errorLog($e);
  estError("Internal PKI EST Server: " . $e->getMessage(), 500);
}

// Convert errors to exceptions
//set_error_handler(function ($severity, $message, $file, $line) {
//    error_log("PHP Error: $message in $file on line $line");
//    throw new ErrorException($message, 0, $severity, $file, $line);
//});

set_exception_handler('exception_handler');

$authenticated = false;
$role = 'standard';
if (key_exists('CLIENT_CERT_VERIFY', $_SERVER)) {
  $clientCertVerify = $_SERVER['CLIENT_CERT_VERIFY'];
  $dn = $_SERVER['SUBJECT_DN'];
  $attrs = explode(',', $dn);
  foreach ($attrs as $attr) {
    if (str_contains($attr, '=')) {
      list($type, $value) = explode('=', $attr);
      switch(strtolower($type)) {
        case 'role':
          $role = $value;
        break;
        case 'cn':
          $username = $value;
        break;
        default:
      }
    }
  }
  switch ($clientCertVerify) {
    case 'SUCCESS':
      $authenticated = true;
    break;
    case 'FAILED':
      $reason = explode(':', $clientCertVerify)[1];
      errorLog("Unauthorized: SSL authentication with your client certificate (subject $dn) failed. Reason: $reason");
      estError("Unauthorized: SSL authentication with your client certificate (subject $dn) failed. Reason: $reason", 401); 
    break;
    default: //NONE - will use username and password for POST
  }
}

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
  errorLog("est-server receiving " . $_SERVER['REQUEST_METHOD'] . " request for " . $_SERVER['REQUEST_URI'] . " URI from " . $_SERVER['REMOTE_ADDR'], 'info');

switch($_SERVER['REQUEST_METHOD']) {
  case 'GET':
    if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
      errorLog("est-server: processing GET request...");
    if ($log_level == LOG_DEBUG)
      errorLog("est-server GET request URI: " . $_SERVER['REQUEST_URI'], $level = 'debug');
    switch($_SERVER['REQUEST_URI']) {
/*
To get the CA certs, use

curl https://pki.example.com/.well-known/est/cacerts | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out cacerts.pem

one might want to delete subject and issuer lines in cacerts.pem and leave just certs

*/
      case '/.well-known/est/cacerts':
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("est-server: processing cacerts GET request...", $level = 'info');
       
        $contentInfo = new ContentInfo('1.2.840.113549.1.7.2');
        $contentInfo->content->certificates[] = new Certificate($signing_ca_der_path);
        $contentInfo->content->certificates[] = new Certificate($root_ca_der_path);
        $der = $contentInfo->encode();
        $response = base64_encode($der); 
        headers(strlen($response));
        echo $response;
        if ($log_level == LOG_DEBUG)
          errorLog("est-server cacerts reply: " . print_r(headers_list()) . "\n\n$response", $level = 'debug');
        exit(0);
      default:
        errorLog("est-server.php error: unrecognized http request uri using GET " . $_SERVER['REQUEST_URI']);
        estError('method not allowed', 405); 
    }
  break;
  case 'POST':
    if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
      errorLog("est-server: processing POST request...", $level = 'info');
    if ($_SERVER['CONTENT_TYPE'] != 'application/pkcs10') {
      errorLog("est-server.php error: wrong content-type - expected application/pkcs10, received " . $_SERVER['CONTENT_TYPE']);
      estError('wrong content type', 415);
    }
    if (! key_exists('PHP_AUTH_USER', $_SERVER)) {
      if (! $authenticated) {
        errorLog("est-server.php error: missing PHP_AUTH_USER key in superglobal _SERVER");
        estError('missing username', 401);
      }
    } else 
      $username = $_SERVER['PHP_AUTH_USER'];
    if (! key_exists('PHP_AUTH_PW', $_SERVER)) {
      if ( ! $authenticated) {
        errorLog("est-server.php error: missing PHP_AUTH_PW key in superglobal _SERVER");
        estError('missing password', 401);
      }
    } else 
      $password = $_SERVER['PHP_AUTH_PW'];
    if (isset($username) && isset($password) && ! $authenticated && $ldap_auth)
      auth($username, $password);
    
    $estRequest = file_get_contents('php://input');
    if ($log_level == LOG_DEBUG)
      errorLog("est-server POST request: $estRequest", $level = 'debug');
    $len = strlen($estRequest);
    if ($_SERVER['CONTENT_LENGTH'] != $len) {
      errorLog("est-server.php error(): wrong content-length, calculated $len, received " . $_SERVER['CONTENT_LENGTH']);
      estError('wrong content length', 400);
    }

    switch($_SERVER['REQUEST_URI']) {
/*
Certificate can be requested using curl and openssl, where cacerts are from the GET request above and test.example.internal.req is a CSR file:

curl -v --cacert cacerts.pem --user username:password --data-binary @test.example.internal.req -H "Content-Type: application/pkcs10"  https://pki.example.com/.well-known/est/simpleenroll | openssl base64 -d -A | openssl pkcs7 -inform der -print_certs -out test.lat.internal.crt

or with SSL client certificate auth (simply replace --user username:password with --cert username.p12[:password]

curl -v --cacert cacerts.pem --cert username.p12[:password] --data-binary @test.example.internal.req -H "Content-Type: application/pkcs10"  https://pki.example.com/.well-known/est/simpleenroll | openssl base64 -d -A | openssl pkcs7 -inform der -print_certs -out test.example.internal.crt

Then delete subject and issuer from the test.example.internal.crt if those lines are unwanted for any reason
*/
      case '/.well-known/est/simpleenroll':
      case '/.well-known/est/simplereenroll': //not much difference from simple enroll
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
          errorLog("est-server simpleenroll: processing simpleenroll POST request...", $level = 'info');
        $certreq = new CertificationRequest();
        $certreq->decode(pem2der($estRequest));
                    
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("est-server csrUrl: converting CSR to CertTemplate...", $level = 'info');
        $certTemplate = new CertTemplate();
        $certTemplate->csr2template($certreq, $role);
        if ($log_level == LOG_DEBUG) 
          errorLog("certTemplate: " . print_r($certTemplate, true));   
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("est-server simpleenroll: all checks passed, creating the cert...", $level = 'info');
        $cert = new Certificate();
        $cert->set($certTemplate, $username, $defaultExtKeyUsages = true, $role); //$username will be set as an owner of the cert in its subject
        if ($log_level == LOG_DEBUG) 
          errorLog("new_cert: " . print_r($cert, true), $level = 'debug');
        $cert->sign();
        $cert->save(0);
        if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
          errorLog("est-server simpleenroll: certificate with the serial number " . $cert->tbsCertificate->serialNumber . " has been created successfully. Updating the order with id " . $order['id'], $level = 'info');
        $contentInfo = new ContentInfo('1.2.840.113549.1.7.2');
        $contentInfo->content->certificates[] = $cert;
        $der = $contentInfo->encode();
        $response = base64_encode($der); 
        headers(strlen($response));
        echo $response;
        if ($log_level == LOG_DEBUG)
          errorLog("est-server simpleenroll reply: " . print_r(headers_list()) . "\n\n$response", $level = 'debug');
        exit(0);
      default:
        errorLog("est-server.php error: unrecognized http request uri using POST " . $_SERVER['REQUEST_URI']);
        estError('unknown http request uri', 400);        
    }    
  break;
  default:
    errorLog("est-server.php error: unrecognized http request method " . $_SERVER['REQUEST_METHOD']);
    estError('unknown http request method', 400);        
}
