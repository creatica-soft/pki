<?php

require_once 'asn1_types.php';
require_once 'asn1decode.php';
require_once 'asn1encode.php';
require_once 'helper_functions.php';
require_once 'sql.php';
require_once 'cmp_sql.php';

require_once 'pki_message.php';
require_once 'globals.php';
require_once 'cert_response.php';
require_once 'cert_rep_msg.php';
require_once 'pki_status_info.php';
require_once 'rev_rep.php';

//global declarations
$sender = null;
$transactionID = '';
$senderNonce = '';
$requestContentType = -1;
$request = null;
$response = null;
$responseStatus = ACCEPTED;
$implicitConfirm = false;
$confirmWaitTimeInterval = date_interval_create_from_date_string("$confirm_wait_time_sec seconds");
$statusStrings = array();
$role = 'standard';

function headers($statusCode, $len) {
  header('Cache-Control: no-cache', true);
  header('Pragma: no-cache', true);
  header('Content-Type: application/pkixcmp', true);
  header('Content-Length: ' . $len, true, $statusCode);  
}

function errorMsg($statusStrings, $errorCode = 0) {
  global $pkiFailInfo, $signing_ca_der_path, $include_signing_ca_cert_in_extra_certs;
  //$strings = '';
  //$n = count($statusStrings);
  //for ($i = 0; $i < $n - 1; $i++)
  //  $strings .= $statusStrings[$i] . "\n";
  //$strings .= $statusStrings[$n - 1];  
  $response = new PKIMessage();
  if (is_null($response->header))
    $response->setHeader();
  $response->setBody(ERROR);
  $response->body->content->set(REJECTION, $statusStrings, $pkiFailInfo[$errorCode]);
  $response->protection = new PKIProtection();
  $response->protection->protect($response->header, $response->body);
  if ($include_signing_ca_cert_in_extra_certs) {
    $response->extraCerts = new ExtraCerts();
    $response->extraCerts->extraCerts[] = file_get_contents($signing_ca_der_path);
    $response->extraCerts->encoded = true;
  }
  $encoded = $response->encode();
  headers(200, strlen($encoded));
  echo $encoded;
  exit(1);
}

function exception_handler($e) {
  errorLog($e);
  errorMsg(array("Internal PKI CMP Server: " . $e->getMessage()), $e->getCode());
}

// Convert errors to exceptions
//set_error_handler(function ($severity, $message, $file, $line) {
//    error_log("PHP Error: $message in $file on line $line");
//    throw new ErrorException($message, 0, $severity, $file, $line);
//});

set_exception_handler('exception_handler');

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: receiving data from " . $_SERVER['REMOTE_ADDR'] . "\n", 'info');
if ($_SERVER['CONTENT_TYPE'] != $content_type) {
  errorLog('Wrong Content-Type Header: ' . $_SERVER['CONTENT_TYPE'] . ". Content-Type header must be $content_type");
  headers(415, 0);
  exit(1);
}
if ($_SERVER['REQUEST_URI'] != $cmp_path) {
  errorLog('Wrong request uri: ' . $_SERVER['REQUEST_URI'] . ". Request uri must be $cmp_path");
  headers(404, 0);
  exit(1);
}
if ($log_level == LOG_DEBUG) 
  errorLog("cmp server.php: content-type http header has been verified: " . $_SERVER['CONTENT_TYPE'] . "\n", 'debug');
 
$pkiRequest = file_get_contents('php://input');
$len = strlen($pkiRequest);
if ($_SERVER['CONTENT_LENGTH'] != $len) {
  errorLog('Wrong Content-Length Header: ' . $_SERVER['CONTENT_LENGTH'] . ". Content-Length is not equal content size $len");
  exit(1);
}
if ($log_level == LOG_DEBUG) {
  errorLog("cmp server.php: verified that http header Content-Length was equaled to the actual data size: " . $_SERVER['CONTENT_LENGTH'] . "\n", 'debug');
  errorLog("cmp server.php: based64 encoded DER content is: " . base64_encode($pkiRequest) . "\n", 'debug');
}

$request = new PKIMessage();
$request->decode($pkiRequest);
if ($log_level == LOG_DEBUG) {
  errorLog("cmp server.php: decoded data is " . print_r($request, true) . "\n", 'debug');
}

$request->checkHeader();
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: PKIHeader check has passed\n", 'info');

if ($request->header->protectionAlg->algorithm != str2oid('password based MAC')) {
  //find a cert with the subject matching the sender and senderKID matching SubjectKeyID
  $cert = $request->getCert();
  $role = $cert->tbsCertificate->subject->getRole();
  if (! $role)
    throw new Exception("Client SSL certificate with the subject " . $cert->tbsCertificate->subject . " is missing a role attribute", BAD_MESSAGE_CHECK);
  $certCN = $cert->tbsCertificate->subject->getCN();
  if (! $certCN)
    throw new Exception("cmp server.php: client SSL certificate with the subject " . $cert->tbsCertificate->subject . " is missing a CN attribute", BAD_MESSAGE_CHECK);
  if (in_array($certCN, $master_users)) $role = 'master';
  if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
    errorLog("cmp server.php: a certificate matching the sender " . $sender->name . " has been found\n", 'info');
  $request->validateProtection($secret = null, $cert);   
  if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
    errorLog("cmp server.php: PKI message protection has been validated\n", 'info');
} else { //password-based MAC - need to find the shared secret corresponding to $this->header->sender
  $username = $request->header->sender->getCN();
  if (! $username) throw new Exception("cmp server.php: sender is missing a CN attribute - please use '/CN=username' in the subject");  
  if (in_array($username, $master_users)) $role = 'master';
  $key = sqlGetKey($username);
  if (! $key) throw new Exception("cmp server.php: a shared secret for $username is not found");
  $request->validateProtection($secret = $key);
}
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: creating the PKI response for the request type " . $request->body->type . "\n", 'info');
$response = new PKIMessage();
$response->setHeader();
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response header has been set\n", 'info');

switch($request->body->type) {
  //only valid response cases are listed here
  //requests are in pki_message.php decode()
  case 0: //ir, CertReqMessages
    $response->setBody(IP);
  break;
  case 2: //cr, CertReqMessages
    $response->setBody(CP);
  break;
  case 4: //p10cr, CertReqMessages
    $response->setBody(CP);
  break;
  case 7: //kur, CertReqMessages
    $response->setBody(KUP);
  break;
  case 11: //rr, RevReqContent
    $response->setBody(RP);
  break;
  case 21: //genm, GenMsgContent
    $response->setBody(GENP);
  break;
  case 24: //certConf, CertConfirmContent
    $response->setBody(PKICONF);
    $certReqIds = sqlGetCertReqIds($request->header->transactionID);
    if (! $certReqIds)
      throw new Exception('BAD_REQUEST: no certReqIds have been found', BAD_REQUEST);
    if (! is_array($request->body->content->certStatus)) { //accepted none of the certs
      foreach($certReqIds as $id)
        sqlRevokeCert($id['serial'], $now->getTimestamp());
    } else {
      foreach($request->body->content->certStatus as $certStatus) {
        $reqIdFound = false;
        foreach($certReqIds as $id) {
          if ($certStatus->certReqId == $id['certReqId']) {
            $reqIdFound = true;
            if ($certStatus->statusInfo->status != ACCEPTED)
              sqlRevokeCert($id['serial'], $now->getTimestamp());
            else sqlUpdateCertStatus($id['serial'], 0);
            break;
          }
        }
        if (! $reqIdFound)
          throw new Exception('cmp server.php: BAD_REQUEST: certReqId ' . $certStatus->certReqId . ' has not been found', BAD_REQUEST);
      }
    }
    sqlDeleteCertReqIds($request->header->transactionID);
  break;
  default:
    throw new Exception('cmp server.php: Unsupported request type: ' . $request->body->type, BAD_REQUEST);
  break;
}
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response body has been set\n", 'info');

$response->protection = new PKIProtection();
$response->protection->protect($response->header, $response->body);
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response header and body have been protected by a digital signature\n", 'info');
if ($include_signing_ca_cert_in_extra_certs) {
  $response->extraCerts = new ExtraCerts();
  $response->extraCerts->encoded = true;
  $response->extraCerts->extraCerts[] = file_get_contents($signing_ca_der_path);
  //$response->extraCerts->extraCerts[] = file_get_contents($root_ca_der_path); 
  //root ca cert is better to send in CertRepMessage::caPubs[] field
  //see $include_root_ca_cert_in_capubs global var
  if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
    errorLog("cmp server.php: extra certs have been added to the PKI response\n", 'info');
}
if ($log_level == LOG_DEBUG) {
  errorLog("cmp server.php: the PKI response content is " . print_r($response, true) . "\n", 'debug');
}

$encoded = $response->encode();
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response has been DER-encoded\n", 'info');
if ($log_level == LOG_DEBUG) {
  errorLog("cmp server.php: base64-encoded PKI response is " . base64_encode($encoded) . "\n", 'debug');
}
headers(200, strlen($encoded));
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response http headers have been sent\n", 'info');
echo $encoded;
if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
  errorLog("cmp server.php: the PKI response has been sent\n", 'info');
