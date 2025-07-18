<?php
require_once 'asn1_types.php';
require_once 'helper_functions.php';
require_once 'globals.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'extension.php';
require_once 'general_name.php';
require_once 'algorithm_identifier.php';
require_once 'certificate.php';
require_once 'cert_id.php';
require_once 'request.php';
require_once 'response.php';
require_once 'sql.php';

function headers($len) {
  header('Cache-Control: no-cache', true);
  header('Pragma: no-cache', true);
  header('Content-Type: application/ocsp-response', true);
  header('Content-Length: ' . $len, true, 200);
}

function ocspError($status) {
  $response = new OCSPResponse($status);
  $encoded = $response->encode();
  headers(strlen($encoded));
  echo $encoded;
  exit(1);
}

function exception_handler($e) {
  errorLog($e);
  ocspError($e->getCode());
}

set_exception_handler('exception_handler');

/*
   OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  -- Response has valid confirmations
       malformedRequest      (1),  -- Illegal confirmation request
       internalError         (2),  -- Internal error in issuer
       tryLater              (3),  -- Try again later
                                   -- (4) is not used
       sigRequired           (5),  -- Must sign the request
       unauthorized          (6)   -- Request unauthorized
   }
*/

if ($log_level == LOG_DEBUG || $log_level == LOG_INFO) 
  errorLog("ocsp-server.php: receiving data from " . $_SERVER['REMOTE_ADDR'] . "\n", 'info');
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  if ($_SERVER['CONTENT_TYPE'] != 'application/ocsp-request')
    throw new Exception("ocsp-server.php error(): wrong content-type - expected application/ocsp-request, received " . $_SERVER['CONTENT_TYPE'], 1);
  if ($log_level == LOG_DEBUG) 
    errorLog("ocsp-server.php: content-type http header has been verified: " . $_SERVER['CONTENT_TYPE'] . "\n", 'debug');
 
  $ocspRequest = file_get_contents('php://input');
  $len = strlen($ocspRequest);
  if ($_SERVER['CONTENT_LENGTH'] != $len)
    throw new Exception("ocsp-server.php error(): wrong content-length, calculated $len, received " . $_SERVER['CONTENT_LENGTH'], 1);
  if ($log_level == LOG_DEBUG) {
    errorLog("ocsp-server.php: verified that http header Content-Length was equaled to the actual data size: " . $_SERVER['CONTENT_LENGTH'] . "\n", 'debug');
    errorLog("ocsp-server.php: based64 encoded DER content is: " . base64_encode($ocspRequest), 'debug');
  }
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET') {
  $requestUri = explode('/', $_SERVER['REQUEST_URI']);
  $ocspRequest = urldecode(array_pop($requestUri));
  $ocspRequest = base64_decode($ocspRequest);
}
$request = new OCSPRequest();
$request->decode($ocspRequest);
if (! is_null($request->signature)) {
  if (is_null($request->tbsRequest->name))
    throw new Exception("ocsp-server.php error(): signed tbsRequest is missing name", 1);
  if (is_null($request->signature->certs))
    throw new Exception("ocsp-server.php error(): request signature is missing certs", 1);
  $signingCert = null;
  foreach($request->signature->certs as $cert) {
    if ($cert->tbsCertificate->subject == $request->tbsRequest->name) {
      $signingCert = $cert;
      break;
    }
  }
  if (is_null($signingCert))
    throw new Exception("ocsp-server.php error(): unable to find a signing certificate mathing tbsRequest name " . $request->tbsRequest->name, 1);
  $encoded = $request->tbsRequest->encode();
  $res = openssl_verify($encoded, hex2bin($request->signature->value), $signingCert->tbsCertificate->publicKey->subjectPublicKey, oid2str($signingCert->tbsCertificate->publicKey->algorithm));
  switch($res) {
    case 0: //invalid
      throw new Exception("Invalid certificate signature, serialNumber " . $cert->tbsCertificate->serialNumber . ", subject " . $cert->tbsCertificate->subject->toString(), 6);
    break;
    case 1: //valid, need to verify the validity dates and revocation status
      $validFrom = $cert->tbsCertificate->validity->notBefore2DateTime();
      $validTo = $cert->tbsCertificate->validity->notAfter2DateTime();
      if ($validFrom->diff($now)->format("%R") == '-') //not valid yet
        throw new Exception("notBefore $cert->tbsCertificate->validity->notBefore is in the future, serialNumber " . $cert->tbsCertificate->serialNumber . ", subject " . $cert->tbsCertificate->subject->toString(), 6);
      elseif ($validTo->diff($now)->format("%R") == '+') //already expired
        throw new Exception("notAfter $cert->tbsCertificate->validity->notAfter is in the past, serialNumber " . $cert->tbsCertificate->serialNumber . ", subject " . $this->tbsCertificate->subject->toString(), 6);
      //revocation status check - done by checking certs.db
      $certificate = sqlGetCert($cert->tbsCertificate->serialNumber);
      if (is_null($certificate))
        throw new Exception("Certificate with the serial number " . $cert->tbsCertificate->serialNumber . " and the subject " . $cert->tbsCertificate->subject->toString() . " is not found in the database", 6);
      switch($certificate['status']) {
        case 0: //valid
        break;
        case 1: //expired
          throw new Exception("Certificate with the serial number " . $cert->tbsCertificate->serialNumber . " and the subject " . $cert->tbsCertificate->subject->toString() . " has expired", 6);
        case -1: //revoked
          throw new Exception("Certificate with the serial number " . $cert->tbsCertificate->serialNumber . " and the subject " . $cert->tbsCertificate->subject->toString() . " is revoked. Revocation reason: " . $certificate['revocationReason'],6);
      }
    break;
    case -1: //error
      $error = "ocsp-server.php openssl_verify() error: ";
      while($err = openssl_error_string()) $error .= $err;
      throw new Exception($error, 6);
  }  
}

$internalCAsigningCert = new Certificate($signing_ca_der_path);
$dn = $internalCAsigningCert->tbsCertificate->subject->encode();
$subjectPublicKey = $internalCAsigningCert->tbsCertificate->publicKey->subjectPublicKey->encode();	
$responseData = new ResponseData();
sqlUpdateAllCerts();
foreach ($request->tbsRequest->requests->requests as $req) {
  $cert = sqlGetCert($req->reqCert->serialNumber);
  $response = new Response();
  $response->certID = clone $req->reqCert;
  if (is_null($cert)) { //non-issued certs may return "revoked" status, 
                        //we should do it because it is possible to request certs via backup CA in TDR or test CA in LAT and 
                        //therefore to have no record in production certs.db
    errorLog("ocsp-server.php info: a certificate with the sn " . $req->reqCert->serialNumber . " was not found in certs.db", 'info');
    $revInfo = new RevokedInfo();
    $revInfo->time = '19700101000000Z'; //this is a must for "non-issued" certs (see https://datatracker.ietf.org/doc/html/rfc6960#section-2.2)
    $revInfo->reason = 6; //onHold - same as above, we must also include Extended Revoked Definition extension (see https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.8)
    $response->certStatus = 1;
    $response->revInfo = $revInfo;
    $responseData->extensions = new Extensions();
    $ocspExtendedRevoke = new Extension();
    $ocspExtendedRevoke->setOCSPExtendedRevoke();
    $responseData->extensions->extensions[] = $ocspExtendedRevoke;
  } else {
    //besides serialNumber, we need to check our signing CA issuerKey and issuerName match those in the request
    //because the cert might have had the same serial but issued by a different authority
    //if it is the case, then we return status unknown (2)
    $issuerKeyHash = hash(oid2str($req->reqCert->hashAlg->algorithm), $subjectPublicKey, $binary = false);
    if (strncmp($issuerKeyHash, $req->reqCert->issuerKeyHash, strlen($issuerKeyHash)) != 0) {
      errorLog("ocsp-server.php error: issuerKeyHash $issuerKeyHash is not equaled req->reqCert->issuerKeyHash " . $req->reqCert->issuerKeyHash);  
      $response->certStatus = 2;
      $response->revInfo = null;
      continue; 
    }
    $issuerNameHash = hash(oid2str($req->reqCert->hashAlg->algorithm), $dn, $binary = false);
    if (strncmp($issuerNameHash, $req->reqCert->issuerNameHash, strlen($issuerNameHash)) != 0) {
      errorLog("ocsp-server.php error: issuerNameHash $issuerNameHash is not equaled req->reqCert->issuerNameHash " . $req->reqCert->issuerNameHash);  
      $response->certStatus = 2;
      $response->revInfo = null;
      continue; 
    }
    switch ($cert['status']) {
      case 0: //valid
        $response->certStatus = 0;    
        $response->revInfo = null;
      break;
      case 1: //expired
      break;
      case -1: //revoked
        $revInfo = new RevokedInfo();
        $revInfo->time = date_create_from_format("U", $cert['revocationDate'], new DateTimeZone("+0000"))->format("YmdHis") . 'Z';
        $revInfo->reason = $cert['revocationReason'];
        $response->certStatus = 1;
        $response->revInfo = $revInfo;
      break;
      case 2: //onHold
        $revInfo = new RevokedInfo();
        $revInfo->time = $cert['notBefore'];
        $revInfo->reason = 6; //onHold
        $response->certStatus = 1;
        $response->revInfo = $revInfo;
      break;
      default: //unknown
        $response->certStatus = 2;
        $response->revInfo = null;
    }
  }
  $responseData->responses[] = $response;
}
if (! is_null($request->tbsRequest->extensions)) {
  $nonce = $request->tbsRequest->extensions->getOCSPNonce();
  if ($nonce !== false) {
    if (is_null($responseData->extensions))
      $responseData->extensions = new Extensions();
    $responseData->extensions->extensions[] = clone $request->tbsRequest->extensions->extensions[$nonce];
  }
}
$basicOCSPResponse = new BasicOCSPResponse($responseData);
$responseBytes = new ResponseBytes($basicOCSPResponse);
$ocspResponse = new OCSPResponse(0);
$ocspResponse->responseBytes = $responseBytes;
$encoded = $ocspResponse->encode();
headers(strlen($encoded));
echo $encoded;
