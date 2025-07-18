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

/*
   OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

   OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  -- Response has valid confirmations
       malformedRequest      (1),  -- Illegal confirmation request
       internalError         (2),  -- Internal error in issuer
       tryLater              (3),  -- Try again later
                                   -- (4) is not used
       sigRequired           (5),  -- Must sign the request
       unauthorized          (6)   -- Request unauthorized
   }
   The value for responseBytes consists of an OBJECT IDENTIFIER and a
   response syntax identified by that OID encoded as an OCTET STRING.

   ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING }

   For a basic OCSP responder, responseType will be id-pkix-ocsp-basic.

   id-pkix-ocsp           OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1 }
   id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1.1 }

   The value for response SHALL be the DER encoding of
   BasicOCSPResponse.

   BasicOCSPResponse       ::= SEQUENCE {
      tbsResponseData      ResponseData,
      signatureAlgorithm   AlgorithmIdentifier,
      signature            BIT STRING,
      certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

   The value for signature SHALL be computed on the hash of the DER
   encoding of ResponseData.  The responder MAY include certificates in
   the certs field of BasicOCSPResponse that help the OCSP client verify
   the responder's signature.  If no certificates are included, then
   certs SHOULD be absent.

   ResponseData ::= SEQUENCE {
      version              [0] EXPLICIT Version DEFAULT v1,
      responderID              ResponderID,
      producedAt               GeneralizedTime,
      responses                SEQUENCE OF SingleResponse,
      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

   ResponderID ::= CHOICE {
      byName               [1] Name,
      byKey                [2] KeyHash }

   KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
   (excluding the tag and length fields)

   SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }

   CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }

   RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

   CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }

   UnknownInfo ::= NULL
*/

class RevokedInfo {
  public $time; //GeneralizedTime
  public $reason; //[0]     EXPLICIT CRLReason OPTIONAL

  function encode($implicit = false) {
    $encoded = asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->time);
    if (! is_null($this->reason)) {
      $reason = asn1encode($class = 0, $constructed = false, $type = ENUMERATED, $value = $this->reason);
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $reason);
    }
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct() {
    $this->reason = null;
  }
}

class Response {
  public $certID; //CertificateID
  public $certStatus; //0 - good, 1 - revoked or 2 - unknown
  public $revInfo; //if $certStatus == 1
  public $thisUpdate; //GeneralizedTime
  public $nextUpdate; //[0]       EXPLICIT GeneralizedTime OPTIONAL
  public $extensions; //[1]       EXPLICIT Extensions OPTIONAL

  function encode() {
    $encoded = $this->certID->encode();
    switch($this->certStatus) {
      case 0:
        $encoded .= asn1encode($class = 2, $constructed = false, $type = 0, $value = '');
      break;
      case 1:
        $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $this->revInfo->encode($implicit = true));
      break;
      case 2:
        $encoded .= asn1encode($class = 2, $constructed = false, $type = 2, $value = '');
      break;
    }
    $encoded .= asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->thisUpdate);
    if (! is_null($this->nextUpdate))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->nextUpdate);
    if (! is_null($this->extensions))
      $encoded .= $this->extensions->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function __construct() {
    global $now;
    $this->thisUpdate = $now->format("YmdHis") . 'Z';
    $this->nextUpdate = null;
    $this->extensions = null;
  }
}

class ResponseData {
  public $version; //[0] explicit
  public $responderID; //choice of name [1] or pubkey hash [2] (sha-1)
  public $producedAt; //GeneralizedTime
  public $responses; //SEQUENCE of Response
  public $extensions; //[1] explicit

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->responderID);
    $encoded = asn1encode($class = 2, $constructed = true, $type = 2, $value = $encoded);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = GENERALIZED_TIME, $value = $this->producedAt);
    $responses = '';
    foreach($this->responses as $response)
      $responses .= $response->encode();
    $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $responses);
    if (! is_null($this->extensions))
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $this->extensions->encode());
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct() {
    global $signing_ca_der_path, $now;
    $this->version = 0; //default v1
    $this->extensions = null;
    $signingCert = new Certificate($signing_ca_der_path);
    $this->responderID = bin2hex(hash('sha1', $signingCert->tbsCertificate->publicKey->subjectPublicKey->encode(), $binary = true));
    $this->producedAt = $now->format("YmdHis") . 'Z';
    $this->responses = array();
  }
}

class BasicOCSPResponse {
  public $responseData; //ResponseData
  public $signatureAlg; //AlgorithmIdentifier
  public $signature; //BIT_STRING
  public $certs; //[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL

  function encode() {
    $encoded = $this->responseData->encode();
    $this->sign($encoded);
    $encoded .= $this->signatureAlg->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->signature);
    if (! is_null($this->certs)) {
      $certs = '';
      foreach ($this->certs as $cert)
        $certs .= $cert->encode();
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $certs);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  private function sign($encoded) {
    global $signing_ca_privkey_path;

    while(openssl_error_string());
    $res = openssl_sign($encoded, $signature, file_get_contents($signing_ca_privkey_path), oid2str($this->signatureAlg->algorithm));
    if (! $res) {
      $error = "BasicOCSPResponse::sign() openssl_sign error: ";
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception($error, 2);
    }
    $this->signature = bin2hex($signature);
  }

  function __construct($responseData) {
    global $default_signing_alg;
    $this->responseData = $responseData;
    $this->signatureAlg = new AlgorithmIdentifier($default_signing_alg);
    $this->signatureAlg->explicitNullParameters = true;
    $this->certs = null;
  }
}

class ResponseBytes {
  public $responseType;
  public $response;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->responseType);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->response);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct($basicOCSPResponse) {
    $this->responseType = '1.3.6.1.5.5.7.48.1.1';
    if (! is_null($basicOCSPResponse) && is_object($basicOCSPResponse) && $basicOCSPResponse instanceof BasicOCSPResponse)
      $this->response = bin2hex($basicOCSPResponse->encode());
    else {
      $error = "ResponseBytes::__construct() error: an argument is not an instance of BasicOCSPResponse class";
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception($error, 2);
    }
  }
}

class OCSPResponse {
  public $responseStatus;
  public $responseBytes; //[0] EXPLICIT ResponseBytes OPTIONAL

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = ENUMERATED, $value = $this->responseStatus);
    if (! is_null($this->responseBytes))
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $this->responseBytes->encode());
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct($status) {
    $this->responseStatus = $status;
    $this->responseBytes = null;
  }
}
