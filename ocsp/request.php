<?php
require_once 'asn1_types.php';
require_once 'helper_functions.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'extension.php';
require_once 'general_name.php';
require_once 'algorithm_identifier.php';
require_once 'certificate.php';
require_once 'globals.php';
require_once 'cert_id.php';

/*
OCSPRequest     ::=     SEQUENCE {
       tbsRequest                  TBSRequest,
       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

   TBSRequest      ::=     SEQUENCE {
       version             [0]     EXPLICIT Version DEFAULT v1,
       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
       requestList                 SEQUENCE OF Request,
       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

   Signature       ::=     SEQUENCE {
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING,
       certs               [0] EXPLICIT SEQUENCE OF Certificate
   OPTIONAL}

   Version         ::=             INTEGER  {  v1(0) }

   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }

   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
*/


class Signature {
  public $alg; //AlgorithmIdentifier
  public $value; //BIT_STRING
  public $certs; //[0] EXPLICIT SEQUENCE OF Certificate

  function encode() {
    $encoded = $this->alg->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = $this->value);
    if (! is_null($this->certs))
      $encoded .= $this->certs->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
 
  function decode($signature) {
    $decoded = asn1decode($request);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $signature = $decoded['value'];
    else
      throw new Exception("Request::decode() error: bad message check: expected an ASN.1 SEQUENCE for Request, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    $iter = 0;
    while (strlen($signature) > 2) {
      switch($iter) {
        case 0:
          $this->alg = new AlgorithmIdentifier();
          $next = $this->alg->decode($request);
        break;
        case 1:
          $decoded = asn1decode($signature);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
            $this->value = $decoded['value'];
          else
            throw new Exception("Signature::decode() error: bad message check: expected an ASN.1 BIT_STRING for Signature value, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 2:
          $this->extensions = new Extensions();
          $next = $this->extensions->decode($signature, $implicit = true);
        break;
        default:
          throw new Exception("Signature::decode() error: bad message check: string is too long", 1);
      }
      $signature = substr($signature, $next);
      $iter++;
    }
    return $offset;    
  }
}

class Request {
  public $reqCert;  //CertificateID
  public $extensions; //[0] EXPLICIT Extensions OPTIONAL

  function encode() {
    $encoded = $this->reqCert->encode();
    if (! is_null($this->extensions))
      $encoded .= $this->extensions->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
 
  function decode($request) {
    $decoded = asn1decode($request);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $request = $decoded['value'];
    else
      throw new Exception("Request::decode() error: bad message check: expected an ASN.1 SEQUENCE for Request, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    $iter = 0;
    while (strlen($request) > 2) {
      switch($iter) {
        case 0:
          $this->reqCert = new CertificateID();
          $next = $this->reqCert->decode($request);
        break;
        case 1:
          $this->extensions = new Extensions();
          $next = $this->extensions->decode($request, $implicit = true);     
        break;
        default:
          throw new Exception("Request::decode() error: bad message check: string is too long", 1);
      }
      $request = substr($request, $next);
      $iter++;
    }
    return $offset;    
  }
}

class Requests {
  public $requests;

  function encode() {
    $encoded = '';
    foreach ($this->requests as $request)
      $encoded .= $request->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
 
  function decode($requests) {
    $decoded = asn1decode($requests);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $requests = $decoded['value'];
    else
      throw new Exception("Requests::decode() error: bad message check: expected an ASN.1 SEQUENCE for Requests, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($requests) > 2) {
      $req = new Request();
      $next = $req->decode($requests);
      $this->requests[] = $req;
      $requests = substr($requests, $next);
    }
    return $offset;    
  }
  
  function __construct() {
    $this->requests = array();
  }

}

class TBSRequest {
  public $version; //[0]     EXPLICIT Version DEFAULT v1
  private $versionExplicit; //BOOLEAN - whether version is explicitly present in TBSRequest
  public $name; //[1]     EXPLICIT GeneralName OPTIONAL
  public $requests; //SEQUENCE OF Request
  public $extensions; //[2]     EXPLICIT Extensions OPTIONAL

  function encode() {
    $encoded = '';
    if ($this->versionExplicit) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
      $encoded = asn1encode($class = 2, $constructed = true, $type = 0, $value = $encoded);
    }
    if (! is_null($this->name))
      $decoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $this->name->encode());
    $encoded .= $this->requests->encode();
    if (! is_null($this->extensions))
      $decoded .= asn1encode($class = 2, $constructed = true, $type = 2, $value = $this->extensions->encode());
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $decoded);
  }

  function decode($request) {
    $iter = 0;
    $decoded = asn1decode($request);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $request = $decoded['value'];
    else
      throw new Exception("TBSRequest::decode() error: bad message check: expected an ASN.1 SEQUENCE for TBSRequest, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($request) > 2) {
      $decoded = asn1decode($request);
      if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed']) {
        $next = $decoded['length'] + $decoded['hl'];
        switch($decoded['type']) {
          case 0: //version
            $decoded = asn1decode($request);
            if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
              $this->version = $decoded['value'];
              $this->versionExplicit = true;
            } else
              throw new Exception("TBSRequest::decode() error: bad message check: expected an ASN.1 INTEGER for TBSRequest version, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          break;
          case 1: //name
            $this->name = new GeneralName();
            $this->name->decode($decoded['value']);
          break;
          case 2: //extensions
            $this->extensions = new Extensions();
            $this->extensions->decode($decoded['value'], $implicit = false);
          break;
          default:
            throw new Exception("TBSRequest::decode() error: bad message check: string is too long", 1);
        }
      } else {
        $this->requests = new Requests();
        $next = $this->requests->decode($request);
      }
      $request = substr($request, $next);
      $iter++;
    }
    return $offset;    
  }
 
  function __construct() {
    $this->version = 0; //v1 default
    $this->versionExplicit = false;
    $this->name = null;
    $this->extensions = null;
  }
}

class OCSPRequest {
  public $tbsRequest; //TBSRequest
  public $signature; //[0]     EXPLICIT Signature OPTIONAL

  function encode() {
    $encoded = $this->tbsRequest->encode();
    if (! is_null($this->signature)) 
      $encoded .= $this->signature->encode();
    return asn1encode($class = 0, $constructed = 1, $type = SEQUENCE, $value = $encoded);
  }

  function decode($request) {
    $iter = 0;
    $decoded = asn1decode($request);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $request = $decoded['value'];
    else
      throw new Exception("OCSPRequest::decode() error: bad message check: expected an ASN.1 SEQUENCE for OCSPRequest, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($request) > 2) {
      switch($iter) {
        case 0: //tbsRequest
          $this->tbsRequest = new TBSRequest();
          $next = $this->tbsRequest->decode($request);
        break;
        case 1: //signature
          $this->signature = new Signature();
          $next = $this->signature->decode($request);
        break;
        default:
          throw new Exception("OCSPRequest::decode() error: bad message check: string is too long", 1);
      }
      $request = substr($request, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->signature = null;
  }
}
