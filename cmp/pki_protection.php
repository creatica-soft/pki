<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'helper_functions.php';
require_once 'globals.php';

/*
PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
     }
     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

PKIProtection ::= BIT STRING

   The input to the calculation of PKIProtection is the DER encoding of
   the following data structure:

        ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
*/

class PKIProtection {
  public $value;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->value);
    return asn1encode($class = 2, $constructed = true, $type = 0, $value = $encoded);
  }

  function decode($value) {
    $decoded = asn1decode($value);
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
      $this->value = $decoded['value'];
    else
      throw new Exception("PKIProtection::decode() error: bad message check: expected an ASN.1 BIT_STRING for PKIProtection, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    return $decoded['length'] + $decoded['hl'];
  }

  //calculate BASEKEY as a symmetric key for HMAC algorithm using the method described in RFC4210
  private function getBaseKey($alg, $iterCount, $secret, $salt) {
    $alg = oid2str($alg);
    $basekey = openssl_digest($secret . hex2bin($salt), $alg, true);
    for ($i = 1; $i < $iterCount; $i++)
      $basekey = openssl_digest($basekey, $alg, true);
    return $basekey;
  }

  // try to verify a signature hold in $this->value against $content using $algId and the $signingCert as a Certificate object
  // returns true or false, throw Exception on error
  private function verifySignature($content, $algId, $signingCert) {
    //PEM format requires headers and must be 64-char long strings terminated with \r\n -- see rfc7468
    $der = $signingCert->encode();
    $signingCert = der2pem($der, 'CERTIFICATE');
    while (openssl_error_string());
    $cert = openssl_x509_read($signingCert);
    if (! $cert) {
      $error = "PKIProtection::verifySignature() openssl x509 read error: ";
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception($error, SYSTEM_FAILURE);
    }
    $res = openssl_verify($content, hex2bin($this->value), $cert, $algId);
    openssl_x509_free($cert);
    switch($res) {
      case 0: return false; //signature is invalid
      case 1: return true; //signature is valid
      default:
        $error = "PKIProtection::verifySignature() openssl verify error: ";
        while ($err = $statusStrings[] = openssl_error_string()) $error .= $err;
        throw new Exception($error, SYSTEM_FAILURE);
    }
  }

  private function sign($privKeyPEMfile, $content, $algId) {
    if (! file_exists($privKeyPEMfile))
      throw new Exception("PKIProtection::sign() error: file $privKeyPEMfile does not exist", SYSTEM_FAILURE);
    $privkey = file_get_contents($privKeyPEMfile);
    if (! $privkey)
      throw new Exception("PKIProtection::sign() file_get_contents() error opening a file $privKeyPEMfile", SYSTEM_FAILURE);
    while (openssl_error_string());
    $res = openssl_sign($content, $value, $privkey, $algId);
    if (! $res) {
      $error = "PKIProtection::sign() openssl sign error: ";
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception($error, SYSTEM_FAILURE);
    }
    return bin2hex($value);
  }

  function validate($secret = null, $signingCert = null) {
    global $request;
    $header_body = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $request->header->encode() . $request->body->encode());
    switch($request->header->protectionAlg->algorithm) {
      case '1.2.840.113533.7.66.13': //shared secret
        $basekey = $this->getBaseKey($request->header->protectionAlg->parameters->owf->algorithm, $request->header->protectionAlg->parameters->iterationCount, $secret, $request->header->protectionAlg->parameters->salt);
        //calculate HMAC hash using BASEKEY over pkiHeader + pkiBody in DER
        $alg = oid2str($request->header->protectionAlg->parameters->mac->algorithm);
        $alg = explode('-', $alg)[1]; //hmac-sha1, hmac-sha256
        $protection = hash_hmac($alg, $header_body, $basekey, $binary = false);

        //compare calculated HMAC hash or signature with the one obtained from the pkiMessage
        $res = strcmp($protection, $this->value);
        
        //if they are equal, then return true; otherwise, return false
        if ($res == 0) return true;
      break;
      case '1.2.840.10040.4.3': //dsa-with-SHA1
      case '1.2.840.113549.1.1.5': //sha1WithRSAEncryption
      case '1.2.840.10045.4.1': //ecdsa-with-SHA1
        return $this->verifySignature($header_body, OPENSSL_ALGO_SHA1, $signingCert);
      break;
      case '2.16.840.1.101.3.4.3.2': //dsa-with-SHA256
      case '1.2.840.113549.1.1.11': //sha256WithRSAEncryption
      case '1.2.840.10045.4.3.2': //ecdsa-with-SHA256
        return $this->verifySignature($header_body, OPENSSL_ALGO_SHA256, $signingCert);
      break;
      case '1.2.840.113533.7.66.30': //DHBasedMac
        throw new Exception('DHBasedMac PKI message protection algorithm is not supported', BAD_ALG);
      default:
        throw new Exception("Unknown protection algorithm " . $request->header->protectionAlg->algorithm, BAD_ALG);
    }
    return false;
  }

  function protect($header, $body, $secret = null) {
    global $signing_ca_privkey_path;
    $header_body = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $header->encode() . $body->encode());
    switch($header->protectionAlg->algorithm) {
      case '1.2.840.113533.7.66.13':
        if (is_null($secret))
          throw new Exception("Password-based HMAC algorithm requires a shared secret but it is null", BAD_ALG);
        $basekey = $this->getBaseKey($header->protectionAlg->parameters->owf->algorithm, $header->protectionAlg->parameters->iterationCount, $secret, $header->protectionAlg->parameters->salt);

        //calculate HMAC hash using BASEKEY over pkiHeader + pkiBody in DER
        $this->value = hash_hmac(oid2str($header->protectionAlg->parameters->mac->algorithm), $header_body, $basekey, $binary = false);
      break;
      case '1.2.840.113549.1.1.5': //sha1WithRSAEncryption
        $this->value = $this->sign($signing_ca_privkey_path, $header_body, OPENSSL_ALGO_SHA1);
      break;
      case '1.2.840.113549.1.1.11': //sha256WithRSAEncryption
        $this->value = $this->sign($signing_ca_privkey_path, $header_body, OPENSSL_ALGO_SHA256);
      break;
      case '1.2.840.113533.7.66.30': //DHBasedMac
        throw new Exception('PKIProtection::protect() error: DHBasedMac PKI message protection algorithm is not supported', BAD_ALG_ID);
      default:
        $this->value = $this->sign($signing_ca_privkey_path, $header_body, oid2str($header->protectionAlg->algorithm));
    }
  }

  function __construct() {
    $this->value = null;
  }
}

?>