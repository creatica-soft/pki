<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'helper_functions.php';
require_once 'algorithm_identifier.php';
require_once 'general_name.php';
require_once 'validity.php';
require_once 'subject_pubkey_info.php';
require_once 'extension.php';
require_once 'certification_request.php';

/*
CertTemplate ::= SEQUENCE {
 version [0] Version OPTIONAL,
 serialNumber [1] INTEGER OPTIONAL,
 signingAlg [2] AlgorithmIdentifier OPTIONAL,
 issuer [3] Name OPTIONAL,
 validity [4] OptionalValidity OPTIONAL,
 subject [5] Name OPTIONAL,
 publicKey [6] SubjectPublicKeyInfo OPTIONAL,
 issuerUID [7] UniqueIdentifier OPTIONAL,
 subjectUID [8] UniqueIdentifier OPTIONAL,
 extensions [9] Extensions OPTIONAL }

UniqueIdentifier ::= BIT STRING
*/

class CertTemplate {
  public $version;
  public $serialNumber;
  public $signingAlg;
  public $issuer;
  public $validity;
  public $subject;
  public $publicKey;
  public $issuerUID;
  public $subjectUID;
  public $extensions;

  function csr2template($csr, $role = 'standard', $acme = false) {
    global $min_key_size, $base_url;
    //validate csr signature
    $der = $csr->certificationRequestInfo->subjectPKInfo->encode();
    $pubkey = der2pem($der, 'PUBLIC KEY');
    $certificationRequestInfo = $csr->certificationRequestInfo->encode();
    $alg = 0;
    switch ($csr->signatureAlgorithm->algorithm) {
      case '1.2.840.113549.1.1.5': //sha1WithRSAEncryption
      case '1.2.840.10040.4.1': //dsaWithSha1
      case '1.2.840.10045.4.1': //ecdsaWithSha1
        $alg = OPENSSL_ALGO_SHA1;
      break;
      case '1.2.840.113549.1.1.11': //sha256WithRSAEncryption
      case '1.2.840.10045.4.3.2': //ecdsa-with-SHA256
      case '2.16.840.1.101.3.4.3.2': //dsaWithSha256
        $alg = OPENSSL_ALGO_SHA256;
      break;
      case '2.16.840.1.101.3.4.3.1': //dsaWithSha224
        $alg = OPENSSL_ALGO_SHA224;
      break;
      default:
        throw new Exception("CertTemplate::csr2template() error: unknown signature algorithm " . $csr->signatureAlgorithm->algorithm);
    }
    $res = openssl_verify($certificationRequestInfo, hex2bin($csr->signature), $pubkey, $alg);
    switch($res) {
      case 0: //invalid
        throw new Exception("CertTemplate::csr2template() error: invalid csr signature, subject " . $csr->certificationRequestInfo->subject);
      break;
      case 1: //valid
      break;
      case -1: //error
        $error = "CertTemplate::csr2template() error: ";
        while($err = openssl_error_string()) $error .= $err;
        throw new Exception($error);
    }
    $this->signingAlg = clone $csr->signatureAlgorithm;
    $this->subject = clone $csr->certificationRequestInfo->subject;
    $this->publicKey = clone $csr->certificationRequestInfo->subjectPKInfo;
    switch($this->publicKey->algorithm->algorithm) {
      case '1.2.840.113549.1.1.1': //rsaEncryption
      break;
      case '1.2.840.10040.4.1': //DSA
      break;
      case '1.2.840.10045.2.1': //EC
      break;
      default:
        throw new Exception("CertTemplate::csr2template() error: unknown key algorithm " . $this->publicKey->algorithm->algorithm . " for subject " . $this->subject);  
    }
    if (! is_null($csr->certificationRequestInfo->attributes)) {
      foreach($csr->certificationRequestInfo->attributes->attributes as $attribute) {
        if ($attribute->type == '1.2.840.113549.1.9.14' && key_exists(0, $attribute->values) && $attribute->values[0] instanceof Extensions) {
          $this->extensions = clone $attribute->values[0];
        } 
      }
    }
    //add cn from subject to SANs if it's not there
    $sans = false;
    if (! is_null($this->extensions))
      $sans = $this->extensions->checkSubjectAltName($role, $acme);
    else {
      $this->extensions = new Extensions();
    }
    if (! $sans) $sans = array();
    $cn = $this->subject->getCN();
    if ($cn) {
      if (! in_array($cn, $sans)) {
        if (! $acme && ! check_cn($cn, $role))
          throw new Exception("CertTemplate::csr2template() error: unaccepted SAN extension: CN $cn in the cert template subject is not from the list of approved domains: $base_url/domains.txt");
        $sans[] = new GeneralName($cn);
        $this->extensions->setSubjectAltName($sans);
      }
    }
  }

//cert template uses implicit tagging, meaning that context-specific class is masking the enclosing type
  function encode() {
    $cert = '';
    if (! is_null($this->version)) {
      $encoded = encode($type = INTEGER, $value = $this->version);
      $cert .= asn1encode($class = 2, $constructed = false, $type = 0, $value = $encoded);
    }
    if (! is_null($this->serialNumber)) {
      // this optional INTEGER is encoded as primitive context-specific type because of implicit tagging masking the INTEGER type
      // as oppose to constructed context-specific type, which would allow decoding data without explicit knowledge of the data
      $encoded = encode($type = INTEGER, $value = $this->serialNumber);
      $cert .= asn1encode($class = 2, $constructed = false, $type = 1, $value = $encoded);
    }
    if (! is_null($this->signingAlg))
      $cert .= asn1encode($class = 2, $constructed = true, $type = 2, $value = $this->signingAlg->encode($implicit = true));
    if (! is_null($this->issuer))
      $cert .= asn1encode($class = 2, $constructed = true, $type = 3, $value = $this->issuer->encode($implicit = false));
    if (! is_null($this->validity))
      $cert .= asn1encode($class = 2, $constructed = true, $type = 4, $value = $this->validity->encode($implicit = true));
    if (! is_null($this->subject))
      $cert .= asn1encode($class = 2, $constructed = true, $type = 5, $value = $this->subject->encode($implicit = false));
    if (! is_null($this->publicKey)) {
      $cert .= asn1encode($class = 2, $constructed = true, $type = 6, $value = $this->publicKey->encode($implicit = true));
    }
    if (! is_null($this->issuerUID))
      $cert .= asn1encode($class = 2, $constructed = false, $type = 7, $value = $this->issuerUID);
    if (! is_null($this->subjectUID))
      $cert .= asn1encode($class = 0, $constructed = false, $type = 8, $value = $this->subjectUID);
    if (! is_null($this->extensions))
      $cert .= asn1encode($class = 2, $constructed = true, $type = 9, $value = $this->extensions->encode($implicit = true));
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $cert);
  }
  
  function decode($certTemplate) {
    $iter = 0;
    $decoded = asn1decode($certTemplate);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certTemplate = $decoded['value'];
    else
      throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertTemplate, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($certTemplate) > 2) {
      $decoded = asn1decode($certTemplate);
      if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS) {
        switch($decoded['type']) {
          case 0: //version
            if (! $decoded['constructed'])
              $this->version = decode(INTEGER, $decoded['value']);
            else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS primitive class type 0, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 1: //serialNumber
            if (! $decoded['constructed'])
              $this->serialNumber = decode(INTEGER, $decoded['value']);
            else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS primitive class type 1, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 2: //signingAlg
            if ($decoded['constructed']) {
              $this->signingAlg = new AlgorithmIdentifier();
              $this->signingAlg->decode($decoded['value'], $implicit = true);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 2, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 3: //issuer
            if ($decoded['constructed']) {
              $this->issuer = new Name();
              $this->issuer->decode($decoded['value']);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 3, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 4: //validity
            if ($decoded['constructed']) {
              $this->validity = new Validity();
              $this->validity->decode($decoded['value']);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 4, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 5: //subject
            if ($decoded['constructed']) {
              $this->subject = new Name();
              $this->subject->decode($decoded['value']);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 5, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 6: //publicKey
            if ($decoded['constructed']) {
              $this->publicKey = new SubjectPublicKeyInfo();
              $this->publicKey->decode($decoded['value'], $implicit = true);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 6, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 7: //issuerUID
            if (! $decoded['constructed'])
              $this->issuerUID = decode(BIT_STRING, $decoded['value']);
            else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS primitive class type 7, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 8: //subjectUID
            if (! $decoded['constructed'])
              $this->subjectUID = decode(BIT_STRING, $decoded['value']);
            else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS primitive class type 8, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          case 9: //extensions
            if ($decoded['constructed']) {
              $this->extensions = new Extensions();
              $this->extensions->decode($decoded['value'], $implicit = true);
            } else
              throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class type 9, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          break;
          default:
            throw new Exception("CertTemplate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class types from 0 to 9, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        }
      }
      $certTemplate = substr($certTemplate, $decoded['length'] + $decoded['hl']);
      if ($iter > 9)
        throw new Exception("CertTemplate::decode() error: string is too long");
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $version = null;
    $serialNumber = null;
    $signingAlg = null;
    $issuer = null;
    $validity = null;
    $subject = null;
    $publicKey = null;
    $issuerUID = null;
    $subjectUID = null;
    $extensions = null;
  }

  function __clone() {
    if (! is_null($this->signingAlg))
      $this->signingAlg = clone $this->signingAlg;
    if (! is_null($this->issuer))
      $this->issuer = clone $this->issuer;
    if (! is_null($this->validity))
      $this->validity = clone $this->validity;
    if (! is_null($this->subject))
      $this->subject = clone $this->subject;
    if (! is_null($this->publicKey))
      $this->publicKey = clone $this->publicKey;
    if (! is_null($this->extensions))
      $this->extensions = clone $this->extensions;
  }
}
