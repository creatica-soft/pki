<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'general_name.php';

/*
//in order to verify integrity of self-signed certs, this hash structure is used
OOBCertHash ::= SEQUENCE {
            hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
            certId      [1] CertId                  OPTIONAL,
            hashVal         BIT STRING
        }
id-regCtrl-oldCertID           OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.5 }
   CertId ::= SEQUENCE {
         issuer           GeneralName,
         serialNumber     INTEGER
     }
*/

class CertHash {
  public $hashAlg;
  public $certId;
  public $hashValue;

  function encode() {
    $encoded = '';
    if (! is_null($this->hashAlg)) {
      $hashAlg = $this->hashAlg->encode();
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $hashAlg);
    }
    if (! is_null($this->certId)) {
      $certId = $this->certId->encode();
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $certId);
    }
    $encoded .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->hashValue);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct($certificate = null, $hashAlg = 'sha1') {
    $this->hashAlg = new AlgorithmIdentifier($hashAlg);
    if (! is_null($certificate)) {
      $cert = new Certificate();
      $cert->decode($certificate);
      $this->certId = new CertId();
      $this->certId->issuer = clone $cert->tbsCertificate->issuer;
      $this->certId->serialNumber = $cert->tbsCertificate->serialNumber;
      $this->hashValue = hash($hashAlg, $cert->encode());
    } else $this->certId = null;
  }
}

class CertId {
  public $issuer;
  public $serialNumber;

  function encode() {
    $seq = $this->issuer->encode();
    $seq .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->serialNumber);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $seq); 
  }

  function decode($certId) {
    $iter = 0;
    $decoded = asn1decode($certId);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certId = $decoded['value'];
    else
      throw new Exception("CertId::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertId, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($certId) > 2) {
      switch($iter) {
        case 0: //issuer
          $this->issuer = new GeneralName();
          $next = $this->issuer->decode($certId);
        break;
        case 1: //serialNumber
          $decoded = asn1decode($certId);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->serialNumber = $decoded['value'];
          else
            throw new Exception("CertId::decode() error: bad message check: expected an ASN.1 INTEGER for serialNumber, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          $next = $decoded['length'] + $decoded['hl'];
        break;
      }
      $certId = substr($certId, $next);
      $iter++;
    }
    return $offset;
  }
}

/*
   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
*/

class CertificateID {
  public $hashAlg; //AlgorithmIdentifier
  public $issuerNameHash; //OCTET STRING, -- Hash of issuer's DN
  public $issuerKeyHash; //OCTET STRING, -- Hash of issuer's public key
  public $serialNumber; //CertificateSerialNumber 

  function encode() {
    $encoded = $this->hashAlg->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->issuerNameHash);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->issuerKeyHash);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->serialNumber);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($certID) {
    $decoded = asn1decode($certID);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certID = $decoded['value'];
    else
      throw new Exception("CertID::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertID, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
    $offset = $decoded['length'] + $decoded['hl'];
    $iter = 0;
    while (strlen($certID) > 2) {
      switch($iter) {
        case 0:
          $this->hashAlg = new AlgorithmIdentifier();
          $next = $this->hashAlg->decode($certID);
        break;
        case 1:
          $decoded = asn1decode($certID);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
            $this->issuerNameHash = $decoded['value'];
          else
            throw new Exception("CertID::decode() error: bad message check: expected an ASN.1 OCTET_STRING for CertID issuerNameHash, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 2:
          $decoded = asn1decode($certID);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
            $this->issuerKeyHash = $decoded['value'];
          else
            throw new Exception("CertID::decode() error: bad message check: expected an ASN.1 OCTET_STRING for CertID issuerKeyHash, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 3:
          $decoded = asn1decode($certID);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->serialNumber = $decoded['value'];
          else
            throw new Exception("CertID::decode() error: bad message check: expected an ASN.1 INTEGER for CertID serialNumber, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 1);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        default:
          throw new Exception("CertID::decode() error: bad message check: string is too long", 1);
      }
      $certID = substr($certID, $next);
      $iter++;
    }
    return $offset;    
  }
  
  function __clone() {
    $this->hashAlg = clone $this->hashAlg;
  }
}

?>