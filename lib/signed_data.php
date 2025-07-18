<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'general_name.php';
require_once 'helper_functions.php';

/*
PKCS #7 from https://datatracker.ietf.org/doc/html/rfc2315

ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content
       [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

ContentType ::= OBJECT IDENTIFIER

pkcs-7 OBJECT IDENTIFIER ::=
     { iso(1) member-body(2) US(840) rsadsi(113549)
         pkcs(1) 7 }
signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }

Simple PKI responses contains just base64 encoded SingedData. Despite the name, it is actually unsigned! Hence,
both encapContentInfo and signerInfos must be absent (or empty sequence and set?) in simple PKI responses (see https://datatracker.ietf.org/doc/html/rfc5272#section-4.1)
and digestAlgorithms I think is just an empty SET or perhaps absent too?

from https://datatracker.ietf.org/doc/html/rfc5652 (PKCS #7)

SignedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithms DigestAlgorithmIdentifiers,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SignerInfos }

DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier 0..MAX
SignerInfos ::= SET OF SignerInfo 0..MAX

SignerInfo ::= SEQUENCE {
     version CMSVersion,
     sid SignerIdentifier,
     digestAlgorithm DigestAlgorithmIdentifier,
     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
     signatureAlgorithm SignatureAlgorithmIdentifier,
     signature SignatureValue,
     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

    If the SignerIdentifier is the CHOICE issuerAndSerialNumber, then the version MUST be 1. 
    If the SignerIdentifier is subjectKeyIdentifier, then the version MUST be 3.
      
   SignerIdentifier ::= CHOICE {
        issuerAndSerialNumber IssuerAndSerialNumber,
        subjectKeyIdentifier [0] SubjectKeyIdentifier }

   IssuerAndSerialNumber ::= SEQUENCE {
        issuer Name,
        serialNumber CertificateSerialNumber }

      CertificateSerialNumber ::= INTEGER

   SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

   UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

   Attribute ::= SEQUENCE {
        attrType OBJECT IDENTIFIER,
        attrValues SET OF AttributeValue }

   AttributeValue ::= ANY

   SignatureValue ::= OCTET STRING


   EncapsulatedContentInfo ::= SEQUENCE {
        eContentType ContentType,
        eContent [0] EXPLICIT OCTET STRING OPTIONAL }

      ContentType ::= OBJECT IDENTIFIER
   
From https://www.ietf.org/rfc/rfc3852.txt:

   The optional omission of the eContent within the
   EncapsulatedContentInfo field makes it possible to construct
   "external signatures."  In the case of external signatures, the
   content being signed is absent from the EncapsulatedContentInfo value
   included in the signed-data content type.  If the eContent value
   within EncapsulatedContentInfo is absent, then the signatureValue is
   calculated and the eContentType is assigned as though the eContent
   value was present.

   In the degenerate case where there are no signers, the
   EncapsulatedContentInfo value being "signed" is irrelevant.  In this
   case, the content type within the EncapsulatedContentInfo value being
   "signed" MUST be id-data:
   
   id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 },
   
   and the content field of the EncapsulatedContentInfo value MUST be omitted.

   The message digest is computed over the octets comprising the value of the OCTET STRING,
   neither the tag nor length octets are included.

   
CMSversion in SignedData should probably be 4

 version is the syntax version number.  The appropriate value
      depends on certificates, eContentType, and SignerInfo.  The
      version MUST be assigned as follows:

         IF ((certificates is present) AND
            (any certificates with a type of other are present)) OR
            ((crls is present) AND
            (any crls with a type of other are present))
         THEN version MUST be 5
         ELSE
            IF (certificates is present) AND
               (any version 2 attribute certificates are present)
            THEN version MUST be 4
            ELSE
               IF ((certificates is present) AND
                  (any version 1 attribute certificates are present)) OR
                  (any SignerInfo structures are version 3) OR
                  (encapContentInfo eContentType is other than id-data)
               THEN version MUST be 3
               ELSE version MUST be 1

From https://datatracker.ietf.org/doc/html/rfc7030#section-4.1.3 (EST)
The HTTP content-type of "application/pkcs7-mime" is used. 
The Simple PKI Response is sent with a Content-Transfer-Encoding of "base64"
*/

class IssuerAndSerialNumber {
  public $issuer; //Name
  public $serialNumber; //INTEGER
  
  function encode() {
    $encoded = $this->issuer->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->serialNumber);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($issuerAndSerialNumber) {
    //file_put_contents('/tmp/issuerAndSerialNumber.der', $issuerAndSerialNumber);
    $decoded = asn1decode($issuerAndSerialNumber);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $issuerAndSerialNumber = $decoded['value'];
    else
      throw new Exception("IssuerAndSerialNumber::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for SignedAttributes, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    $iter = 0;
    while (strlen($issuerAndSerialNumber) >= 2) {
      switch ($iter) {
        case 0:
          $this->issuer = new Name();
          $next = $this->issuer->decode($decoded['value']);  
        break;
        case 1:
          $decoded = asn1decode($issuerAndSerialNumber);
          $next = $decoded['hl'] + $decoded['length'];
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->serialNumber = $decoded['value'];
          } else
            throw new Exception("IssuerAndSerialNumber::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for serialNumber, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("IssuerAndSerialNumber::decode() error: bad message check: expected an ASN.1 data too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));            
      }
      $issuerAndSerialNumber = substr($issuerAndSerialNumber, $next);
      $iter++;
    }
    return $offset;
  }
  
  function __construct($issuer = null, $serialNumber = null) {
    $this->issuer = $issuer;
    $this->serialNumber = $serialNumber;
  }
}

class SignedAttribute {
  public $type;
  public $values; //SET of values
  
  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->type);
    $set = '';
    foreach($this->values as $val) {
      switch ($this->type) {
        case '1.2.840.113549.1.9.3': //content-type
          $set .= asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $val);
        break;
        case '1.2.840.113549.1.9.4': //message-digest
          $set .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $val);
        break;
        default:
          throw new Exception("SignedAttributes::encode() error: unknown type: " . $this->type);
      }
    }  
    $encoded .= asn1encode($class = 0, $constructed = true, $type = SET, $value = $set);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($signedAttribute) {
    $decoded = asn1decode($signedAttribute);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $signedAttribute = $decoded['value'];
    else
      throw new Exception("SignedAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for SignedAttribute, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    $iter = 0;
    while (strlen($signedAttribute) >= 2) {
      $decoded = asn1decode($signedAttribute);
      $next = $decoded['hl'] + $decoded['length'];
      switch ($iter) {
        case 0:
        if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
          $this->type = $decoded['value'];
        } else
          throw new Exception("SignedAttribute::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type for attribute type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SET) {
            $value = $decoded['value'];
            while (strlen($value) >= 2) {
              $decoded2 = asn1decode($value);
              $nextVal = $decoded2['hl'] + $decoded2['length'];
              switch ($this->type) {
                case '1.2.840.113549.1.9.3': //content-type
                  if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OBJECT_IDENTIFIER)
                    $this->values[] = $decoded2['value'];
                  else
                    throw new Exception("SignedAttribute::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type for content-type, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
                break;
                case '1.2.840.113549.1.9.4': //message-digest
                  if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING)
                    $this->values[] = $decoded2['value'];
                  else
                    throw new Exception("SignedAttribute::decode() error: bad message check: expected an ASN.1 OCTET_STRING type for message-digest, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
                break;
                default:
                  $this->values[] = $decoded2['value'];
              }
              $value = substr($value, $nextVal);
            }
          } else
              throw new Exception("SignedAttribute::decode() error: bad message check: expected an ASN.1 SET type for attribute values, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $signedAttribute = substr($signedAttribute, $next);
      $iter++;
    }
    return $offset;  
  }
  
  function __construct($type = null) {
    $this->type = $type;
    $this->values = array();
  }
}

class SignedAttributes {
  public $signedAttributes;
  
  function encode($implicit = true) {
    $attrs = '';
    foreach ($this->signedAttributes as $attribute)
      $attrs .= $attribute->encode();
    if ($implicit)
      return $attrs;
    return asn1encode($class = 0, $constructed = true, $type = SET, $value = $attrs);
  }
  
  function decode($signedAttributes, $implicit = true) {
    if (! $implicit) {
      $decoded = asn1decode($signedAttributes);
      if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET)
        $signedAttributes = $decoded['value'];
      else
        throw new Exception("SignedAttributes::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for SignedAttributes, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $offset = $decoded['hl'] + $decoded['length'];
    }
    $nextAttr = 0;
    while (strlen($signedAttributes) >= 2) {
      $attr = new SignedAttribute();
      $nextAttr = $attr->decode($signedAttributes);
      $this->signedAttributes[] = $attr;
      $signedAttributes = substr($signedAttributes, $nextAttr);
    }
    if ($implicit) return $nextAttr;
    return $offset;
  }
  
  function __construct() {
    $this->signedAttributes = array();
  }
}

class SignerInfo {
  public $version;
  public $issuerAndSerialNumber;
  public $digestAlgorithm;
  public $signedAttributes; //[0] IMPLICIT Attributes OPTIONAL
  public $digestEncryptionAlgorithm;
  public $encryptedDigest;
  public $unsigneddAttributes; //[1] IMPLICIT Attributes OPTIONAL
  
  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
    $encoded .= $this->issuerAndSerialNumber->encode();
    $encoded .= $this->digestAlgorithm->encode();
    $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $this->signedAttributes->encode());
    $encoded .= $this->digestEncryptionAlgorithm->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->encryptedDigest);
    if (! is_null($this->unsigneddAttributes)) {
      $attrs = '';
      foreach ($this->unsigneddAttributes as $attr) {
        $attrs .= $attr->encode();
      }
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $attrs);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($signerInfo) {
    $iter = 0;
    $decoded = asn1decode($signerInfo);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $signerInfo = $decoded['value'];
    else
      throw new Exception("SignerInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for SignerInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($signerInfo) >= 2) {
      switch($iter) {
        case 0: //version
          $decoded = asn1decode($signerInfo);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->version = $decoded['value'];
          } else
            throw new Exception("SignerInfo::decode() error: bad message check: expected an ASN.1 INTEGER type for version, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //issuerAndSerialNumber
          $this->issuerAndSerialNumber = new IssuerAndSerialNumber();
          $next = $this->issuerAndSerialNumber->decode($signerInfo);
        break;
        case 2: //digestAlgorithm
          $this->digestAlgorithm = new AlgorithmIdentifier();
          $next = $this->digestAlgorithm->decode($signerInfo);
        break;
        default:
          $decoded2 = asn1decode($signerInfo);
          $next = $decoded2['hl'] + $decoded2['length'];
          switch($decoded2['class']) {
            case CONTEXT_SPECIFIC_CLASS: //attributes
              if ($decoded2['constructed'] && $decoded2['type'] == 0) {
                $this->signedAttributes = new SignedAttributes();
                $this->signedAttributes->decode($decoded2['value']);
              }
              elseif ($decoded2['constructed'] && $decoded2['type'] == 1) {
                $this->unsigneddAttributes = new SignedAttributes();
                $this->unsigneddAttributes->decode($decoded2['value']);                
              }
              else //error
                throw new Exception("SignerInfo::decode() error: bad message check:  unknown CONTEXT_SPECIFIC_CLASS for attributes, received class " . class2str($decoded['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
            break;
            case UNIVERSAL_CLASS: //digestEncryptionAlgorithm and encryptedDigest
              if ($decoded2['constructed'] && $decoded2['type'] == SEQUENCE) {
                $this->digestEncryptionAlgorithm = new AlgorithmIdentifier();
                $this->digestEncryptionAlgorithm->decode($signerInfo);
              } elseif (! $decoded2['constructed'] && $decoded2['type'] == OCTET_STRING) {
                $this->encryptedDigest = $decoded2['value'];                 
              } else
                throw new Exception("SignerInfo::decode() error: bad message check:  expected UNIVERSAL_CLASS type either SEQUENCE or OCTET_STRING for algorithm or digest, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
            break;
            default:
              throw new Exception("SignerInfo::decode() error: bad message check:  expected either CONTEXT_SPECIFIC_CLASS or UNIVERSAL_CLASS, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
          }
      } 
      $signerInfo = substr($signerInfo, $next);
      $iter++;
    }
    return $offset;    
  }
  
  function __construct($issuer = null, $serialNumber = null, $octets = null) {
    global $default_digest_alg, $default_encrypting_alg, $signing_ca_privkey_path;
    $this->version = 1;
    if (! is_null($issuer) && ! is_null($serialNumber))
      $this->issuerAndSerialNumber = new IssuerAndSerialNumber($issuer, $serialNumber);
    else $this->issuerAndSerialNumber = null;
    $this->digestAlgorithm = new AlgorithmIdentifier($default_digest_alg, $explicitNullParameters = true);
    $this->signedAttributes = new SignedAttributes();
    if (! is_null($octets)) {
      $attr = new SignedAttribute('1.2.840.113549.1.9.3'); //content-type
      $attr->values[] = '1.3.6.1.5.5.7.12.3'; //PKIResponse
      $this->signedAttributes->signedAttributes[] = $attr;
      $attr = new SignedAttribute('1.2.840.113549.1.9.4'); //message-digest
      $attr->values[] = openssl_digest($octets, $default_digest_alg);
      $this->signedAttributes->signedAttributes[] = $attr;
      $digestInput = $this->signedAttributes->encode($implicit = false); //see section 5.4 of https://www.ietf.org/rfc/rfc3852.txt
      $this->digestEncryptionAlgorithm = new AlgorithmIdentifier($default_encrypting_alg, $explicitNullParameters = true);
      $signature = '';
      while(openssl_error_string());
      $privKey = file_get_contents($signing_ca_privkey_path);
      $res = openssl_sign($digestInput, $signature, $privKey, $default_digest_alg);
      if (! $res) {
        $err = openssl_error_string();
        $res = '';
        do {
          $err .= $res;
          $res = openssl_error_string();
        } while($res);
        throw new Exception('mswstep signed_data.php error: openssl_private_encrypt() returned false: ' . $err);
      }
      $this->encryptedDigest = bin2hex($signature);
    }
  }
}

class SignerInfos {
  public $signerInfos; //array of SignerInfo
  
  function encode() {
    $infos = '';
    foreach ($this->signerInfos as $signerInfo)
      $infos .= $signerInfo->encode();
    return asn1encode($class = 0, $constructed = true, $type = SET, $value = $infos);
  }
  
  function decode($signerInfos) {
    $decoded = asn1decode($signerInfos);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET)
      $signerInfos = $decoded['value'];
    else
      throw new Exception("SignerInfos::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for signerInfos, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($signerInfos) >= 2) {
      $info = new SignerInfo();
      $nextInfo = $info->decode($signerInfos);
      $this->signerInfos[] = $info;
      $signerInfos = substr($signerInfos, $nextInfo);
    }
    return $offset;
  }
  
  function __construct() {
    $this->signerInfos = array();
  }
}

class SignedData { //ASN.1 SEQUENCE
  public $version; //probably 4, MS uses 3 for full PKIResponse
  public $digestAlgs; //empty ASN.1 SET for simple PKIResponse or SET of AlgorithmIdentifiers for full PKIResponse
  public $contentInfo; //should be empty sequence for simple PKIResponse; for full PKIResponse it is id-cct-PKIResponse (1.3.6.1.5.5.7.12.3)
  public $certificates; // [0] IMPLICIT CertificateSet OPTIONAL
  public $crls; // [1] IMPLICIT RevocationInfoChoices OPTIONAL
  public $signerInfos; //SignerInfos class; should be empty SET for simple PKIResponse

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
    $algs = '';
    foreach ($this->digestAlgs as $alg) {
      $algs .= $alg->encode();
    }
    $encoded .= asn1encode($class = 0, $constructed = true, $type = SET, $value = $algs);
    $encoded .= $this->contentInfo->encode();
    $certSet = '';
    foreach ($this->certificates as $cert)
      $certSet .= $cert->encode();
    if ($certSet != '')
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $certSet);
    $crlSet = '';
    foreach ($this->crls as $crl)
      $crlSet .= $crl->encode();
    if ($crlSet != '')
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $crlSet);
    if (! is_null($this->signerInfos))
      $encoded .= $this->signerInfos->encode();
    else $encoded .= asn1encode($class = 0, $constructed = true, $type = SET, $value = '');
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($signedData) {
    $iter = 0;
    $decoded = asn1decode($signedData);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $signedData = $decoded['value'];
    else
      throw new Exception("SignedData::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for SignedData, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($signedData) >= 2) {
      switch($iter) {
        case 0: //version
          $decoded = asn1decode($signedData);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->version = $decoded['value'];
          } else
            throw new Exception("SignedData::decode() error: bad message check: expected an ASN.1 INTEGER type for version, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //digestAlgs
          $decoded = asn1decode($signedData);
          if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SET) {
            $algs = $decoded['value'];
            $this->digestAlgs = array();
            while (strlen($algs) > 2) {
              $alg = new AlgorithmIdentifier();
              $nextAlg = $alg->decode($algs);
              $this->digestAlgs[] = $alg;
              $algs = substr($algs, $nextAlg);
            }
          } else
            throw new Exception("SignedData::decode() error: bad message check: expected an ASN.1 SET type for digestAlgs, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 2: //contentInfo
          $this->contentInfo = new ContentInfo();
          $next = $this->contentInfo->decode($signedData);
        break;
        default:
          $decoded2 = asn1decode($signedData);
          $next = $decoded2['hl'] + $decoded2['length'];
          if ($decoded2['class'] == CONTEXT_SPECIFIC_CLASS && $decoded2['constructed']) { //certificates or crls
            switch ($decoded2['type']) {
              case 0: //certificates
                $certs = $decoded2['value'];
                while (strlen($certs) > 2) {
                  $cert = new Certificate();
                  $nextCert = $cert->decode($certs);
                  $this->certificates[] = $cert;
                  $certs = substr($certs, $nextCert);
                }
              break;
              case 1: //crls
              break;
              default: //error
                throw new Exception("SignedData::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS type either 0 or 1 for certificates or crls, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
            }
          } elseif ($decoded2['class'] == UNIVERSAL_CLASS && $decoded2['constructed'] && $decoded2['type'] == SET) { //signerInfos
              $this->signerInfos = new SignerInfos();
              $this->signerInfos->decode($signedData);
          } else //error
                throw new Exception("SignedData::decode() error: bad message check: expected an ASN.1 either constructed CONTEXT_SPECIFIC_CLASS or UNIVERSAL_CLASS for certificates, crls or signerInfos, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type'], $decoded2['class']));
      }
      $signedData = substr($signedData, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct($contentType = '1.2.840.113549.1.7.1') {
    global $signed_data_version, $digest_algs;
    $this->version = $signed_data_version;
    $this->digestAlgs = array();
    if (isset($digest_algs)) {
      foreach ($digest_algs as $alg) {
        $this->digestAlgs[] = new AlgorithmIdentifier($alg, $explicitNullParameters = true);
      }
    }
    $this->contentInfo = new ContentInfo($contentType);
    $this->certificates = array();
    $this->crls = array();
    $this->signerInfos = null;
  }
}

class ContentInfo {
  public $contentType; //OID
  public $content; //SignedData for oid pkcs7-signedData, PKCS10 certificate request for pkcs7-data, id-cct-PKIResponse (1.3.6.1.5.5.7.12.3) for full PKIResponse

  function encode() {
    if ($this->contentType != '')
      $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->contentType);
    else $encoded = '';
    if (! is_null($this->content))
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $this->content->encode());
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($contentInfo) {
    $iter = 0;
    $decoded = asn1decode($contentInfo);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $contentInfo = $decoded['value'];
    else
      throw new Exception("ContentInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for ContentInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($contentInfo) >= 2) {
      $decoded = asn1decode($contentInfo);
      $next = $decoded['hl'] + $decoded['length'];
      switch($iter) {
        case 0: //contentType
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->contentType = $decoded['value'];
          } else
            throw new Exception("ContentInfo::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type for contentType, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //content
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] == 0) {
            switch ($this->contentType) {
              case '1.2.840.113549.1.7.1': //pkcs7-data
                $content = asn1decode($decoded['value']);
                if ($content['class'] == UNIVERSAL_CLASS && ! $content['constructed'] && $content['type'] == OCTET_STRING) {
                  $this->content = new CertificationRequest();
                  $this->content->decode(hex2bin($content['value']));
                } else
                  throw new Exception("ContentInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS type OCTET_STRING for content, received class " . class2str($content['class']) . ", constructed " . $content['constructed'] . ", type " . type2str($content['type'], $content['class']));
              break;
              case '1.2.840.113549.1.7.2': //pkcs7-signedData
                $this->content = new SignedData();
                $this->content->decode($decoded['value']);
              break;
              case '1.3.6.1.5.5.7.12.2': //PKIRequest
                throw new Exception("ContentInfo::decode() error: received contentType for content PKIRequest " . $this->contentType);
              break;
              case '1.3.6.1.5.5.7.12.3': //PKIResponse
                $this->content = new PKIResponse();
                $this->content->decode($decoded['value']);
              break;
              default: //error              
                throw new Exception("ContentInfo::decode() error: bad message check: unknown contentType for content, received " . $this->contentType);
            }
          } else
            throw new Exception("ContentInfo::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS type 0 for content, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("ContentInfo::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $contentInfo = substr($contentInfo, $next);
      $iter++;
    }
    return $offset;    
  }

  function __construct($contentType = '') {
    $this->contentType = $contentType;
    switch ($contentType){
      case '1.2.840.113549.1.7.2':
        $this->content = new SignedData();
      break;
      default:
        $this->content = null;
    }
  }
}

/*
From https://datatracker.ietf.org/doc/html/rfc5272#section-4.2.1
PKIResponse ::= SEQUENCE {
          controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
          cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
          otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
      }
      
TaggedAttribute ::= SEQUENCE {
         bodyPartID         BodyPartID,
         attrType           OBJECT IDENTIFIER,
         attrValues         SET OF AttributeValue
     }

     AttributeValue ::= ANY

   bodyPartID  is a unique integer that identifies this control.
   attrType    is the OID that identifies the control.
   attrValues  is the data values used in processing the control.  The
               structure of the data is dependent on the specific
               control.
               
TaggedContentInfo ::= SEQUENCE {
         bodyPartID              BodyPartID,
         contentInfo             ContentInfo
     }
*/

class CMCStatusInfo {
  public $status; //CMCStatus: INTEGER: 0 - success, 2 - failed, 3 - pending, 4 - noSupport, 5 - confirmedRequired, 6 - popRequired, 7 - partial
  public $list; //could be SEQUENCE of INTEGER 1
  public $statusString; //optional UTF8String
  
  function encode() {
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = INTEGER, $value = $this->status);
    $list = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = INTEGER, $value = $this->list);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $list);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = UTF8_STRING, $value = $this->statusString);
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SET, $value = $encoded);
  }
  
  function decode($cmcStatusInfo) {
    $iter = 0;
    $decoded = asn1decode($cmcStatusInfo);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET)
      $cmcStatusInfo = $decoded['value'];
    else
      throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for cmcStatusInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    $decoded = asn1decode($cmcStatusInfo);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $cmcStatusInfo = $decoded['value'];
    else
      throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for cmcStatusInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    while (strlen($cmcStatusInfo) >= 2) {
      $decoded = asn1decode($cmcStatusInfo);
      $next = $decoded['hl'] + $decoded['length'];
      switch($iter) {
        case 0: //status
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->status = $decoded['value'];
          else
            throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for status, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //list
          if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE) {
            $list = asn1decode($decoded['value']);
            if ($list['class'] == 0 && ! $list['constructed'] && $list['type'] == INTEGER)
              $this->list = $list['value'];
            else
              throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for list, received class " . class2str($list['class']) . ", constructed " . $list['constructed'] . ", type " . type2str($list['type'], $list['class']));
          }
          else
            throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for list, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 2: //statusString
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == UTF8_STRING)
            $this->statusString = $decoded['value'];
          else
            throw new Exception("CMCStatusInfo::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type UTF8_STRING for statusString, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("CMCStatusInfo::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $cmcStatusInfo = substr($cmcStatusInfo, $next);
      $iter++;
    }
    return $offset;               
  }
  
  function __construct($status = 0, $statusString = '') {
    $this->status = $status;
    $this->list = 1;
    $this->statusString = $statusString;
  }
}

class IssuedCertHash {
  public $type; //OBJECT_IDENTIFIER 1.3.6.1.4.1.311.21.17 (szOID_ISSUED_CERT_HASH)
  public $values; //SET of OCTET_STRING (SHA1 hash of issued cert) 
  
  function encode() {
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->type);
    $values = '';
    foreach ($this->values as $val)
      $values .= asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = OCTET_STRING, $value = $val);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SET, $value = $values);
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($issuedCertHash) {
    $iter = 0;
    $decoded = asn1decode($issuedCertHash);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $issuedCertHash = $decoded['value'];
    else
      throw new Exception("IssuedCertHash::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for cmcStatusInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($issuedCertHash) >= 2) {
      $decoded = asn1decode($issuedCertHash);
      $next = $decoded['hl'] + $decoded['length'];
      switch($iter) {
        case 0: //type
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER)
            $this->type = $decoded['value'];
          else
            throw new Exception("IssuedCertHash::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type OBJECT_IDENTIFIER for type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //values
          if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET) {
            $values = asn1decode($decoded['value']);
            if ($values['class'] == 0 && ! $values['constructed'] && $values['type'] == OCTET_STRING)
              $this->values = $values['value'];
            else
              throw new Exception("IssuedCertHash::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type OCTET_STRING for list, received class " . class2str($values['class']) . ", constructed " . $values['constructed'] . ", type " . type2str($values['type'], $values['class']));
          }
          else
            throw new Exception("IssuedCertHash::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for list, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("IssuedCertHash::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $IssuedCertHash = substr($IssuedCertHash, $next);
      $iter++;
    }
    return $offset;                   
  }
  
  function __construct($values = null, $oid = '1.3.6.1.4.1.311.21.17') {
    $this->type = $oid;
    if (! is_null($values) && is_array($values))
      $this->values = $values;
    else $this->values = array();
  }
}

class IssuedCertHashes {
  public $issuedCertHashes; //array of IssuedCertHash
  
  function encode() {
    $encoded = '';
    foreach($this->issuedCertHashes as $hash)
      $encoded .= $hash->encode();
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SET, $value = $encoded);
  }
  
  function decode($issuedCertHashes) {
    $decoded = asn1decode($issuedCertHashes);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET)
      $issuedCertHashes = $decoded['value'];
    else
      throw new Exception("IssuedCertHashes::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for cmcStatusInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($issuedCertHashes) >= 2) {
      $issuedCertHash = new IssuedCertHash();
      $next = $issuedCertHash->decode($decoded['value']);
      $this->issuedCertHashes[] = $issuedCertHash;
      $issuedCertHashes = substr($issuedCertHashes, $next);
    }
    return $offset;
  }
    
  function __construct($hashes = null) {
    $this->issuedCertHashes = array();
    if (! is_null($hashes) && is_array($hashes)) {
      $this->issuedCertHashes[] = new IssuedCertHash($hashes);
    }
  }
}

class AdditionalCMCAttribute {
  public $status;
  public $list;
  public $issuedCertHashes; //IssuedCertHashes
  
  function encode() {
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = INTEGER, $value = $this->status);
    $list = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = INTEGER, $value = $this->list);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $list);
    $encoded .= $this->issuedCertHashes->encode();
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SET, $value = $encoded);
  }
  
  function decode($addCMCattr) {
    $iter = 0;
    $decoded = asn1decode($addCMCattr);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SET)
      $addCMCattr = $decoded['value'];
    else
      throw new Exception("AdditionalCMCAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SET for addCMCattr, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    $decoded = asn1decode($cmcStatusInfo);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $cmcStatusInfo = $decoded['value'];
    else
      throw new Exception("AdditionalCMCAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for addCMCattr, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    while (strlen($addCMCattr) >= 2) {
      switch($iter) {
        case 0: //status
          $decoded = asn1decode($addCMCattr);
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->status = $decoded['value'];
          else
            throw new Exception("AdditionalCMCAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for status, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //list
          $decoded = asn1decode($addCMCattr);
          if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE) {
            $list = asn1decode($decoded['value']);
            if ($list['class'] == 0 && ! $list['constructed'] && $list['type'] == INTEGER)
              $this->list = $list['value'];
            else
              throw new Exception("AdditionalCMCAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for list, received class " . class2str($list['class']) . ", constructed " . $list['constructed'] . ", type " . type2str($list['type'], $list['class']));
          }
          else
            throw new Exception("AdditionalCMCAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for list, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        $next = $decoded['hl'] + $decoded['length'];
      break;
        case 2: //issuedCertHashes
          $this->issuedCertHashes = new IssuedCertHashes();
          $next = $this->issuedCertHashes->decode($addCMCattr);
        break;
        default:
          throw new Exception("AdditionalCMCAttribute::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $addCMCattr = substr($addCMCattr, $next);
      $iter++;
    }
    return $offset;                   
  }
  
  function __construct($status = 0, $certHash = '') {
    $this->status = $status;
    $this->list = 1;
    $this->issuedCertHashes = new IssuedCertHashes([$certHash]);
  }
}

class PKIAttribute {
  public $id; //INTEGER, attribute number?
  public $type; //id-cmc-statusInfo (1.3.6.1.5.5.7.7.1), for example or szOID_CMC_ADD_ATTRIBUTES (1.3.6.1.4.1.311.10.10.1)
  public $value; //for the id-cmc-statusInfo oid, it is CMCStatusInfo, for szOID_CMC_ADD_ATTRIBUTES oid (1.3.6.1.4.1.311.21.17), it is AdditionalCMCAttribute  -  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9e33bdec-48db-45a6-9ab2-66676a586be4

  function encode() {
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = INTEGER, $value = $this->id);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->type);
    $encoded .= $this->value->encode();
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($pkiAttribute) {
    $iter = 0;
    $decoded = asn1decode($pkiAttribute);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiAttribute = $decoded['value'];
    else
      throw new Exception("PKIAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for pkiAttribute, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($pkiAttribute) >= 2) {
      switch($iter) {
        case 0: //id
          $decoded = asn1decode($pkiAttribute);
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->id = $decoded['value'];
          else
            throw new Exception("PKIAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type INTEGER for id, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //type
          $decoded = asn1decode($pkiAttribute);
          if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER)
            $this->type = $decoded['value'];
          else
            throw new Exception("PKIAttribute::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type OBJECT_IDENTIFIER for type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        default:
          switch ($this->type) {
            case '1.3.6.1.5.5.7.7.1': //id-cmc-statusInfo
              $this->value = new CMCStatusInfo();
              $next = $this->value->decode($pkiAttribute);
            break;
            case '1.3.6.1.4.1.311.10.10.1': //AdditionalCMCAttribute
              $this->value = new AdditionalCMCAttribute();
              $next = $this->value->decode($pkiAttribute);
            break;
            default:
              throw new Exception("PKIAttribute::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          }
      }
      $pkiAttribute = substr($pkiAttribute, $next);
      $iter++;
    }
    return $offset;           
  }
  
  function __construct($id = 0, $type = '', $value = '') {
    $this->id = $id;
    $this->type = $type;
    $this->value = $value;
  }
}

class PKIAttributes { //SEQUENCE of PKIAttribute
  public $pkiAttributes; //array of PKIAttribute
  
  function encode() {
    $encoded = '';
    foreach ($this->pkiAttributes as $attr) {
      $encoded .= $attr->encode();
    }      
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($attrs) {
    $iter = 0;
    $decoded = asn1decode($attrs);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $attrs = $decoded['value'];
    else
      throw new Exception("PKIAttributes::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for pkiAttributes, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    while (strlen($attrs) >= 2) {
      $attr = new PKIAttribute();
      $next = $attr->decode($decoded['value']);
      $this->pkiAttributes[] = $attr;
      $attrs = substr($attrs, $next);
    }
    return $offset;
  }
  
  function __construct() {
    $this->pkiAttributes = array();
  }
}

class PKIResponse {
  public $controls; //PKIAttributes
  public $contents; //SEQUENCE of ContentInfo, could be empty
  public $messages; //SEQUENCE, used by controls, could be empty
  
  function encode() {
    $encoded = $this->controls->encode();
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $this->contents);
    $encoded .= asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $this->messages);
    $encoded = asn1encode($class = UNIVERSAL_CLASS, $constructed = true, $type = SEQUENCE, $value = $encoded);
    return asn1encode($class = UNIVERSAL_CLASS, $constructed = false, $type = OCTET_STRING, $value = bin2hex($encoded));
  }
  
  function decode($pkiResponse) {
    $iter = 0;
    $decoded = asn1decode($pkiResponse);
    if ($decoded['class'] == 0 && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
      $pkiResponse = hex2bin($decoded['value']);
    else
      throw new Exception("PKIResponse::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type OCTET_STRING for PKIResponse, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['hl'] + $decoded['length'];
    $decoded = asn1decode($pkiResponse);
    if ($decoded['class'] == 0 && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiResponse = $decoded['value'];
    else
      throw new Exception("PKIResponse::decode() error: bad message check: expected an ASN.1 UNIVERSAL_CLASS class and type SEQUENCE for PKIResponse, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    while (strlen($pkiResponse) >= 2) {
      switch($iter) {
        case 0: //controls
          $this->controls = new PKIAttributes();
          $next = $this->controls->decode($pkiResponse);
        break;
        case 1: //contents
          $decoded = asn1decode($pkiResponse);
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 2: //messages
          $decoded = asn1decode($pkiResponse);
          $next = $decoded['hl'] + $decoded['length'];
        break;
        default:
          throw new Exception("PKIResponse::decode() error: bad message check:  ASN1 structure is too long, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      }
      $pkiResponse = substr($pkiResponse, $next);
      $iter++;
    }
    return $offset;       
  }
  
  function __construct($status = 0, $statusString = '', $hash = '') {
    $this->controls = new PKIAttributes();
    $this->controls->pkiAttributes[] = new PKIAttribute(1, '1.3.6.1.5.5.7.7.1', new CMCStatusInfo($status, $statusString));
    $this->controls->pkiAttributes[] = new PKIAttribute(2, '1.3.6.1.4.1.311.10.10.1', new AdditionalCMCAttribute($status, $hash));
    $this->contents = '';
    $this->messages = '';
  }
}
