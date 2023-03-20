<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'algorithm_identifier.php';
require_once 'subject_pubkey_info.php';
require_once 'extension.php';

/*
From RFC 2986 (PKCS#10)
   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }
   SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
        algorithm        AlgorithmIdentifier {{IOSet}},
        subjectPublicKey BIT STRING
   }
   PKInfoAlgorithms ALGORITHM ::= {
        ...  -- add any locally defined algorithms here -- }
   Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }} //somehow SET is implicit!
   CRIAttributes  ATTRIBUTE  ::= {
        ... -- add any locally defined attributes here -- }
   Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        type   ATTRIBUTE.&id({IOSet}),
        values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
   }
*/

class CSRAttributes { //set of Attribute
  public $attributes;

  function encode() {
    $encoded = '';
    foreach($this->attributes as $attribute)
      $encoded .= $attribute->encode();
    return asn1encode($class = 2, $constructed = true, $type = 0, $value = $encoded);
  }

  function decode($attributes) {
    $decoded = asn1decode($attributes);
    if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] == 0)
      $attributes = $decoded['value'];
    else
      throw new Exception("CSRAttributes::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC class and type 0 for CSRAttributes, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($attributes) >= 2) {
      $attribute = new CSRAttribute();
      $next = $attribute->decode($attributes);               
      $this->attributes[] = $attribute;
      $attributes = substr($attributes, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->attributes = array();
  }

  function __clone() {
    foreach($this->attributes as &$attribute)
      $attribute = clone $attribute;
  }
}

/*
see https://datatracker.ietf.org/doc/html/rfc2985#page-16
seems like attriutes are cert extensions, oid is 1.2.840.113549.1.9.14 - extensionRequest
 extensionRequest ATTRIBUTE ::= {
           WITH SYNTAX ExtensionRequest
           SINGLE VALUE TRUE
           ID pkcs-9-at-extensionRequest
   }
   ExtensionRequest ::= Extensions
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
Extension ::= SEQUENCE {
 extnID OBJECT IDENTIFIER,
 critical BOOLEAN DEFAULT FALSE,
 extnValue OCTET STRING }

   challengePassword ATTRIBUTE ::= {
           WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
           EQUALITY MATCHING RULE caseExactMatch
           SINGLE VALUE TRUE
           ID pkcs-9-at-challengePassword
   }
DirectoryString ::= CHOICE {
 teletexString TeletexString (SIZE (1..MAX)),
 printableString PrintableString (SIZE (1..MAX)),
 universalString UniversalString (SIZE (1..MAX)),
 utf8String UTF8String (SIZE (1..MAX)),
 bmpString BMPString (SIZE (1..MAX)) }
*/

class CSRAttribute {
  public $type; //attribute id
  public $values; //attribute values

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->type);
    $attr = '';
    foreach($this->values as $value) {
      switch($this->type) {
        case '1.2.840.113549.1.9.14': //extensionRequest
          $attr .= $value->encode(); //Extensions
        break;
        case '1.2.840.113549.1.9.7': //challengePassword (DirectoryString) - unsupported
          $attr .= asn1encode($class = 0, $constructed = false, $type = UTF8_STRING, $value = $value);
        break;
/*        
        case '1.3.6.1.4.1.311.13.2.2': //SET of MS CSP (Crypto service provider)
          $attr .= $value->encode();
        break;
*/         
        default:
          $attr .= $value;
      }
    }
    $encoded .= asn1encode($class = 0, $constructed = true, $type = SET, $value = $attr);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($attribute) {
    $iter = 0;
    $decoded = asn1decode($attribute);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $attribute = $decoded['value'];
    else
      throw new Exception("CSRAttribute::decode() error: bad message check: expected an ASN.1 SEQUENCE for CSRAttribute, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($attribute) >= 2) {
      $decoded = asn1decode($attribute);
      $next = $decoded['hl'] + $decoded['length'];
      switch($iter) {
        case 0: //type
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->type = $decoded['value'];
          } else
            throw new Exception("CSRAttribute::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type for type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SET) {
            $attr = $decoded['value'];
          } else
            throw new Exception("CSRAttribute::decode() error: bad message check: expected an ASN.1 SET type for values, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          switch($this->type) {
            case '1.2.840.113549.1.9.14': //extensionRequest
              $extensions = new Extensions();
              $extensions->decode($attr);
              $this->values[] = $extensions;
            break;
            case '1.2.840.113549.1.9.7': //challengePassword
              $challengePassword = asn1decode($attr);
              if ($challengePassword['class'] == UNIVERSAL_CLASS && ! $challengePassword['constructed']) {
                $this->values[] = $challengePassword['value'];
              } else
                throw new Exception("CSRAttribute::decode() error: bad message check: expected an ASN.1 DirectoryString (CHOICE) type for values, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
            break;
/*            
            case '1.3.6.1.4.1.311.13.2.2': //SET of MS CSP (Crypto service provider)
              $csps = new CSPAttributes();
              $csps->decode($attr);
              $this->values[] = $csps;
            break;
*/              
            default:
              $this->values[] = $attr;
          }          
      }
      $attribute = substr($attribute, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->values = array();
  }

  function __clone() {
    $this->values = clone $this->values;
  }
}

class CertificationRequestInfo {
  public $version; //INTEGER v1 (0)
  public $subject; //Name
  public $subjectPKInfo; //SubjectPublicKeyInfo
  public $attributes; //[0] SET of Attribute, PKCS#9 cert extensions

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
    $encoded .= $this->subject->encode();
    $encoded .= $this->subjectPKInfo->encode();
    if (! is_null($this->attributes)) {
      $encoded .= $this->attributes->encode();
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($req) {
    $iter = 0;
    $decoded = asn1decode($req);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $req = $decoded['value'];
    else
      throw new Exception("CertificationRequestInfo::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertificationRequestInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($req) >= 2) {
      switch($iter) {
        case 0: //version
          $decoded = asn1decode($req);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->version = $decoded['value'];
          } else
            throw new Exception("CertificationRequestInfo::decode() error: bad message check: expected an ASN.1 INTEGER type for version, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //subject
          $this->subject = new Name();
          $next = $this->subject->decode($req);         
        break;
        case 2: //subjectPKInfo
          $this->subjectPKInfo = new SubjectPublicKeyInfo();
          $next = $this->subjectPKInfo->decode($req);         
        break;
        case 3: //attributes
          $this->attributes = new CSRAttributes();
          $next = $this->attributes->decode($req);         
        break;
        default:
          throw new Exception("CertificationRequestInfo::decode() error: bad message check: string is too long");
      }
      $req = substr($req, $next);
      $iter++;
    }
    return $offset;
  }

  function __clone() {
    $this->subject = clone $this->subject;
    $this->subjectPKInfo = clone $this->subjectPKInfo;
    $this->attributes = clone $this->attributes;
  }
}

/*
   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
   AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
        algorithm          ALGORITHM.&id({IOSet}),
        parameters         ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
   }
   SignatureAlgorithms ALGORITHM ::= {
        ... -- add any locally defined algorithms here -- }
*/

class CertificationRequest {
  public $certificationRequestInfo; //CertificationRequestInfo - this DER-encoded value is being signed
  public $signatureAlgorithm; //AlgorithmIdentifier
  public $signature; //BIT STRING

  function encode() {
    $encoded = $this->certificationRequestInfo->encode();
    $encoded .= $this->signatureAlgorithm->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->signature);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($csr) {
    $iter = 0;
    $decoded = asn1decode($csr);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $csr = $decoded['value'];
    else
      throw new Exception("CertificationRequest::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertificationRequest, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($csr) >= 2) {
      switch($iter) {
        case 0: //certificationRequestInfo
          $this->certificationRequestInfo = new CertificationRequestInfo();
          $next = $this->certificationRequestInfo->decode($csr);
        break;
        case 1: //signatureAlgorithm
          //file_put_contents('/tmp/signatureAlgorithm.der', $csr);
          $this->signatureAlgorithm = new AlgorithmIdentifier();
          $next = $this->signatureAlgorithm->decode($csr);         
        break;
        case 2: //signature
          //file_put_contents('/tmp/signature.der', $csr);
          $decoded = asn1decode($csr);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING) {
            $this->signature = $decoded['value'];
          } else
            throw new Exception("CertificationRequest::decode() error: bad message check: expected an ASN.1 BIT_STRING type for signature, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        default:
          throw new Exception("CertificationRequest::decode() error: bad message check: string is too long");
      }
      $csr = substr($csr, $next);
      $iter++;
    }
    return $offset;
  }

  function __clone() {
    $this->certificationRequestInfo = clone $this->certificationRequestInfo;
    $this->signatureAlgorithm = clone $this->signatureAlgorithm;
  }

}

?>