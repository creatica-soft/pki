<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'algorithm_identifier.php';

/*
SubjectPublicKeyInfo ::= SEQUENCE {
 algorithm AlgorithmIdentifier,
 subjectPublicKey BIT STRING }

FROM RFC3279: 2.3.1 RSA Keys
pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
                     rsadsi(113549) pkcs(1) 1 }

      rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1}

   The rsaEncryption OID is intended to be used in the algorithm field
   of a value of type AlgorithmIdentifier.  The parameters field MUST
   have ASN.1 type NULL for this algorithm identifier.

   The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey:

      RSAPublicKey ::= SEQUENCE {
         modulus            INTEGER,    -- n
         publicExponent     INTEGER  }  -- e

For info about ECDSA and ECDH keys, see https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.5
ansi-X9-62 OBJECT IDENTIFIER ::=
                             { iso(1) member-body(2) us(840) 10045 }
     id-public-key-type OBJECT IDENTIFIER  ::= { ansi-X9.62 2 }
     id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }

   The elliptic curve public key (an ECPoint which is an OCTET STRING)
   is mapped to a subjectPublicKey (a BIT STRING) as follows:  the most
   significant bit of the OCTET STRING becomes the most significant bit
   of the BIT STRING, and the least significant bit of the OCTET STRING
   becomes the least significant bit of the BIT STRING.  Note that this
   octet string may represent an elliptic curve point in compressed or
   uncompressed form.  Implementations that support elliptic curve
   according to this specification MUST support the uncompressed form
   and MAY support the compressed form.
*/

class RSAPublicKey {
  public $modulus;
  public $publicExponent;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->modulus);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->publicExponent);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function decode($pubkey) {
    global $min_key_size;
    $iter = 0;
    $decoded = asn1decode($pubkey);
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
      $pubkey = $decoded['value'];
    else
      throw new Exception("RSAPublicKey::decode() error: bad message check: expected an ASN.1 BIT_STRING for RSAPublicKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    $decoded = asn1decode(hex2bin($pubkey));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pubkey = $decoded['value'];
    else
      throw new Exception("RSAPublicKey::decode() error: bad message check: expected an ASN.1 SEQUENCE for RSAPublicKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    while (strlen($pubkey) > 2) {
      $decoded = asn1decode($pubkey);
      switch($iter) {
        case 0: //modulus
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->modulus = $decoded['value'];
            $keySize = strlen(gmp_strval($this->modulus, 16)) * 4;
            if ($keySize < $min_key_size)
              throw new Exception("RSA key is too short: $keySize. Minimum RSA key length is $min_key_size bits");  
          } else
            throw new Exception("RSAPublicKey::decode() error: bad message check: expected an ASN.1 INTEGER for modulus, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //publicExponent
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->publicExponent = $decoded['value'];
          } else
            throw new Exception("RSAPublicKey::decode() error: bad message check: expected an ASN.1 INTEGER for publicExponent, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("RSAPublicKey::decode() error: bad message check: string is too long");
      }
      $pubkey = substr($pubkey, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $offset;
  }

  function __construct($modulus = null, $exponent = null) {
    if (! is_null($modulus)) {
      $m = bin2hex(base64url_decode($modulus));
      $m = gmp_init('0x' . $m);
      $this->modulus = gmp_strval($m, 10);
    } else $this->modulus = null;
    if (! is_null($exponent)) {
      $e = bin2hex(base64url_decode($exponent));
      $e = gmp_init('0x' . $e);
      $this->publicExponent = gmp_strval($e, 10);
    } else $this->publicExponent = null;
  }
}

class DSAPublicKey {
  public $publicKey;

  function encode() {
    return asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->publicKey);
  }

  function decode($pubkey) {
    global $min_dsakey_size;
    $decoded = asn1decode($pubkey);
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
      $pubkey = $decoded['value'];
    else
      throw new Exception("ECPublicKey::decode() error: bad message check: expected an ASN.1 BIT_STRING for DSAPublicKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    $decoded = asn1decode(hex2bin($pubkey));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
      $this->publicKey = $decoded['value'];
      $keySize = strlen(gmp_strval($this->publicKey, 16)) * 8;
      if ($keySize < $min_dsakey_size)
        throw new Exception("DSA key is too short: $keySize. Minimum DSA key length is $min_dsakey_size bits");  
    }
    else
      throw new Exception("ECPublicKey::decode() error: bad message check: expected an ASN.1 INTEGER for DSAPublicKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    return $offset;
  }

  function __construct() {
    $this->publicKey = null;
  }  
}

class ECPublicKey {
  public $ecPoint;

  function encode() {
    return encode($type = OCTET_STRING, $value = $this->ecPoint);
  }

  function decode($pubkey) {
    global $min_eckey_size;
    $decoded = asn1decode($pubkey);
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING) {
      $this->ecPoint = $decoded['value'];
      $keySize = strlen($this->ecPoint) * 8;
      if ($keySize < $min_eckey_size)
        throw new Exception("EC key is too short: $keySize. Minimum EC key length is $min_eckey_size bits");  
    }
    else
      throw new Exception("ECPublicKey::decode() error: bad message check: expected an ASN.1 BIT_STRING for ECPublicKey, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    return $decoded['length'] + $decoded['hl'];
  }

  function __construct($x = null, $y = null) {
    if (! is_null($x) && ! is_null($y))
      $this->ecPoint = '04' . bin2hex(base64url_decode($x)) . bin2hex(base64url_decode($y));
    else $this->ecPoint = null;
  }  
}

class SubjectPublicKeyInfo {
  public $algorithm;
  public $subjectPublicKey;

  function encode($implicit = false) {
    $encoded = $this->algorithm->encode();
    $pubkey = $this->subjectPublicKey->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . bin2hex($pubkey));
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($subjectPublicKeyInfo, $implicit = false) {
    $iter = 0;
    if (! $implicit) {
      $decoded = asn1decode($subjectPublicKeyInfo);
      if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
        $subjectPublicKeyInfo = $decoded['value'];
      else
        throw new Exception("SubjectPublicKeyInfo::decode() error: bad message check: expected an ASN.1 SEQUENCE for subjectPublicKeyInfo, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $offset = $decoded['length'] + $decoded['hl'];
    } else $offset = strlen($subjectPublicKeyInfo);
    while(strlen($subjectPublicKeyInfo) > 2) {
      switch($iter) {
        case 0: //algorithm
          $this->algorithm = new AlgorithmIdentifier();
          $next = $this->algorithm->decode($subjectPublicKeyInfo);
        break;
        case 1: //subjectPublicKey
          switch($this->algorithm->algorithm) {
            case '1.2.840.113549.1.1.1': //rsaEncryption
              $this->subjectPublicKey = new RSAPublicKey();
            break;
            case '1.2.840.10040.4.1': //DSA
              $this->subjectPublicKey = new DSAPublicKey();
            break;
            case '1.2.840.10045.2.1': //EC
              $this->subjectPublicKey = new ECPublicKey();
            break;
            default:
              throw new Exception("SubjectPublicKeyInfo::decode() error: bad message check: unknown key algorithm id " . $this->algorithm->algorithm);
          }
          $next = $this->subjectPublicKey->decode($subjectPublicKeyInfo);
        break;
        default:
          throw new Exception("SubjectPublicKeyInfo::decode() error: string is too long");
      }
      $subjectPublicKeyInfo = substr($subjectPublicKeyInfo, $next);
      $iter++;
    }
    return $offset;
  }

  function __clone() {
    $this->algorithm = clone $this->algorithm;
    $this->subjectPublicKey = clone $this->subjectPublicKey;
  }
}

?>