<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';

/*
AlgorithmIdentifier ::= SEQUENCE {
 algorithm OBJECT IDENTIFIER,
 parameters ANY DEFINED BY algorithm OPTIONAL }
 -- contains a value of the type
 -- registered for use with the
 -- algorithm object identifier value

EcpkParameters ::= CHOICE {
        ecParameters  ECParameters,
        namedCurve    OBJECT IDENTIFIER,
        implicitlyCA  NULL }

ECParameters ::= SEQUENCE {
         version   ECPVer,          -- version is always 1
         fieldID   FieldID,         -- identifies the finite field over
                                    -- which the curve is defined
         curve     Curve,           -- coefficients a and b of the
                                    -- elliptic curve
         base      ECPoint,         -- specifies the base point P
                                    -- on the elliptic curve
         order     INTEGER,         -- the order n of the base point
         cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
         }
      ECPVer ::= INTEGER {ecpVer1(1)}

      FieldID ::= SEQUENCE {
         fieldType   OBJECT IDENTIFIER,
         parameters  ANY DEFINED BY fieldType }

id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1) }

The object identifiers prime-field and characteristic-two-field name
are the two kinds of fields defined in this Standard.  They have the
following values:

prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
Prime-p ::= INTEGER    -- Field size p (p in bits)

characteristic-two-field OBJECT IDENTIFIER ::= { id-fieldType 2 }

Characteristic-two ::= SEQUENCE {
    m           INTEGER,                      -- Field size 2^m
    basis       OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY basis }

   The object identifier id-characteristic-two-basis specifies an arc
   containing the object identifiers for each type of basis for the
   characteristic-two finite fields.  It has the following value:

      id-characteristic-two-basis OBJECT IDENTIFIER ::= {
           characteristic-two-field basisType(1) }

   The object identifiers gnBasis, tpBasis and ppBasis name the three
   kinds of basis for characteristic-two finite fields defined by
   [X9.62].  They have the following values:

      gnBasis OBJECT IDENTIFIER ::= { id-characteristic-two-basis 1 }

      -- for gnBasis, the value of the parameters field is NULL

      tpBasis OBJECT IDENTIFIER ::= { id-characteristic-two-basis 2 }

      -- type of parameters field for tpBasis is Trinomial

      Trinomial ::= INTEGER

      ppBasis OBJECT IDENTIFIER ::= { id-characteristic-two-basis 3 }

      -- type of parameters field for ppBasis is Pentanomial

      Pentanomial ::= SEQUENCE {
         k1  INTEGER,
         k2  INTEGER,
         k3  INTEGER }

      Curve ::= SEQUENCE {
         a         FieldElement,
         b         FieldElement,
         seed      BIT STRING OPTIONAL }
      FieldElement ::= OCTET STRING
      ECPoint ::= OCTET STRING
*/

/*
//This class is not used. The recommended class for EC parameters is ECPKParameters, which uses named elliptic curves

class ECParameters {
  public $version;
  public $fieldID;
  public $curve; //Curve
  public $base; //ECPoint
  public $order; //INTEGER
  public $cofactor; //INTEGER OPTIONAL

  function encode() {
  }

  function decode($param) {
  }
}
*/

/*
PBMParameter ::= SEQUENCE {
 salt OCTET STRING,
 owf AlgorithmIdentifier,
 -- AlgId for a One-Way Function (SHA-1 recommended)
 iterationCount INTEGER,
 -- number of times the OWF is applied
 mac AlgorithmIdentifier
 -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
} -- or HMAC [HMAC, RFC2202])
*/

class PBMParameter {
  public $salt; //OCTET STRING
  public $owf; //AlgorithmIdentifier
  public $iterationCount; //INTEGER
  public $mac; //AlgorithmIdentifier
  
  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->salt);
    $encoded .= $this->owf->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->iterationCount);
    $encoded .= $this->mac->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);    
  }
  
  function decode($param) {
    $iter = 0;
    $decoded = asn1decode($param);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $param = $decoded['value'];
    else
      throw new Exception('PBMParameter::decode() error: bad message check: expected an ASN.1 SEQUENCE for PBMParameter, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($param) > 2) {
      switch($iter) {
        case 0: //salt
          $decoded = asn1decode($param);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING) {
            $this->salt = $decoded['value'];
          } else
            throw new Exception('PBMParameter::decode() error: bad message check: expected an ASN.1 OCTET_STRING type for salt, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //owf
          $this->owf = new AlgorithmIdentifier(); 
          $next = $this->owf->decode($param);
        break;
        case 2: //iterationCount
          $decoded = asn1decode($param);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->iterationCount = $decoded['value'];
          } else
            throw new Exception('PBMParameter::decode() error: bad message check: expected an ASN.1 INTEGER type for iterationCount, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 3: //mac
          $this->mac = new AlgorithmIdentifier(); 
          $next = $this->mac->decode($param);
        break;
        default:
          throw new Exception('PBMParameter::decode() error: bad message check: string is too long');
      }
      $param = substr($param, $next);
      $iter++;
    }
    return $offset;    
  }
  
  function __construct($salt = null, $owf = 'sha1', $iterationCount = 500, $mac = 'hmac-sha1') {
    if (! is_null($salt)) {
      $this->salt = $salt;
      $this->owf = new AlgorithIdentifier($owf, $explicitNullParameters = true);
      $this->iterationCount = $iterationCount;
      $this->mac = new AlgorithIdentifier($mac, $explicitNullParameters = true);
    }
  }
}

class DSSParameters {
  public $p; //INTEGER
  public $q; //INTEGER
  public $g; //INTEGER

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->p);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->q);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->g);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($param) {
    $iter = 0;
    $decoded = asn1decode($param);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $param = $decoded['value'];
    else
      throw new Exception('DSSParameters::decode() error: bad message check: expected an ASN.1 SEQUENCE for DSSParameters, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($param) > 2) {
      $decoded = asn1decode($param);
      $next = $decoded['length'] + $decoded['hl'];
      switch($iter) {
        case 0: //p
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->p = $decoded['value'];
          } else
            throw new Exception('DSSParameters::decode() error: bad message check: expected an ASN.1 INTEGER type for p, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //q
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->q = $decoded['value'];
          } else
            throw new Exception('DSSParameters::decode() error: bad message check: expected an ASN.1 INTEGER type for q, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
        break;
        case 2: //g
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->g = $decoded['value'];
          } else
            throw new Exception('DSSParameters::decode() error: bad message check: expected an ASN.1 INTEGER type for g, received class ' . class2str($decoded['class']) . ', constructed ' . $decoded['constructed'] . ', type ' . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception('DSSParameters::decode() error: bad message check: string is too long');
      }
      $param = substr($param, $next);
      $iter++;
    }
    return $offset;
  }
}

class ECPKParameters {
  public $ecParamters;
  public $namedCurve;
  public $implictlyCA;

  function encode() {
    if (! is_null($this->ecParamters))
      return $this->ecParamters->encode();
    if (! is_null($this->namedCurve))
      return asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->namedCurve);
    if ($this->implictlyCA)
      return asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
  }

  function decode($param) {
    $decoded = asn1decode($param);
    if ($decoded['class'] == UNIVERSAL_CLASS) {
      if ($decoded['constructed'] && $decoded['type'] == SEQUENCE)
        throw new Exception("ECPKParameters::decode() error: ECParamters choice is not supported");
      elseif (! $decoded['constructed']) {
        if ($decoded['type'] == OBJECT_IDENTIFIER) {
          $this->namedCurve = $decoded['value'];
        }
        elseif ($decoded['type'] == NULL_VALUE)
          $this->implicitlyCA = true;
        else
          throw new Exception("ECPKParameters::decode() error: unexpected ASN.1 type, expected either SEQUENCE, OBJECT_IDENTIFIER or NULL_VALUE, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      } else
        throw new Exception("ECPKParameters::decode() error: unexpected ASN.1 tag or type, expected either SEQUENCE, OBJECT_IDENTIFIER or NULL_VALUE, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    } else
      throw new Exception("ECPKParameters::decode() error: unexpected ASN.1 class, expected an ASN.1 UNIVERSAL class, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    return strlen($param);
  }
  
  function __construct($implicitlyCA = null) {
    $this->ecParamters = null;
    $this->namedCurve = null;
    if (! is_null($implicitlyCA))
      $this->implicitlyCA = $implicitlyCA;
    else $this->implicitlyCA = false;
  }
}

class AlgorithmIdentifier {
  public $algorithm;
  public $parameters;
  public $explicitNullParameters;

  function encode($implicit = false) {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->algorithm);
    switch($this->algorithm) {
      case "1.2.840.113533.7.66.13": //password based MAC
      case "1.2.840.113533.7.66.30": //DHBasedMac      
      case "1.2.840.10040.4.1": //DSAPublicKey
      case "1.2.840.10045.2.1": //ecPublicKey
      case "1.2.840.10045.4.1": //ecdsa-with-SHA1
      case "1.2.840.10045.4.3.2": //ecdsa-with-SHA256
        if (! is_null($this->parameters))
          $encoded .= $this->parameters->encode();
      break;
      case "1.3.6.1.5.5.8.1.2": //hmac-sha1
      case "1.2.840.113549.2.9": //hmac-sha256
      case "1.2.840.113549.1.1.1": //rsaEncryption (RSAPublicKey)
      case "1.2.840.113549.1.1.5": //sha1WithRSAEncryption
      case "1.2.840.113549.1.1.11": //sha256WithRSAEncryption
      case "2.16.840.1.101.3.4.1.2": //aes128-CBC-PAD - used in genm because of $preferred_symmetric_alg = 'aes-128-cbc' in globals.php
      case "2.16.840.1.101.3.4.2.1": //sha256
      case "1.3.14.3.2.26": //sha1
        if ($this->explicitNullParameters)
          $encoded .= asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
      break;
      case "1.2.840.10040.4.3": //dsaWithSHA1
      case '2.16.840.1.101.3.4.3.2': //dsa-with-sha256
      break;
      default:
        throw new Exception("AlgorithmIdentifier::encode() error: unknown algorithm oid");
    }
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($alg, $implicit = false) {
    $iter = 0;
    if (! $implicit) {
      $decoded = asn1decode($alg);
      if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
        $alg = $decoded['value'];
      else
        throw new Exception("AlgorithmIdentifier::decode() error: bad message check: expected an ASN.1 SEQUENCE for AlgorithmIdentifier, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $offset = $decoded['length'] + $decoded['hl'];
    } else $offset = strlen($alg);
    while (strlen($alg) >= 2) {
      switch($iter) {
        case 0: //algorithm
          $decoded = asn1decode($alg);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->algorithm = $decoded['value'];
          } else
            throw new Exception("AlgorithmIdentifier::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        case 1: //parameters
          switch($this->algorithm) {
            case "1.2.840.113533.7.66.13": //id-PasswordBasedMac
              $this->parameters = new PBMParameter();
              $next = $this->parameters->decode($alg);
            break;
            case "1.2.840.10040.4.1": //DSAPublicKey
              $this->parameters = new DSSParameters();
              $next = $this->parameters->decode($alg);
            break;
            case "1.2.840.10045.2.1": //ecPublicKey
              $this->parameters = new ECPKParameters();
              $next = $this->parameters->decode($alg);
            break;
            case "1.2.840.10045.4.1": //ecdsa-with-SHA1
            case "1.2.840.10045.4.3.2": //ecdsa-with-SHA256
              $this->parameters = new ECPKParameters();
              $next = $this->parameters->decode($alg);
            break;
            case '1.3.14.3.2.26': //sha1
            case '2.16.840.1.101.3.4.2.1': //sha256
            case "1.2.840.113549.1.1.1": //rsaEncryption (RSAPublicKey)
            case "1.2.840.113549.1.1.5": //sha1WithRSAEncryption
            case "1.2.840.113549.1.1.11": //sha256WithRSAEncryption
              $decoded = asn1decode($alg);
              if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == NULL_VALUE) {
                $this->explicitNullParameters = true;
                $next = $decoded['hl'] + $decoded['length'];
              }
              else
                throw new Exception("AlgorithmIdentifier::decode() error: bad message check: expected an ASN.1 NULL_VALUE, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
            break;
            default:
              throw new Exception("AlgorithmIdentifier::decode() error: unknown algorithm oid " . $this->algorithm);
          }
        break;
        default:
          throw new Exception("AlgorithmIdentifier::decode() error: bad message check: string is too long");
      }
      $alg = substr($alg, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct($alg = null, $explicitNullParameters = false) {
    $this->parameters = null;
    $this->explicitNullParameters = $explicitNullParameters;
    if (! is_null($alg)) {
      if (is_string($alg)) {
        if ($alg[0] != '0' || $alg[0] != '1' || $alg[0] != '2') $alg = str2oid($alg);
        $this->algorithm = $alg;
      } else
        throw new Exception("AlgorithmIdentifier::__construct() error: an argument is neither a string nor null");
    }
  }

  function __clone() {
    if (! is_null($this->parameters))
      $this->parameters = clone $this->parameters;
  }
}

?>