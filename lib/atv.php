<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'cert_id.php';

/*
AttributeTypeAndValue ::= SEQUENCE {
 type OBJECT IDENTIFIER,
 value ANY DEFINED BY type }

id-regCtrl-regToken            OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.1 } with the value of UTF8_STRING
id-regCtrl-authenticator       OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.2 } with the value of UTF8_STRING
id-regCtrl-pkiPublicationInfo  OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.3 }
   PKIPublicationInfo ::= SEQUENCE {
        action     INTEGER {
                     dontPublish (0),
                     pleasePublish (1) },
        pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
   SinglePubInfo ::= SEQUENCE {
         pubMethod    INTEGER {
             dontCare    (0),
             x500        (1),
             web         (2),
             ldap        (3) },
         pubLocation  GeneralName OPTIONAL }
id-regCtrl-pkiArchiveOptions   OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.4 }
   PKIArchiveOptions ::= CHOICE {
      encryptedPrivKey     [0] EncryptedKey,
      -- the actual value of the private key
      keyGenParameters     [1] KeyGenParameters,
      -- parameters which allow the private key to be re-generated
      archiveRemGenPrivKey [2] BOOLEAN }
      -- set to TRUE if sender wishes receiver to archive the private
      -- key of a key pair that the receiver generates in response to
      -- this request; set to FALSE if no archival is desired.

   EncryptedKey ::= CHOICE {
      encryptedValue        EncryptedValue, -- deprecated
      envelopedData     [0] EnvelopedData }
      -- The encrypted private key MUST be placed in the envelopedData
      -- encryptedContentInfo encryptedContent OCTET STRING.

   KeyGenParameters ::= OCTET STRING

id-regCtrl-oldCertID           OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.5 }
   CertId ::= SEQUENCE {
         issuer           GeneralName,
         serialNumber     INTEGER
     }
id-regCtrl-protocolEncrKey     OBJECT IDENTIFIER ::=  { 1.3.6.1.5.5.7.5.1.6 } with SubjectPublicKeyInfo as a value
*/

class AtributeTypeAndValues {
  public $atvs;

  function encode() {
    $encoded = '';
    foreach($atvs as $atv)
      $encoded .= $atv->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($atvs) {
    $decoded = asn1decode($atvs);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $atvs = $decoded['value'];
    else
      throw new Exception("AtributeTypeAndValues::decode() error: bad message check: expected an ASN.1 SEQUENCE for AtributeTypeAndValues, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($atvs) > 2) {
      $atv = new AtributeTypeAndValue();
      $next = $atv->decode($atvs);
      $this->atvs[] = clone $atv;
      $atvs = substr($atvs, $next);
    }
    return $offset;
  }

  function __construct($atvs) {
    $this->atvs = array();
    if (! is_null($atvs))
      $this->decode($atvs);
  }
}

class AttributeTypeAndValue {
  public $attrType;
  public $attrValue;
  public $attrValueType;

  function __toString() {
    switch($this->attrType) {
      case '2.5.4.5':
        $rdn = '/serialNumber=' . $this->attrValue;
      break;
      case '2.5.4.6':
        $rdn = '/c=' . $this->attrValue;
      break;
      case '2.5.4.8':
        $rdn = '/st=' . $this->attrValue;
      break;
      case '2.5.4.7':
        $rdn = '/l=' . $this->attrValue;
      break;
      case '2.5.4.9':
        $rdn = '/street=' . $this->attrValue;
      break;
      case '2.5.4.10':
        $rdn = '/o=' . $this->attrValue;
      break;
      case '2.5.4.11':
        $rdn = '/ou=' . $this->attrValue;
      break;
      case '2.5.4.12':
        $rdn = '/title=' . $this->attrValue;
      break;
      case '2.5.4.3':
        $rdn = '/cn=' . $this->attrValue;
      break;
      case '2.5.4.32':
        $rdn = '/owner=' . $this->attrValue;
      break;
      case '2.5.4.42':
        $rdn = '/givenName=' . $this->attrValue;
      break;
      case '2.5.4.4':
        $rdn = '/sn=' . $this->attrValue;
      break;
      case '2.5.4.43':
        $rdn = '/initials=' . $this->attrValue;
      break;
      case '2.5.4.44':
        $rdn = '/generationQualifier=' . $this->attrValue;
      break;
      case '2.5.4.46':
        $rdn = '/dnQualifier=' . $this->attrValue;
      break;
      case '2.5.4.65':
        $rdn = '/pseudonym=' . $this->attrValue;
      break;
      case '2.5.4.72':
        $rdn = '/role=' . $this->attrValue;
      break;
      case '0.9.2342.19200300.100.1.25':
        $rdn = '/dc=' . $this->attrValue;
      break;
      case '1.2.840.113549.1.9.1':
        $rdn = '/emailAddress=' . $this->attrValue;      
      break;
      default:
      break;
    }
    return $rdn;
  }

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->attrType);
    switch($this->attrType) {
      case '1.3.6.1.5.5.7.5.1.1': //regToken
      break;
      case '1.3.6.1.5.5.7.5.1.2': //Authenticator
      break;
      case '1.3.6.1.5.5.7.5.1.3': //pkiPublicationInfo
      break;
      case '1.3.6.1.5.5.7.5.1.4': //pkiArchiveOptions
      break;
      case '1.3.6.1.5.5.7.5.1.5': //oldCertId
        $encoded .= $this->attrValue->encode();
      break;
      default:
        $encoded .= asn1encode($class = 0, $constructed = false, $type = $this->attrValueType, $value = $this->attrValue);
      break;
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($atv) {
    $iter = 0;
    $decoded = asn1decode($atv);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $atv = $decoded['value'];
    else
      throw new Exception("AttributeTypeAndValue::decode() error: bad message check: expected an ASN.1 SEQUENCE for AttributeTypeAndValue, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($atv) > 2) {
      switch($iter) {
        case 0: //attrType
          $decoded = asn1decode($atv);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->attrType = $decoded['value'];
            $next = $decoded['length'] + $decoded['hl'];
          } else
            throw new Exception("AttributeTypeAndValue::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //attrValue
          switch($this->attrType) {
            case '1.3.6.1.5.5.7.5.1.1': //regToken
            break;
            case '1.3.6.1.5.5.7.5.1.2': //Authenticator
            break;
            case '1.3.6.1.5.5.7.5.1.3': //pkiPublicationInfo
            break;
            case '1.3.6.1.5.5.7.5.1.4': //pkiArchiveOptions
            break;
            case '1.3.6.1.5.5.7.5.1.5': //CertId
              $this->attrValue = new CertId();
              $next = $this->attrValue->decode($atv);
              $this->attrValueType = SEQUENCE;
            break;
            default:
              $decoded = asn1decode($atv);
              if (! $decoded['constructed']) {
                $this->attrValue = $decoded['value'];
                $this->attrValueType = $decoded['type'];
              } else
                throw new Exception("AttributeTypeAndValue::decode() error: bad message check: expected an ASN.1 primitive class for an attribute value, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
              $next = $decoded['length'] + $decoded['hl'];
            break;
          }
        break;
        default:
          throw new Exception("AttributeTypeAndValue::decode() error: bad message check: string is too long");
      }
      $atv = substr($atv, $next);
      $iter++;
    }
    return $offset;
  }
/*
   Implementers should note that the DER encoding of the SET OF values
   requires ordering of the encodings of the values.  In particular,
   this issue arises with respect to distinguished names.

   Implementers should note that the DER encoding of SET or SEQUENCE
   components whose value is the DEFAULT omit the component from the
   encoded certificate or CRL.  For example, a BasicConstraints
   extension whose cA value is FALSE would omit the cA boolean from the
   encoded certificate.
*/

  function __construct($atv = null) {
    if (! is_null($atv)) {
      if (is_string($atv)) {
        list($key, $val) = explode('=', $atv);
        if ($key[0] == '0' || $key[0] == '1' || $key[0] == '2') 
          $k = oid2str($key);
        else $k = strtolower($key);
        switch($k) {
          case 'c': //X520countryName ::=     PrintableString (SIZE (2)), from rfc5280, appendix A
            $this->attrType = '2.5.4.6';
            if (strlen($val) > 2)
              throw new Exception("Country is too long, must be a 2-letter string");
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'st': //DirectoryString - a choice of TeletexString, PrintableString, UniversalString, UTF8String, and BMPString
            $this->attrType = '2.5.4.8';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'l': //DirectoryString
            $this->attrType = '2.5.4.7';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'street':
            $this->attrType = '2.5.4.9';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'o': //DirectoryString
            $this->attrType = '2.5.4.10';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'ou': //DirectoryString
            $this->attrType = '2.5.4.11';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'title': //DirectoryString
            $this->attrType = '2.5.4.12';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'cn': //DirectoryString
            $this->attrType = '2.5.4.3';
            $this->attrValue = $val;
            $this->attrValueType = UTF8_STRING; //because singing CA ($singing_ca_path) has CN encoded as UTF8_STRING
          break;
          case 'name': //DirectoryString
            $this->attrType = '2.5.4.41';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'givenname': //DirectoryString
            $this->attrType = '2.5.4.42';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'sn': //DirectoryString
            $this->attrType = '2.5.4.4';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'serialNumber': //X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))
            $this->attrType = '2.5.4.5';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'owner':
            $this->attrType = '2.5.4.32';
            $this->attrValue = $val;
            $this->attrValueType = UTF8_STRING;
          break;
          case 'initials': //DirectoryString
            $this->attrType = '2.5.4.43';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'generationQualifier': //DirectoryString
            $this->attrType = '2.5.4.44';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'dnQualifier': //PrintableString
            $this->attrType = '2.5.4.46';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'pseudonym': //DirectoryString
            $this->attrType = '2.5.4.65';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'role':
            $this->attrType = '2.5.4.72';
            $this->attrValue = $val;
            $this->attrValueType = PRINTABLE_STRING;
          break;
          case 'dc': //DomainComponent ::=  IA5String
            $this->attrType = '0.9.2342.19200300.100.1.25';
            $this->attrValue = $val;
            $this->attrValueType = IA5_STRING; //ASCII
          break;
          case 'emailAddress': //emailAddress ::=  IA5String
            $this->attrType = '1.2.840.113549.1.9.1';
            $this->attrValue = $val;
            $this->attrValueType = IA5_STRING; //ASCII
          break;
          default: 
          break;
/*
default type for other fields is
CHOICE {
      teletexString     TeletexString   (SIZE (1..max)),
      printableString   PrintableString (SIZE (1..max)),
      universalString   UniversalString (SIZE (1..max)),
      utf8String        UTF8String      (SIZE (1..max)),
      bmpString         BMPString       (SIZE (1..max)) }
where max is different of each type
Conforming RFC5280 implementations MUST support UTF8String and PrintableString (and IA5_STRING for dc I suppose).
Conforming implementations MUST support name comparisons using caseIgnoreMatch, which
is simply defined as being a case-insensitive comparison where insignificant spaces are ignored,
which only works for printableString. Detail comparison rules are described in RFC5280 Section 7.
*/
        }
      }
    }
  }
}
