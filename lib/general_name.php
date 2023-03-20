<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'atv.php';

/*
DistinguishedName ::= RDNSequence

Name ::= CHOICE { -- only one possibility for now --
 rdnSequence RDNSequence }

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::=
 SET SIZE (1 .. MAX) OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
 type OBJECT IDENTIFIER,
 value ANY DEFINED BY type }

from rfc2247 (Using Domains in LDAP/X.500 Distinguished Names):
The DC (short for domainComponent) attribute type is defined as
   follows:

    ( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreIA5Match
     SUBSTR caseIgnoreIA5SubstringsMatch
     SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )

The DirectoryString ASN.1 type allows a choice between the
   TeletexString, PrintableString, or UniversalString ASN.1 types from
   [ASN.1]
*/

class RDN {
  public $atvSet;

  function encode() {
    $atvSet = '';
    foreach($this->atvSet as $atv)
      $atvSet .= $atv->encode();
    return asn1encode($class = 0, $constructed = true, $type = SET, $value = $atvSet);
  }

  function decode($atvSet) {
    $decoded = asn1decode($atvSet);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SET)
      $atvSet = $decoded['value'];
    else
      throw new Exception("RDN::decode() error: bad message check: expected an ASN.1 SET for RDN, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while (strlen($atvSet) > 2) {
      $atv = new AttributeTypeAndValue();
      $next = $atv->decode($atvSet);
      $this->atvSet[] = $atv;
      $atvSet = substr($atvSet, $next);
    }
    return $offset;
  }

  function __construct($atvSet = null) {
    $this->atvSet = array();
    if (! is_null($atvSet)) {
      if (is_string($atvSet))
        $this->atvSet[] = new AttributeTypeAndValue($atvSet);
      else
        throw new Exception("RDN::__construct() error: an argument is neither null nor a string");
    }
  }

  function __clone() {
    foreach($this->atvSet as $set)
      $set = clone $set;
  }
}

class Name {
  public $rdnSeq;

  function addOwner($owner) {
    if (! $this->getOwner())
      $this->rdnSeq[] = new RDN("owner=$owner");
  }

  function getOwner() {
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        if ($atv->attrType == '2.5.4.32') //owner
          return $atv->attrValue;    
      }
    }
    return false;
  }

  function addRole($role) {
    if (! $this->getRole())
      $this->rdnSeq[] = new RDN("role=$role");
  }

  function getRole() {
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        if ($atv->attrType == '2.5.4.72') //role
          return $atv->attrValue;    
      }
    }
    return false;
  }

  function getCN() {
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        if ($atv->attrType == '2.5.4.3') //cn
          return $atv->attrValue;    
      }
    }
    return false;
  }
  
  function getEmail() {
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        if ($atv->attrType == '1.2.840.113549.1.9.1') //emailAddress
          return $atv->attrValue;    
      }
    }
    return false;
  }
  
  function __toString() {
    $dn = '';
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        $dn .= $atv;
      }
    }
    return $dn;  
  }

  //this comparison is too simple and is not conformant to RFC5280 section 7!
  function equals($name) {
    foreach($this->rdnSeq as $rdn) {
      foreach($rdn->atvSet as $atv) {
        $res = false;
        foreach($name->rdnSeq as $dn) {
          foreach($dn->atvSet as $tv) {
            if ($atv->attrType == $tv->attrType && strcasecmp($atv->attrValue, $tv->attrValue) == 0)
              $res = true;
          }
        }
      }
    }
    return $res;
  }

  function encode($implicit = false) {
    if (is_null($this->rdnSeq) || count($this->rdnSeq) == 0)
      $dn = ''; //asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
    else {
      $dn = '';
      foreach($this->rdnSeq as $set)
        $dn .= $set->encode(); 
    }
    if ($implicit) return $dn;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $dn);
  }

  function decode($name) {
    $decoded = asn1decode($name);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $name = $decoded['value'];
    else
      throw new Exception("Name::decode() error: bad message check: expected an ASN.1 SEQUENCE for name, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($name) > 2) {
      $rdn = new RDN();
      $next = $rdn->decode($name);
      $this->rdnSeq[] = $rdn;
      $name = substr($name, $next);
    }
    return $offset;
  }

  protected function map($name) {
    foreach($name as $key => $set) {
      if (empty($set)) continue;
      $this->rdnSeq[] = new RDN($set);
    }
  }

  function __construct($name = null) {
    $this->rdnSeq = array();
    if (! is_null($name)) {
      if (is_string($name)) { //format: '/c=CA/st=Ontario/l=Toronto/street=Main/dc=example/dc=com/cn=example.com'
        $this->map(explode('/', $name));
      } else
        throw new Exception("Name::__construct() error: argument is neither null nor an array");
    }
  }

  function __clone() {
    foreach($this->rdnSeq as $seq)
      $seq = clone $seq;
  }
}

/*
GeneralName ::= CHOICE {
 otherName [0] OtherName,
 rfc822Name [1] IA5String, //email addresses as described in RFC822
 dNSName [2] IA5String, //dns names
 x400Address [3] ORAddress,
 directoryName [4] Name, //DN - this one is used most in PKI
 ediPartyName [5] EDIPartyName,
 uniformResourceIdentifier [6] IA5String, //URI
 iPAddress [7] OCTET STRING, //IP addreses
 registeredID [8] OBJECT IDENTIFIER }

OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }
*/

class GeneralName extends Name {
  public $type;
  public $name; //string in a format '/C=CA/L=Toronto/CN=test.com', for example for DN, or an IP address or a DNS name

  function dn2dns() {
    if ($this->type != 4)
      throw new Exception("GeneralName::dn2dns() error: the type is not a DN");
    foreach($this->rdnSeq as $seq) {
      foreach($seq->atvSet as $atv) {
        if ($atv->attrType == '2.5.4.3') {
          if (check_cn($atv->attrValue)) {
            $this->type = 2;
            $this->name = $atv->attrValue;
            $this->rdnSeq = null;
            return true;
          } 
        }
      }
    }
    return false;
  }

  function encode($implicit = false) {
    switch($this->type) {
      case 1: //email
        if ($implicit) $encoded = $this->name;
        else
          $encoded = asn1encode($class = 0, $constructed = false, $type = IA5_STRING, $value = $this->name);
      break;
      case 2: //DNS
        if ($implicit) $encoded = $this->name;
        else
          $encoded = asn1encode($class = 0, $constructed = false, $type = IA5_STRING, $value = $this->name);
      break;
      case 4: //DN
        $encoded = parent::encode();
      break;
      case 6: //URI
        if ($implicit) $encoded = $this->name;
        else
          $encoded = asn1encode($class = 0, $constructed = false, $type = IA5_STRING, $value = $this->name);
      break;
      case 7: //IP
        if ($implicit)
          $encoded = encode(OCTET_STRING, bin2hex(inet_pton($this->name)));
        else
          $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = bin2hex(inet_pton($this->name)));
      break;
      case 8: //OID
        if ($implicit)
          $encoded = encode(OBJECT_IDENTIFIER, $this->name);
        else
          $encoded = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->name);
      break;
      default:
        throw new Exception("GeneralName:encode() error: unknown or unsupported type: " . print_r($this->type, true));
    }
    if ($implicit)
      return asn1encode($class = 2, $constructed = false, $type = $this->type, $value = $encoded);
    return asn1encode($class = 2, $constructed = true, $type = $this->type, $value = $encoded);
  }

  function decode($generalName, $implicit = false) {
    if ($implicit) $constructed = false;
    else $constructed = true;
    $decoded = asn1decode($generalName);
    if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] == $constructed && $decoded['type'] >= 0 && $decoded['type'] <= 8)
      $generalName = $decoded['value'];
    else
      throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC class and type between 0 and 8 for generalName, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    $this->type = $decoded['type'];
    switch($this->type) {
      case 0: //otherName
        throw new Exception("GeneralName::map() error: General name type AnotherName is not implemented");
      break;
      case 1: //rfc822 (email)
        if ($implicit)
          $this->name = decode(IA5_STRING, $decoded['value']);
        else {
          $decoded = asn1decode($decoded['value']);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == IA5_STRING)
            $this->name = $decoded['value'];
          else
            throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 IA5_STRING for email, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        }
      break;
      case 2: //DNS
        if ($implicit)
          $this->name = decode(IA5_STRING, $decoded['value']);
        else {
          $decoded = asn1decode($decoded['value']);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == IA5_STRING)
            $this->name = $decoded['value'];
          else
            throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 IA5_STRING for dns, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        }
      break;
      case 3: //x400 Address
        throw new Exception("GeneralName::map() error: General name type X400 is not implemented");
      break;
      case 4: //DN
        parent::decode($decoded['value']);
      break;
      case 5: //ediPartyName
        throw new Exception("GeneralName::map() error: General name type ediParty is not implemented");
      break;
      case 6: //URI
        if ($implicit)
          $this->name = decode(IA5_STRING, $decoded['value']);
        else {
          $decoded = asn1decode($decoded['value']);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == IA5_STRING)
            $this->name = $decoded['value'];
          else
            throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 IA5_STRING for uri, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        }
      break;
      case 7: //IP Address
        if ($implicit)
          $this->name = inet_ntop(hex2bin(decode(OCTET_STRING, $decoded['value'])));
        else {
          $decoded = asn1decode($decoded['value']);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
            $this->name = inet_ntop(hex2bin($decoded['value']));
          else
            throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 OCTET_STRING for ip, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        }
      break;
      case 8: //registered OID 
        if (is_array($generalName)) $this->name = decode(OBJECT_IDENTIFIER, $generalName['value']);
        elseif (is_string($generalName)) $this->name = $generalName;
      break;
      default:
        throw new Exception("GeneralName::map() error: General name type is unknown");
    }
    return $offset;
  }

  protected function map($generalName) {
    switch($this->type) {
      case 0: //otherName
        throw new Exception("GeneralName::map() error: General name type AnotherName is not implemented");
      break;
      case 1: //rfc822 (email)
        $this->name = $generalName;
      break;
      case 2: //DNS
        $this->name = $generalName;
      break;
      case 3: //x400 Address
        throw new Exception("GeneralName::map() error: General name type X400 is not implemented");
      break;
      case 4: //DN
        parent::map(explode('/', $generalName));
        $this->name = $generalName;
      break;
      case 5: //ediPartyName
        throw new Exception("GeneralName::map() error: General name type ediParty is not implemented");
      break;
      case 6: //URI
        $this->name = $generalName;
      break;
      case 7: //IP Address
        $this->name = $generalName;
      break;
      case 8: //registered OID 
        $this->name = $generalName;
      break;
      default:
        throw new Exception("GeneralName::map() error: General name type is unknown");
    }
  }
  
  function __construct($generalName = null) {
    global $allowed_ips_in_san;
    if (is_null($generalName)) {
      $this->name = null;
      $this->rdnSeq = null;
      $this->type = null;
    } elseif (is_string($generalName)) { //format: '/c=CA/st=Ontario/l=Toronto/street=Main/dc=example/dc=com/cn=example.com' or dns or IP
        $ipRegex = "/\A(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\z/";
        if (preg_match($ipRegex, $generalName)) {
          $this->type = 7; //IP
          if (! preg_match($allowed_ips_in_san, $generalName))
            throw new Exception("IP address in SAN $generalName does not match the allowed IP regex $allowed_ips_in_san");
        }
        elseif (str_starts_with($generalName, '/'))
          $this->type = 4; //DN
        elseif (str_contains($generalName, '@'))
          $this->type = 1; //email
        elseif (str_contains($generalName, ':'))
          $this->type = 6; //URI
        elseif (preg_match("/\A([0-1]\.[0-3][0-9]{0,1}|2)(\.[0-9]{1}[0-9]{0,20}){1,20}\z/", $generalName))
          $this->type = 8; //OID
        else $this->type = 2; //DNS
        $this->map($generalName);
    } else
      throw new Exception("GeneralName::__construct() error: argument is neither null nor an array nor a string " . print_r($generalName, true));
  }

  function __toString() {
    if (is_null($this->name)) return parent::__toString();
    return $this->name;
  }
}

class GeneralNames {
  public $generalNames;

  function encode() {
    $encoded = '';
    foreach($this->generalNames as $gn)
      $encoded .= $gn->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($generalNames) {
    $decoded = asn1decode($generalNames);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $generalNames = $decoded['value'];
    else
      throw new Exception("GeneralName::decode() error: bad message check: expected an ASN.1 SEQUENCE for generalNames, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($generalNames) > 2) {
      $gn = new GeneralName();
      $next = $gn->decode($generalNames);
      $this->generalNames[] = $gn;
      $generalNames = substr($generalNames, $next);
    }
    return $offset;    
  }

  function __construct() {
    $this->generalNames = array();
  }

}

?>