<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'helper_functions.php';
require_once 'general_name.php';

/*
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension ::= SEQUENCE {
 extnID OBJECT IDENTIFIER,
 critical BOOLEAN DEFAULT FALSE,
 extnValue OCTET STRING }
*/

class Extensions {
  public $extensions;
  
    function getOCSPNonce() {
    $iter = 0;
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '1.3.6.1.5.5.7.48.1.2') == 0)
        return $iter;
      $iter++;
    }
    return false;
  }

  //$eku argument is ExtendedKeyUsage extension from a certTemplate
  //if it's null, then we'll try to retrieve it from $this->extensions
  function checkExtendedKeyUsage($eku = null) {
    if (is_null($eku)) 
      $eku = $this->getExtendedKeyUsage();
    if (! $eku) return true;
    $keyUsage = $this->getKeyUsage();
    if (! $keyUsage) return false;
    extract($keyUsage);
    if (isset($digitalSignature) && isset($keyEncipherment) && isset($keyAgreement) && isset($nonRepudiation)) {
      $res = true;
      foreach($eku as $u) {
        switch(oid2str($u)) {
          case 'TLS Web Server Authentication':
            if (! $digitalSignature || (! $keyEncipherment && ! $keyAgreement))
              $res = false;
          break;
          case 'TLS Web Client Authentication':
            if (! $digitalSignature && ! $keyAgreement)
              $res = false;
          break;
          case 'Code Signing':
            if (! $digitalSignature)
              $res = false;
          break;
          case 'E-mail Protection':
            if (! $digitalSignature || (! $nonRepudiation && (! $keyEncipherment && ! $keyAgreement)))
              $res = false;
          break;
          case 'Time Stamping':
            if (! $digitalSignature && ! $nonRepudiation)
              $res = false;
          break;
          case 'OCSP Signing':
            //we do not allow ocsp signing
            //if (! $digitalSignature && ! $nonRepudiation)
            $res = false;
          break;
          default: break;
        }
      }
      return $res;
    }
    return true;
  }

  function set($certTemplate, $owner = null, $defaultExtKeyUsages = true, $role = 'standard', $acme = false) {
    global $max_san, $default_extensions, $forbidden_extensions, $default_key_usages, $default_extended_key_usages, $signing_ca_der_path, $base_url;

    //check and copy extensions from certTemplate
    $clientExtensions = array();
    if (! is_null($certTemplate->extensions) && $certTemplate->extensions instanceof Extensions && is_array($certTemplate->extensions->extensions)) {
      foreach($certTemplate->extensions->extensions as $extension) {
        if (in_array(oid2str($extension), $forbidden_extensions)) {
          continue;
        }
        $ext = clone $extension;
        switch($ext->extnID) {
          case '2.5.29.15': //keyUsage
            $ext->verifyKeyUsage();
            $ext->setKeyUsage($ext->getKeyUsage());
          break;
          case '2.5.29.17': //san
            if (is_null($owner)) { //do not add SAN if owner is null and not SMIME cert
              $email = false; //not SMIME
              $sans = $ext->getSubjectAltName();
              if ($sans) {
                foreach ($sans as $san) {
                  if ($san->type == 1) { //EMAIL
                    $email = true; //SMIME cert, which should have empty subject; hence no owner in the subject
                    break;
                  }
                }
              }
              if (! $email) {
                $ext = null;
                break;
              }
            }
            $newSan = $ext->checkSubjectAltName($role, $acme);
            if (! $newSan) 
              $ext = null;
            else {
              $sanN = count($newSan);
              if ($sanN == 0) $ext = null; 
              elseif ($sanN > $max_san)
                throw new Exception("Extensions::set() error: too many SANs: the max SANs is $max_san, requested $sanN");
              else $ext->setSubjectAltName($newSan);
            }
          break;
          case '2.5.29.37': //extKeyUsage
            $eku = $ext->getExtendedKeyUsage();
          break;
        }
        if (! is_null($ext)) {
          $this->extensions[] = $ext;
          $clientExtensions[] = $ext->extnID;
        }
      }
      if (isset($eku)) {
        $res = $this->checkExtendedKeyUsage($eku);
        if (! $res)
          throw new Exception("Extensions::set() error: incompatible key and extended key usages");
      }
    }
    //add missing extensions
    foreach ($default_extensions as $ext) {
      if (in_array(str2oid($ext), $clientExtensions)) continue; 
      $extension = new Extension();
      switch($ext) {
        case 'X509v3 Subject Key Identifier':
          $extension->setSubjectKeyIdentifier(bin2hex($certTemplate->publicKey->subjectPublicKey->encode()));
        break;
        case 'X509v3 Authority Key Identifier':
          $signingCert = new Certificate($signing_ca_der_path);
          $extension->setAuthorityKeyIdentifier($signingCert->tbsCertificate->publicKey->subjectPublicKey->encode());
        break;
        case 'X509v3 Basic Constraints':
          $extension->setBasicConstraints();
        break;
        case 'X509v3 Key Usage':
          $extension->setKeyUsage($default_key_usages);
        break;
        case 'X509v3 Extended Key Usage':
          if ($defaultExtKeyUsages) {
            //only add default extended key usages if they are compatible with existing key usages
            if ($this->checkExtendedKeyUsage($default_extended_key_usages))
              $extension->setExtendedKeyUsage($extKeyUsages = $default_extended_key_usages);
            else $extension = null;
          } else $extension = null;
        break;
        case 'X509v3 Subject Alternative Name':
          $dn = clone $certTemplate->subject;
          if ($cn = $dn->getCN()) {
            if (! $acme && ! check_cn($cn, $role))
              throw new Exception("Extensions::set() error: Unaccepted SAN extension: CN $cn in the cert template subject is not from the list of approved domains: $base_url/domains.txt");
            elseif (! is_null($owner)) { //only add SAN if owner is not null
              $san = array();
              $san[] = new GeneralName($cn);
              $extension->setSubjectAltName($san);
            } else $extension = null;
          } elseif ($cn = $dn->getEmail()) {
              $san = array();
              $san[] = new GeneralName($cn);
              $extension->setSubjectAltName($san);          
          } else {
            if (! in_array(str2oid('E-mail Protection'), $eku))
              throw new Exception("Extensions::set() error: Unaccepted SAN extension: missing CN in the cert template subject");
          }
        break;
        case 'X509v3 CRL Distribution Points':
          $extension->setCrlDistributionPoints();
        break;
        case 'Authority Information Access':
          $extension->setAIA();
        break;
        default: 
          $extension = null;
        break;
      }
      if (! is_null($extension))
        $this->extensions[] = $extension;
    }
  }

  function getSubjectKeyIdentifier() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.14') == 0)
        return $ext->getSubjectKeyIdentifier();
    }
    return false;
  }

  function getAuthorityKeyIdentifier() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.35') == 0) 
        return $ext->getAuthorityKeyIdentifier();
    }
    return false;
  }

  function getCertificateTemplateName() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '1.3.6.1.4.1.311.20.2') == 0) 
        return $ext->getCertificateTemplateName();
    }
    return false;
  }

  function getCrlNumber() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.20') == 0)
        return $ext->getCrlNumber();
    }
    return false;
  }

  function getKeyUsage() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.15') == 0)
        return $ext->getKeyUsage();
    }
    return false;
  }

  //$keyUsage is an assoc. array ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'crlSign', 'encipherOnly', 'decipherOnly']
  //where the key (bit) to check should be set to 1 and other keys removed
  function checkKeyUsage($keyUsage) {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.15') == 0)
        return $ext->checkKeyUsage($keyUsage);
    }
    return false;
  }

  function getExtendedKeyUsage() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.37') == 0)
        return $ext->getExtendedKeyUsage();
    }
    return false;
  }

  function getSubjectAltName() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.17') == 0)
        return $ext->getSubjectAltName();
    }
    return false;
  }

  function setSubjectAltName($generalNames, $merge = false) {
    $found = false;
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.17') == 0) {
        if ($merge) {
          $sans = $ext->getSubjectAltName();
          foreach ($generalNames as $gn) {
            if (! in_array($gn, $sans))
              $sans[] = $gn;
          }
          $ext->setSubjectAltName($sans);
        } else
          $ext->setSubjectAltName($generalNames);
        $found = true;
      }
    }
    if (! $found) {
      $ext = new Extension();
      $ext->setSubjectAltName($generalNames);
      $this->extensions[] = $ext;
    }
  }

  function checkSubjectAltName($role = 'standard', $acme = false) {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.17') == 0)
        return $ext->checkSubjectAltName($role, $acme);
    }
    return false;
  }

  function getBasicConstraints() {
    foreach($this->extensions as $ext) {
      if (strcmp($ext->extnID, '2.5.29.19') == 0)
        return $ext->getBasicConstraints();
    }
    return false;
  }

  function encode($implicit = false) {
    $encoded = '';
    foreach ($this->extensions as $ext) {
      $encoded .= $ext->encode();
    }
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($extensions, $implicit = false) {
    if (! $implicit) {
      $decoded = asn1decode($extensions);
      if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
        $extensions = $decoded['value'];
      else
        throw new Exception("Extensions::decode() error: bad message check: expected an ASN.1 SEQUENCE for extensions, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $offset = $decoded['length'] + $decoded['hl'];
    } else $offset = strlen($extensions);
    while(strlen($extensions) > 2) {
      $ext = new Extension();
      $next = $ext->decode($extensions);
      $this->extensions[] = $ext;
      $extensions = substr($extensions, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->extensions = array();
  }
}

class Extension {
  public $extnID;
  public $critical;
  public $extnValue;
  
  function setOCSPExtendedRevoke() {
    $this->extnID = '1.3.6.1.5.5.7.48.1.9';
    $this->extnValue = null;
  }

  function getOCSPNonce() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
      return $decoded['value'];
    else
      throw new Exception("Extension::getCrlNumber() error: expected an ASN.1 INTEGER for CrlNumber, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), 2);
  }

  function verifyKeyUsage() {
    $keyUsage = $this->getKeyUsage();
    if ($keyUsage['keyCertSign'] == 1 || $keyUsage['crlSign'] == 1) {
      $keyUsage['keyCertSign'] = 0;
      $keyUsage['crlSign'] = 0;
    }
    if (($keyUsage['encipherOnly'] == 1 || $keyUsage['decipherOnly'] == 1) && $keyUsage['keyAgreement'] == 0) {
      $keyUsage['encipherOnly'] = 0;
      $keyUsage['decipherOnly'] = 0;
    }
    $this->setKeyUsage($keyUsage);
  }

  function checkSubjectAltName($role = 'standard', $acme = false) {
    global $allowed_ips_in_san, $base_url;
    $sans = $this->getSubjectAltName();
    $newSan = array();
    foreach($sans as $san) {
      switch($san->type) {
        case 1: //Email
          $newSan[] = new GeneralName($san->name);
        break;
        case 2: //DNS
          if (! $acme && ! check_cn($san->name, $role))
              throw new Exception("Extension::checkSubjectAltName() error: unaccepted SAN extension: CN " . $san->name . " in the cert template subject is not from the list of approved domains: $base_url/domains.txt");
          $newSan[] = new GeneralName($san->name);
        break;
        case 7: //IP
          if (! preg_match($allowed_ips_in_san, $san->name))
            throw new Exception("SAN IP $san->name is invalid or not in approved format. Approved IP range regex is $allowed_ips_in_san"); 
          $newSan[] = new GeneralName($san->name);
        break;        
        default:
          throw new Exception("Extension::checkSubjectAltName() error: unsupported GeneralName type $san->type. Only Email (1), DNS (2) and IP (7) are supported in SAN at this time");
      }
    }
    $newSan = array_unique($newSan);
    if (count($newSan) == 0) return false;
    return $newSan;
  }

/*
id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { 2.5.29.14 }

   SubjectKeyIdentifier ::= KeyIdentifier

      (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
           value of the BIT STRING subjectPublicKey (excluding the tag,
           length, and number of unused bits).
OR
      (2) The keyIdentifier is composed of a four-bit type field with
           the value 0100 followed by the least significant 60 bits of
           the SHA-1 hash of the value of the BIT STRING
           subjectPublicKey (excluding the tag, length, and number of
           unused bits).
*/

  function setSubjectKeyIdentifier($pubkey) {
    $this->extnID = '2.5.29.14';
    $encoded = hash('sha1', hex2bin($pubkey), $binary = false);
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $encoded));
  }
  
  function getSubjectKeyIdentifier() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING)
      return $decoded['value'];
    else
      throw new Exception("Extensions::getSubjectKeyIdentifier() error: expected an ASN.1 OCTET_STRING for SubjectKeyIdentifier, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
  }

  function getCertificateTemplateName() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BMP_STRING)
        return $decoded['value'];
    else
      throw new Exception("Extensions::getCertificateTemplateName() error: expected an ASN.1 BMP_STRING for CertificateTemplateName, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
  }

/*
id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { 2.5.29.35 }

   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING
*/

  function setAuthorityKeyIdentifier($subjectPublicKey) {
    $this->extnID = '2.5.29.35';
    $encoded = hash('sha1', $subjectPublicKey, $binary = true);
    $encoded = asn1encode($class = 2, $constructed = false, $type = 0, $value = $encoded);
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded));
  }

  function getAuthorityKeyIdentifier() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE) {
      $kid = asn1decode($decoded['value']);
    } else
      throw new Exception("Extension::getAuthorityKeyIdentifier() error: expected an ASN.1 SEQUENCE for AuthorityKeyIdentifier, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $decoded = asn1decode($kid);
    if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['type'] <= 0 && $decoded['type'] >= 2) {
      switch($decoded['type']) {
        case 0: //keyId
          if (! $decoded['constructed'])
            return bin2hex($decoded['value']);
        break;
        case 1: //authorityCertIssuer - generalNames
          if ($decoded['constructed'])
            return new GeneralNames($decoded['value']);
        break;
        case 2: //authorityCertSerialNumber - certSerialNumber
          if (! $decoded['constructed'])
            return $decoded['value'];
        break;
      }
    } else
      throw new Exception("Extension::getAuthorityKeyIdentifier() error: expected an ASN.1 CONTEXT_SPECIFIC class and type between 0 and 2 for AuthorityKeyIdentifier type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
  }

/*
id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
      KeyUsage ::= BIT STRING {
           digitalSignature        (0), - most significant bit!
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) } - least significant bit!

   Named bit lists are BIT STRINGs where the values have been assigned
   names.  This specification makes use of named bit lists in the
   definitions for the key usage, CRL distribution points, and freshest
   CRL certificate extensions, as well as the freshest CRL and issuing
   distribution point CRL extensions.  When DER encoding a named bit
   list, trailing zeros MUST be omitted.  That is, the encoded value
   ends with the last named bit that is set to one.
*/

  function setKeyUsage($keyUsage) {
    if (! is_array($keyUsage))
        throw new Exception("Extension::setKeyUsage() error: an argument is not an array");
    $this->extnID = '2.5.29.15';
    $ku = $keyUsage['decipherOnly'] | ($keyUsage['encipherOnly'] << 1) | ($keyUsage['crlSign'] << 2) | ($keyUsage['keyCertSign'] << 3) | ($keyUsage['keyAgreement'] << 4) | ($keyUsage['dataEncipherment'] << 5) | ($keyUsage['keyEncipherment'] << 6) | ($keyUsage['nonRepudiation'] << 7) | ($keyUsage['digitalSignature'] << 8); 
    if ($ku == 0)
      throw new Exception("At least one bit in keyUsage extension must be set");
    if ($keyUsage['decipherOnly'] == 0) $ku >>= 1;
    $res = strrchr(decbin($ku), '1');
    $unused_bits = $res ? dechex(strlen($res) - 1) : '00';
    if (strlen($unused_bits) % 2 != 0) $unused_bits = '0' . $unused_bits;
    $ku = dechex($ku);
    if (strlen($ku) % 2 != 0) $ku = '0' . $ku;
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = $unused_bits . $ku));
  }
  
  function getKeyUsage() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
      $ku = $decoded['value'];
    else
      throw new Exception("Extension::getKeyUsage() error: expected an ASN.1 BIT_STRING for keyUsage, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $ku = str_split(str_pad(decbin(hexdec($ku)), 9, '0'));
    $keyUsage['digitalSignature'] = $ku[0];
    $keyUsage['nonRepudiation'] = $ku[1];
    $keyUsage['keyEncipherment'] = $ku[2];
    $keyUsage['dataEncipherment'] = $ku[3];
    $keyUsage['keyAgreement'] = $ku[4];
    $keyUsage['keyCertSign'] = $ku[5];
    $keyUsage['crlSign'] = $ku[6];
    $keyUsage['encipherOnly'] = $ku[7];
    $keyUsage['decipherOnly'] = $ku[8];
    return $keyUsage;
  }

  function checkKeyUsage($keyUsage) {
    $certKeyUsage = $this->getKeyUsage();
    foreach($keyUsage as $key => $value) {
      foreach($certKeyUsage as $k => $v) {
        if (strcasecmp($key, $k) == 0) {
          if ($value != $v) return false;
        }
      }
    }
    return true;
  }

/*
id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

   SubjectAltName ::= GeneralNames
   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
   GeneralName ::= CHOICE {
        otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        x400Address                     [3]     ORAddress,
        directoryName                   [4]     Name,
        ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER }

   OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id }

   EDIPartyName ::= SEQUENCE {
        nameAssigner            [0]     DirectoryString OPTIONAL,
        partyName               [1]     DirectoryString }
*/

  function setSubjectAltName($generalNames) {
    $this->extnID = '2.5.29.17';
    $encoded = '';
    foreach($generalNames as $gn) {
      switch($gn->type) {
        case 0: //otherName
          throw new Exception("General name type OtherName is not implemented");
        case 1: //rfc822 (email)
          $encoded .= $gn->encode($implicit = true);
        break;
/*
from https://datatracker.ietf.org/doc/html/rfc1034#section-3.5 and https://datatracker.ietf.org/doc/html/rfc1123#section-2.1
<domain> ::= <subdomain> | " "
<subdomain> ::= <label> | <subdomain> "." <label>
<label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
<ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
<let-dig-hyp> ::= <let-dig> | "-"
<let-dig> ::= <letter> | <digit>

<letter> ::= any one of the 52 alphabetic characters A through Z in
upper case and a through z in lower case

<digit> ::= any one of the ten digits 0 through 9

So no underscore '_' or any other special characters in DNS names besides the hyphen '-'.

the restriction on the first character is relaxed to allow either a
letter or a digit.  Host software MUST support this more liberal
syntax.

Host software MUST handle host names of up to 63 characters and
SHOULD handle host names of up to 255 characters.
*/
        case 2: //dns
          $encoded .= $gn->encode($implicit = true);
        break;
        case 3: //x400Address
          throw new Exception("General name type x400Address is not implemented");
        case 4: //directoryName - Name type
          $encoded .= $gn->encode();
        break;
        case 5: //ediPartyName
          throw new Exception("General name type ediPartyName is not implemented");
        case 6: //uniformResourceIdentifier
          $encoded .= $gn->encode($implicit = true);
        break;
        case 7: //ipAddress - value octets must be in network order
          $encoded .= $gn->encode($implicit = true);
        break;
        case 8: //registeredID
          throw new Exception("General name type registeredID is not implemented");
        break;
      }
    }
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded));
  }

  function getSubjectAltName() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $gns = $decoded['value'];
    else
      throw new Exception("Extension::getSubjectAltName() error: expected an ASN.1 SEQUENCE for SubjectAltNames, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $san = array();
    while(strlen($gns) > 2) {
      $gn = new GeneralName();
      $next = $gn->decode($gns, $implicit = true);
      $san[] = $gn;
      $gns = substr($gns, $next);
    }
    return $san;
  }

/*
id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 }
   IssuerAltName ::= GeneralNames
id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
   SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
*/

/*
id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
*/

  function setBasicConstraints($critical = true, $ca = false, $len = 0) {
    $this->extnID = '2.5.29.19';
    $this->critical = $critical;
    $encoded = '';
    if ($ca) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = BOOLEAN, $value = 'TRUE');
      $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $len);
    }
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded));
  }

  function getBasicConstraints() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $basicConstraints = $decoded['value'];
    else
      throw new Exception("Extension::getBasicConstraints() error: expected an ASN.1 SEQUENCE for BasicConstraints, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $iter = 0;
    $ca = false;
    $len = 0;
    while(strlen($basicConstraints) > 2) {
      $decoded = asn1decode($basicConstraints);
      switch($iter) {
        case 0:
         if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BOOLEAN)
           $ca = $decoded['value'] == 'TRUE' ? true : false;
         elseif ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
           $len = $decoded['value'];
         else
           throw new Exception("Extension::getBasicConstraints() error: expected either an ASN.1 BOOLEAN for BasicConstraints CA or INTEGER for length, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1:
         if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
           $len = $decoded['value'];
         else
           throw new Exception("Extension::getBasicConstraints() error: expected either an ASN.1 INTEGER for BasicConstraints length, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
         throw new Exception("Extension::getBasicConstraints() error: string is too long");
      }
      $basicConstraints = substr($basicConstraints, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return ['ca' => $ca, 'len' => $len];
  }

/*
id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
   KeyPurposeId ::= OBJECT IDENTIFIER

   anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
   
   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

   id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement

   id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement

   id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature

   id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)

   id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation
*/

  function setExtendedKeyUsage($extKeyUsages, $critical = true) {
    $this->extnID = '2.5.29.37';
    $this->critical = $critical;
    $encoded = '';
    if (! is_array($extKeyUsages))
      throw new Exception("extKeyUsages is not an array");
    foreach ($extKeyUsages as $usage)
      $encoded .= asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = str2oid($usage));
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded));
  }

  function getExtendedKeyUsage() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $extKeyUsages = $decoded['value'];
    else
      throw new Exception("Extension::getExtendedKeyUsage() error: expected an ASN.1 SEQUENCE for ExtendedKeyUsages, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $iter = 0;
    $eku = array();
    while(strlen($extKeyUsages) > 2) {
      $decoded = asn1decode($extKeyUsages);
      if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER)
        $eku[] = $decoded['value'];
      else
        throw new Exception("Extension::getExtendedKeyUsage() error: expected either an ASN.1 OBJECT_IDENTIFIER for ExtendedKeyUsage, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $extKeyUsages = substr($extKeyUsages, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $eku;
  }

/*
id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }

   CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }
*/

  function setCrlDistributionPoints() {
    global $crl_distribution_points;
    $this->extnID = '2.5.29.31';
    $dp = '';
    foreach($crl_distribution_points as $point) {
      $uri = new GeneralName($point);
      $distributionPointName = asn1encode($class = 2, $constructed = true, $type = 0, $value = $uri->encode($implicit = true));
      $distributionPoint = asn1encode($class = 2, $constructed = true, $type = 0, $value = $distributionPointName);
      $dp .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $distributionPoint);
    }
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $dp));
  }

  function getCrlDistributionPoints() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $distPoints = $decoded['value'];
    else
      throw new Exception("Extension::getCrlDistributionPoints() error: expected an ASN.1 SEQUENCE for CrlDistributionPoints, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $iter = 0;
    $dps = array();
    while(strlen($distPoints) > 2) {
      $decoded = asn1decode($distPoints);
      if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed']) {
        switch($decoded['type']) {
          case 0: //distributionPoint (GeneralNames or RDNs)
            $decoded2 = asn1decode($decoded['value']);
            if ($decoded2['class'] == CONTEXT_SPECIFIC_CLASS && $decoded2['constructed']) {
              switch($decoded2['type']) {
                case 0: //generalNames
                  $gns = new GeneralNames();
                  $next = $gns->decode($decoded2['value']);
                  $dps = $gns->generalNames;
                break;
                case 1: //RelativeDistinguishedName 
                break;
                default:
              }
            }
          break;
          case 1: //reason
          break;
          case 2: //crlIssuer
          break;
          default:
        }
      } else
        throw new Exception("Extension::getCrlDistributionPoints() error: expected either an ASN.1 CONTEXT_SPECIFIC constructed class for CrlDistributionPoint, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
      $distPoints = substr($distPoints, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $dps;
  }

/*
id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }

   CRLNumber ::= INTEGER (0..MAX) //up to 20 octets monotonically increasing number
*/

  function setCrlNumber($crlNumber, $critical = false) {
    $this->extnID = '2.5.29.20';
    $this->critical = $critical;
    $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $crlNumber));
  }

  function getCrlNumber() {
    $decoded = asn1decode(hex2bin($this->extnValue));
    if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
      return $decoded['value'];
    else
      throw new Exception("Extension::getCrlNumber() error: expected an ASN.1 INTEGER for CrlNumber, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
  }

/*
   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription
   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
   id-ad-caIssuers OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.2 }
   id-ad-ocsp OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.48.1 }
*/

  function setAIA() {
    global $aia_ca_issuers, $aia_ocsp;
    $encoded = '';
    if (isset($aia_ca_issuers)) {
      $accessMethod = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = '1.3.6.1.5.5.7.48.2');
      foreach($aia_ca_issuers as $issuer) {
        $caIssuer = new GeneralName($issuer);
        $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $accessMethod . $caIssuer->encode($implicit = true));
      }
    }
    if (isset($aia_ocsp)) {
      $accessMethod = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = '1.3.6.1.5.5.7.48.1');
      foreach($aia_ocsp as $ocsp) {
        $ocspResponder = new GeneralName($ocsp);
        $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $accessMethod . $ocspResponder->encode($implicit = true));
      }
    }
    if (! empty($encoded)) {
      $this->extnID = '1.3.6.1.5.5.7.1.1';
      $this->extnValue = bin2hex(asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded));
    }
  }

  function encode() {
    $extension = asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = $this->extnID);
    if ($this->critical)
      $extension .= asn1encode($class = 0, $constructed = false, $type = BOOLEAN, $value = 'TRUE');
    $extension .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->extnValue);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $extension);
  }

  function decode($extension) {
    $iter = 0;
    $this->extnValue = null;
    $decoded = asn1decode($extension);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $extension = $decoded['value'];
    else
      throw new Exception("Extension::decode() error: bad message check: expected an ASN.1 SEQUENCE for extension, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($extension) > 2) {
      $decoded = asn1decode($extension);
      switch($iter) {
        case 0: //extnID
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OBJECT_IDENTIFIER) {
            $this->extnID = $decoded['value'];
          } else
            throw new Exception("Extension::decode() error: bad message check: expected an ASN.1 OBJECT_IDENTIFIER, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 1: //critical or extnValue
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BOOLEAN) {
            $this->critical = $decoded['value'];
          } elseif ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING) {
            $this->extnValue = $decoded['value'];
            break;
          } else
            throw new Exception("Extension::decode() error: bad message check: expected an ASN.1 OCTET_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        case 2: //extnValue
          if (! is_null($this->extnValue))
            throw new Exception("Extension::decode() error: bad message check: string is too long");
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING) {
            $this->extnValue = $decoded['value'];
          } else
            throw new Exception("Extension::decode() error: bad message check: expected an ASN.1 OCTET_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']));
        break;
        default:
          throw new Exception("Extension::decode() error: bad message check: string is too long");
      }
      $extension = substr($extension, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $offset;
  }

  function set($id, $value, $critical = false) {
    $this->extnID = $id;
    $this->extnValue = $value;
    $this->critical = $critical;
  }

  function __construct() {
    $this->critical = false;
  }
}

?>