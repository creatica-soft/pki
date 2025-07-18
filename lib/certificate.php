<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'asn1decode.php';
require_once 'general_name.php';
require_once 'algorithm_identifier.php';
require_once 'validity.php';
require_once 'subject_pubkey_info.php';
require_once 'extension.php';
require_once 'sql.php';

/*
Certificate ::= SEQUENCE {
 tbsCertificate TBSCertificate,
 signatureAlgorithm AlgorithmIdentifier,
 signature BIT STRING }

TBSCertificate ::= SEQUENCE {
 version [0] Version DEFAULT v1,
 serialNumber CertificateSerialNumber,
 signature AlgorithmIdentifier,
 issuer Name,
 validity Validity,
 subject Name,
 subjectPublicKeyInfo SubjectPublicKeyInfo,
 issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL,
 -- If present, version MUST be v2 or v3
 subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
 -- If present, version MUST be v2 or v3
 extensions [3] Extensions OPTIONAL
 -- If present, version MUST be v3 -- }

Version ::= INTEGER { v1(0), v2(1), v3(2) }

CertificateSerialNumber ::= INTEGER

 --  CAs MUST force the serialNumber to be a non-negative integer, that
 --  is, the sign bit in the DER encoding of the INTEGER value MUST be
 --  zero.  This can be done by adding a leading (leftmost) `00'H octet if
 --  necessary.  This removes a potential ambiguity in mapping between a
 --  string of octets and an integer value.

 --  As noted in Section 4.1.2.2, serial numbers can be expected to
 --  contain long integers.  Certificate users MUST be able to handle
 --  serialNumber values up to 20 octets in length.  Conforming CAs MUST
 --  NOT use serialNumber values longer than 20 octets.

 --  As noted in Section 5.2.3, CRL numbers can be expected to contain
 --  long integers.  CRL validators MUST be able to handle cRLNumber
 --  values up to 20 octets in length.  Conforming CRL issuers MUST NOT
 --  use cRLNumber values longer than 20 octets.

Validity ::= SEQUENCE {
 notBefore Time,
 notAfter Time }

Time ::= CHOICE {
 utcTime UTCTime, //YYMMDDhhmmssZ, in php time format "ymdHis" . 'Z'
 generalTime GeneralizedTime } //YYYYMMDDhhmmssZ, in php time format "YmdHis" . 'Z'

UniqueIdentifier ::= BIT STRING

SubjectPublicKeyInfo ::= SEQUENCE {
 algorithm AlgorithmIdentifier,
 subjectPublicKey BIT STRING }

Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

Extension ::= SEQUENCE {
 extnID OBJECT IDENTIFIER,
 critical BOOLEAN DEFAULT FALSE,
 extnValue OCTET STRING }
*/

class TBSCertificate {
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

  //this function has limited use, it's better to run parent::verify()
  function isValid() {
    global $now;
    $validFrom = $this->validity->notBefore2DateTime();
    $validTo = $this->validity->notAfter2DateTime();
    if ($validFrom->diff($now)->format("%R") == '-') { //not valid yet
      throw new Exception("notBefore " . $this->validity->notBefore . " is in the future, serialNumber " . $this->serialNumber . ", subject " . $this->subject);
      return false;
    }
    elseif ($validTo->diff($now)->format("%R") == '+') { //already expired
      throw new Exception("notAfter " . $this->validity->notAfter . " is in the past, serialNumber " . $this->serialNumber . ", subject " . $this->subject);
      return false;
    }
    return true;
  }

  function set($certTemplate, $owner = null, $defaultExtKeyUsages = true, $role = 'standard', $acme = false) {
    global $now, $cert_serial_bytes, $signing_ca_path, $cert_validity_days, $default_signing_alg, $min_key_size;

    $notAfter = new DateTime("now", new DateTimeZone("+0000"));
    $notAfter->add(date_interval_create_from_date_string("$cert_validity_days days"));

    $this->version = 2; //for extensions
    // serialNumbers should be supported up to 20 digits; i.e. 8-byte integers won't work, so they must be numeric strings
    // but they must be positive integers, i.e. the most significant bit must be 0
    $serialNumber = gmp_import(chr(0) . openssl_random_pseudo_bytes($cert_serial_bytes - 1));
    $serialNumber = gmp_strval($serialNumber, 10);
    while(! is_null(sqlGetCert($serialNumber))) {//check that the serialNumber does not exist in the cert db
      $serialNumber = gmp_import(chr(0) . openssl_random_pseudo_bytes($cert_serial_bytes - 1));
      $serialNumber = gmp_strval($serialNumber, 10);
    }
    $this->serialNumber = $serialNumber;
    $this->signingAlg = new AlgorithmIdentifier($default_signing_alg);
    $this->issuer = new Name(getCertSubjectName($signing_ca_path));
    $this->validity = new Validity(null);
    
    //MS Certificate MMC seems to have a bug - it appears to fail to verify the signature
    //The workaround is to issue a certificate which is not yet valid to prevent the validation - this is just a guess!
    //The error message when the cert is already valid is this: "Unable to install the cert, the hash value is incorrect"
    $this->validity->notBefore = gmdate("ymdHis") . 'Z';
    $this->validity->notBeforeType = UTC_TIME;
    $this->validity->notAfter = gmdate("ymdHis", $notAfter->getTimestamp()) . 'Z';
    $this->validity->notAfterType = UTC_TIME;
    if (is_null($certTemplate->subject))
      throw new Exception("TBSCertificate::set() error: bad certificate template - missing subject");
    $this->subject = clone $certTemplate->subject; //encodings must match issuer's one for directoryString types; UTF8_STRING for cn in $signing_ca_path!

    //verify key length
    if (strcasecmp(oid2str($certTemplate->publicKey->algorithm->algorithm), 'rsaEncryption') == 0) {
      if (strlen(gmp_strval($certTemplate->publicKey->subjectPublicKey->modulus, 16)) * 8 < $min_key_size)
        throw new Exception("Bad certificate template - RSA key length is less than $min_key_size");
    }
    $this->publicKey = clone $certTemplate->publicKey;
/*
From RFC5280 section 4.1.2.8:
   The subject and issuer unique identifiers are present in the certificate
   to handle the possibility of reuse of subject and/or issuer names
   over time.  This profile RECOMMENDS that names not be reused for
   different entities and that Internet certificates not make use of
   unique identifiers.  CAs conforming to this profile MUST NOT generate
   certificates with unique identifiers.
*/      

/*
From RFC5280 section 4.2:
   Conforming CAs MUST support key identifiers (Sections 4.2.1.1 and
   4.2.1.2), basic constraints (Section 4.2.1.9), key usage (Section
   4.2.1.3), and certificate policies (Section 4.2.1.4) extensions.  If
   the CA issues certificates with an empty sequence for the subject
   field, the CA MUST support the subject alternative name extension
   (Section 4.2.1.6). 
   At a minimum, applications conforming to this profile MUST recognize
   the following extensions: key usage (Section 4.2.1.3), certificate
   policies (Section 4.2.1.4), subject alternative name (Section
   4.2.1.6), basic constraints (Section 4.2.1.9), name constraints
   (Section 4.2.1.10), policy constraints (Section 4.2.1.11), extended
   key usage (Section 4.2.1.12), and inhibit anyPolicy (Section
   4.2.1.14).
   In addition, applications conforming to this profile SHOULD recognize
   the authority and subject key identifier (Sections 4.2.1.1 and
   4.2.1.2) and policy mappings (Section 4.2.1.5) extensions.
*/
    $clientExtensions = array();
    $extensions = array();
    $this->extensions = new Extensions(null);
    $this->extensions->set($certTemplate, $owner, $defaultExtKeyUsages, $role, $acme);
    $sans = $this->extensions->getSubjectAltName();
    $smime = false;
    if ($sans) {
      foreach ($sans as $san) {
        if ($san->type == 1) //email
          $smime = true;
          break;
      }
    }
    if (! is_null($owner)) {
      if (! $smime) 
        $this->subject->addOwner($owner); // for smime certs, subject should be empty sequence
    } else {
      if (! is_null($role)) 
        $this->subject->addRole($role); // only add role if owner is null
    }
  }

  function encode() {
    $cert = '';
    if ($this->version == 1 || $this->version == 2) { 
      $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
      $cert .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $encoded);
    }
    $cert .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->serialNumber);
    $cert .= $this->signingAlg->encode();
    $cert .= $this->issuer->encode();
    $cert .= $this->validity->encode();
    $cert .= $this->subject->encode();
    $cert .= $this->publicKey->encode();
    if (! is_null($this->issuerUID) && ($this->version == 1 || $this->version == 2)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->issuerUID);
      $cert .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $encoded);
    }
    if (! is_null($this->subjectUID) && ($this->version == 1 || $this->version == 2)) {
      $encoded = asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->subjectUID);
      $cert .= asn1encode($class = 2, $constructed = true, $type = 2, $value = $encoded);
    }
    if (! is_null($this->extensions) && $this->version == 2) {
      $encoded = $this->extensions->encode();    
      $cert .= asn1encode($class = 2, $constructed = true, $type = 3, $value = $encoded);
    }
    $cert = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $cert);
    return $cert;
  }

  function decode($cert) {
    $iter = 0;
    $decoded = asn1decode($cert);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $cert = $decoded['value'];
    else
      throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 SEQUENCE for tbsCertificate, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($cert) > 2) {
      switch($iter) {
        case 0: //version - optional
          $decoded = asn1decode($cert);
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] == 0) {
            $serial = asn1decode($decoded['value']);
            if ($serial['class'] == UNIVERSAL_CLASS && ! $serial['constructed'] && $serial['type'] == INTEGER)
              $this->version = $serial['value'];
            else
              throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 INTEGER for version, received class " . class2str($version['class']) . ", constructed " . $version['constructed'] . ", type " . type2str($version['type']));
          } else {
            if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
              $this->serialNumber = $decoded['value'];
            else
              throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 INTEGER for serial, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
            $iter++;
          }
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //serialNumber
          $decoded = asn1decode($cert);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER)
            $this->serialNumber = $decoded['value'];
          else
            throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 INTEGER for serial, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 2: //signingAlg
          $this->signingAlg = new AlgorithmIdentifier();
          $next = $this->signingAlg->decode($cert);
        break;
        case 3: //issuer
          $this->issuer = new Name();
          $next = $this->issuer->decode($cert);
        break;
        case 4: //validity
          $this->validity = new Validity();
          $next = $this->validity->decode($cert);
        break;
        case 5: //subject
          $this->subject = new Name();
          $next = $this->subject->decode($cert);
        break;
        case 6: //publicKey
          $this->publicKey = new SubjectPublicKeyInfo();
          $next = $this->publicKey->decode($cert);
        break;
        default:
          $decoded = asn1decode($cert);
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS) {
            switch($decoded['type']) {
              case 1: //issuerUID, v2 or v3
                if ($this->version == 0)
                  throw new Exception("Certificate verion must be v2 (1) or v3 (2) for issuerUID");
                if (! $decoded['constructed'])
                  $this->issuerUID = decode(BIT_STRING, $decoded['value']);
                else
                  throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC primitive class and type 1 (implicit BIT_STRING) for issuerUID, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
              break;
              case 2: //subjectUID, v2 or v3
                if ($this->version == 0)
                  throw new Exception("Certificate verion must be v2 (1) or v3 (2) for subjectUID");
                if (! $decoded['constructed'])
                  $this->subjectUID = decode(BIT_STRING, $decoded['value']);
                else
                  throw new Exception("TBSCertificate::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC primitive class and type 2 (implicit BIT_STRING) for subjectUID, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
              break;
              case 3: //extensions, v3 only
                if ($this->version != 2)
                  throw new Exception("Certificate verion must be v3 (2) for extensions");
                if ($decoded['constructed']) {
                  $this->extensions = new Extensions();
                  $next = $this->extensions->decode($decoded['value']);
                }
              break;
              default:
                throw new Exception("TBSCertificate::map() error: unknown certificate option: " . $decoded['type']);
            }
          }
          $next = $decoded['length'] + $decoded['hl'];
      }
      $cert = substr($cert, $next);
      $iter++;
    }
    return $offset;
  }
  
  function __construct() {
    $this->version = 0; //v1 is the default
    $this->issuerUID = null;
    $this->subjectUID = null;
    $this->extensions = null;
  }
}

class Certificate {
  public $tbsCertificate;
  public $signatureAlg;
  public $signature;
  
  function checkQuotas($subject, $owner, $role = 'standard') {
    global $request, $max_certs_per_cn, $max_certs_standard, $max_certs_master;
    $certNumberOverall = sqlGetOwnCertsCount($owner);
    $subject .= '/owner=' . $owner;
    $certNumberPerCN = sqlGetOwnCertsCount($owner, $subject);
    if ($certNumberPerCN >= $max_certs_per_cn)
      throw new Exception('An account ' . $owner . " has exceeded the quota for the number of certificates per CN: $max_certs_per_cn. Please consider revoking unused certs.");
    switch($role) {
      case 'standard':
        if ($certNumberOverall >= $max_certs_standard)
          throw new Exception('An account ' . $owner . " has exceeded the overall standard quota for the number of certificates: $max_certs_standard. Please consider revoking unused certs.");
      break;
      case 'master':
        if ($certNumberOverall >= $max_certs_master)
          throw new Exception('An account ' . $owner . " has exceeded the overall master quota for the number of certificates: $max_certs_master. Please consider revoking unused certs.");
      break;
    }
  }

  function set($certTemplate, $owner, $defaultExtKeyUsages = true, $role = 'standard', $acme = false) {
    global $default_signing_alg;
    $this->checkQuotas($certTemplate->subject, $owner, $role);
    $this->tbsCertificate = new TBSCertificate();
    $this->tbsCertificate->set($certTemplate, $owner, $defaultExtKeyUsages, $role, $acme);
    $this->signatureAlg = new AlgorithmIdentifier($default_signing_alg);
  }

  function sign($privKeyPemFile = null) {
    global $signing_ca_privkey_path;
    if (is_null($privKeyPemFile)) {
      if (! file_exists($signing_ca_privkey_path))
        throw new Exception("File $signing_ca_privkey_path not found");
      $privKey = file_get_contents($signing_ca_privkey_path);
      if (! $privKey) 
        throw new Exception("Unable to open $signing_ca_privkey_path");
    }
    else
      $privKey = file_get_contents($privKeyPemFile);
    $cert = $this->tbsCertificate->encode();
    while(openssl_error_string());
    $res = openssl_sign($cert, $signature, $privKey, oid2str($this->signatureAlg->algorithm));
    if (! $res) {
      $error = '';
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception("Certificate::sign() openssl sign error: $error");
    }
    $this->signature = bin2hex($signature);
  }

  function verify($signing_ca_path) {
    global $signing_ca_der_path, $now;
    //verify that cert issuer matches the subject of signing_ca
    $issuer = $this->tbsCertificate->issuer;
    $ca = new Certificate($signing_ca_der_path);
    $ca = $ca->tbsCertificate->subject;
    if (strcasecmp($issuer, $ca) != 0)
      throw new Exception("Issuer name $issuer is different from signing CA $ca");
    //verify our signature
    while(openssl_error_string());
    $encoded = $this->tbsCertificate->encode();
    $res = openssl_verify($encoded, hex2bin($this->signature), openssl_x509_read('file://' . $signing_ca_path), oid2str($this->signatureAlg->algorithm));
    switch($res) {
      case 0: //invalid
        throw new Exception("Invalid certificate signature, serialNumber " . $this->tbsCertificate->serialNumber . ", subject " . $this->tbsCertificate->subject);
      case 1: //revocation and validity status check - done by checking certs.db
        sqlUpdateAllCerts(); //set status to 1 for all expired certs
        $cert = sqlGetCert($this->tbsCertificate->serialNumber);
        if (is_null($cert))
          throw new Exception("Certificate with the serial number " . $this->tbsCertificate->serialNumber . " and the subject " . $this->tbsCertificate->subject . " is not found in the database");
        switch($cert['status']) {
          case 0: //valid
            return true;
          case 1: //expired
            throw new Exception("Certificate with the serial number " . $this->tbsCertificate->serialNumber . " and the subject " . $this->tbsCertificate->subject . " has expired");
          case -1: //revoked
            throw new Exception("Certificate with the serial number " . $this->tbsCertificate->serialNumber . " and the subject " . $this->tbsCertificate->subject . " is revoked. Revocation reason: " . $cert['revocationReason']);
          default:
            throw new Exception("Certificate with the serial number " . $this->tbsCertificate->serialNumber . " and the subject " . $this->tbsCertificate->subject . " has unknown status " . $cert['status']);          
        }
      case -1: //error
        $error = "Certificate::verify() openssl verify error: ";
        while($err = openssl_error_string()) $error .= $err;
        throw new Exception($error);
    }
  }

  function save($status = 0, $filename = null) {
    $encoded = $this->encode();
    sqlSaveCert($this->tbsCertificate->serialNumber, $status, $this->tbsCertificate->subject, $this->tbsCertificate->validity->notBefore2timestamp(), $this->tbsCertificate->validity->notAfter2timestamp(), $this->tbsCertificate->subject->getOwner(), $this->tbsCertificate->subject->getRole(), $encoded);
    //this is a hack to put the cert on hold for CMP
    if ($status == -1)
      sqlRevokeCert($this->tbsCertificate->serialNumber, $revocationDate = null, $revocationReason = 6); //onHold

    if (! is_null($filename)) {
      if (! file_put_contents($filename, $encoded))
        throw new Exception('Certificate::save() error: ' . print_r(error_get_last(), true));
    }
  }

  function encode() {
    $encoded = $this->tbsCertificate->encode();
    $encoded .= $this->signatureAlg->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->signature);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($cert) {
    $iter = 0;
    $decoded = asn1decode($cert);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $cert = $decoded['value'];
    else
      throw new Exception("Certificate::decode() error: bad message check: expected an ASN.1 SEQUENCE for Certificate, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($cert) > 2) {
      switch($iter) {
        case 0: //tbsCertificate
           $this->tbsCertificate = new TBSCertificate();
           $next = $this->tbsCertificate->decode($cert);
        break;
        case 1: //signatureAlg
          $this->signatureAlg = new AlgorithmIdentifier();
          $next = $this->signatureAlg->decode($cert);
        break;
        case 2: //signature
          $decoded = asn1decode($cert);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == BIT_STRING)
            $this->signature = $decoded['value'];
          else
            throw new Exception("Certificate::decode() error: bad message check: expected an ASN.1 BIT_STRING for signature, received class " . class2str($signature['class']) . ", constructed " . $signature['constructed'] . ", type " . type2str($signature['type']));
          $next = $decoded['hl'] + $decoded['length'];
        break;
        default:
          throw new Exception("Certificate::decode() error: bad message check: string is too long");
      }
      $cert = substr($cert, $next);
      $iter++;
    }
    return $offset;
  }

  //$cert can be either an already decoded array or a filename with DER-encoded cert
  function __construct($cert = null) {
    if (! is_null($cert)) {
      if (is_string($cert)) {
        if (! file_exists($cert))
          throw new Exception("Certificate::__construct() error: filename $cert does not exist");
        $this->decode(file_get_contents($cert));
      }
      else
        throw new Exception('Certificate::__construct() error: an argument is not a string (filename)');
    }
  }
}
