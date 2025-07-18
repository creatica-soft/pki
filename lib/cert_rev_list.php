<?php
require_once 'sql.php';
require_once 'extension.php';
require_once 'algorithm_identifier.php';
require_once 'certificate.php';

class CRL {
  public $tbsCRL;
  public $signatureAlg;
  public $signature;

  function set() {
    global $default_signing_alg, $signing_ca_path, $signing_ca_der_path, $signing_ca_privkey_path, $crl_next_update_in_days, $cert_serial_bytes;
    //need to retrieve non-expired revoked certs
    //so first update all certs in db setting status to expired (1) if needed
    sqlUpdateAllCerts();
    $certs = sqlGetCerts($subject = null, $status = -1);
    $this->tbsCRL->revokedCerts = new RevokedCerts();
    if (! is_null($certs)) {
      foreach($certs as $cert) {
        if (! is_null($cert['revocationDate']) && $cert['revocationDate'] != 0)
          $revocationDate = date_create_from_format($format = 'U', $datetime = $cert['revocationDate']);
        $revCert = new RevokedCert();
        $revCert->set($cert['serial'], $revocationDate);
        $this->tbsCRL->revokedCerts->revokedCerts[] = $revCert;
      }
    }

    $this->tbsCRL->crlExtensions = new Extensions();

    //set CRL number extension
    $oldCrl = sqlGetCerts('CRL');
    if (is_null($oldCrl)) {
      $crlNumber = gmp_import(chr(0) . openssl_random_pseudo_bytes($cert_serial_bytes - 1));
      $crlNumber = gmp_strval($crlNumber, 10);
    } else {
      if (count($oldCrl) > 1)
        throw new Exception("More than one CRL is found in db");
      $crlNumber = gmp_init($oldCrl[0]['serial']);
      $crlNumber = gmp_add($crlNumber, 1);
      $crlNumber = gmp_strval($crlNumber, 10);
    }
    $ext = new Extension();
    $ext->setCrlNumber($crlNumber);
    $this->tbsCRL->crlExtensions->extensions[] = $ext;
     
    //set Authority Key Identifier extension
    $ext = new Extension();
    $signingCert = new Certificate($signing_ca_der_path);
    $ext->setAuthorityKeyIdentifier($signingCert->tbsCertificate->publicKey->subjectPublicKey->encode());
    $this->tbsCRL->crlExtensions->extensions[] = $ext;

    $this->sign($signing_ca_privkey_path);
    $this->save();
  }

  function save($filename = null) {
    $encoded = $this->encode();
    $crlNumber = $this->tbsCRL->crlExtensions->getCrlNumber();
    $oldCrlNumber = gmp_init($crlNumber);
    $oldCrlNumber = gmp_sub($oldCrlNumber, 1);
    $oldCrlNumber = gmp_strval($oldCrlNumber, 10);

    sqlSaveCert($crlNumber, $status = 0, 'CRL', toTimestamp($this->tbsCRL->thisUpdate, UTC_TIME), toTimestamp($this->tbsCRL->nextUpdate, UTC_TIME), false, false, $encoded);
    sqlDeleteCert($oldCrlNumber);

    if (! is_null($filename)) {
      if (! file_put_contents($filename, $encoded))
        throw new Exception("CRL::save() error: " . print_r(error_get_last(), true));
    }
  }

  function sign($privKeyDerFile) {
    $privKey = file_get_contents($privKeyDerFile);
    while(openssl_error_string());
    $crl = $this->tbsCRL->encode();
    $res = openssl_sign($crl, $signature, $privKey, oid2str($this->signatureAlg->algorithm));
    if (! $res) {
      $error = '';
      while ($err = openssl_error_string()) $error .= $err;
      throw new Exception("CRL::sign() openssl sign error: $error");
    }
    $this->signature = bin2hex($signature);
  }

  function encode() {
    $encoded = $this->tbsCRL->encode();
    $encoded .= $this->signatureAlg->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = '00' . $this->signature);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct() {
    global $default_signing_alg;
    $this->tbsCRL = new TBSCRL();
    $this->signatureAlg = new AlgorithmIdentifier($default_signing_alg);
    $this->set();
  }
}

class RevokedCerts {
  public $revokedCerts;

  function encode() {
    $encoded = '';
    foreach($this->revokedCerts as $cert)
      $encoded .= $cert->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function __construct() {
    $this->revokedCerts = array();
  }
}

class RevokedCert {
  public $serialNumber;
  public $revocationTime;
  public $crlExtensions;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->serialNumber);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = UTC_TIME, $value = $this->revocationTime);
    if (! is_null($this->crlExtensions))
      $encoded .= $this->crlExtensions->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  function set($serialNumber, $revocationTime, $crlExts = null) {
    $this->serialNumber = $serialNumber;
    $this->revocationTime = $revocationTime->format("ymdHis") . 'Z';
    $this->crlExtensions = $crlExts;
  }

  function __construct() {
    $this->crlExtensions = null;
  }
}

class TBSCRL {
  public $version; //must be v2 (1, I think) for extensions
  public $signatureAlg;
  public $issuer;
  public $thisUpdate;
  public $nextUpdate;
  public $revokedCerts;
  public $crlExtensions;

  function encode() {
    $encoded = '';
    if (! is_null($this->version))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->version);
    $encoded .= $this->signatureAlg->encode();
    $encoded .= $this->issuer->encode();
    $encoded .= asn1encode($class = 0, $constructed = false, $type = UTC_TIME, $value = $this->thisUpdate);
    if (! is_null($this->nextUpdate))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = UTC_TIME, $value = $this->nextUpdate);
    $encoded .= $this->revokedCerts->encode();
    if (! is_null($this->crlExtensions)) {
      if ($this->version != 1)
        throw new Exception("CRL version must be v2 (1) for CRL extensions");
      $extensions = $this->crlExtensions->encode();
      $encoded .= asn1encode($class = 2, $constructed = true, $type = 0, $value = $extensions);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function set() {
    global $now, $default_signing_alg, $signing_ca_path, $crl_next_update_in_days;
    
    $this->signatureAlg = new AlgorithmIdentifier($default_signing_alg);
    $issuer = getCertSubjectName($signing_ca_path);
    $this->issuer = new Name($issuer);
    $i = date_interval_create_from_date_string("$crl_next_update_in_days days");
    $nextUpdate = date_add($now, $i);
    $this->nextUpdate = gmdate('ymdHis', $nextUpdate->getTimestamp()) . 'Z';
  }

  function __construct() {
    global $now;
    $this->version = 1;
    $this->thisUpdate = $now->format('ymdHis') . 'Z';
    $this->revokedCerts = new RevokedCerts();
    $this->crlExtensions = new Extensions();
    $this->set();
  }
}
