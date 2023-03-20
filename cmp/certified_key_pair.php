<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';

/*
CertifiedKeyPair ::= SEQUENCE {
         certOrEncCert       CertOrEncCert,
         privateKey      [0] EncryptedValue      OPTIONAL,
         -- see [CRMF] for comment on encoding
         publicationInfo [1] PKIPublicationInfo  OPTIONAL
     }

CertOrEncCert ::= CHOICE {
         certificate     [0] Certificate,
         encryptedCert   [1] EncryptedValue
     }

PKIPublicationInfo ::= SEQUENCE {
action INTEGER {
 dontPublish (0),
 pleasePublish (1) },
pubInfos SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
 -- pubInfos MUST NOT be present if action is "dontPublish"
 -- (if action is "pleasePublish" and pubInfos is omitted,
 -- "dontCare" is assumed)

SinglePubInfo ::= SEQUENCE {
 pubMethod INTEGER {
 dontCare (0),
 x500 (1),
 web (2),
 ldap (3) },
 pubLocation GeneralName OPTIONAL }
*/

class CertifiedKeyPair {
  public $certOrEncCert;
  public $cert;
  public $privateKey;
  public $publicationInfo;

  function encode() {
    if ($this->certOrEncCert == 0)
      $cert = $this->cert->encode();
    else
      throw new Exception("CertifiedKeyPair::encode() error: Encrypted certs are not supported", SYSTEM_FAILURE);
    $certifiedKeyPair = asn1encode($class = 2, $constructed = true, $type = $this->certOrEncCert, $value = $cert);
    if (! is_null($this->privateKey)) { //not supported
      throw new Exception("CertifiedKeyPair::encode() error: Encrypted Value is deprecated and encrypted certs are not supported", SYSTEM_FAILURE);
    }
    if (! is_null($this->publicationInfo)) {
      $publicationInfo = $this->publicationInfo->encode();
      $certifiedKeyPair .= asn1encode($class = 2, $constructed = true, $type = 1, $value = $publicationInfo);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certifiedKeyPair);
  }

  function __construct($cert, $certOrEncCert = 0, $privateKey = null, $publicationInfo = null) {
    if (is_null($cert))
      throw new Exception("CertifiedKeyPair::__construct() error: cert is null", SYSTEM_FAILURE);
    $this->cert = $cert;
    $this->certOrEncCert = $certOrEncCert;
    $this->privateKey = $privateKey;
    $this->publicationInfo = $publicationInfo;
  }
}

?>