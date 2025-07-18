<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'certified_key_pair.php';

/*
CertResponse ::= SEQUENCE {
         certReqId           INTEGER,
         status              PKIStatusInfo,
         certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         rspInfo             OCTET STRING        OPTIONAL
         -- analogous to the id-regInfo-utf8Pairs string defined
         -- for regInfo in CertReqMsg [CRMF]
     }
*/

class CertResponse {
  public $certReqId;
  public $status;
  public $certifiedKeyPair;
  public $rspInfo;

  function encode() {
    $certResponse = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->certReqId);
    $certResponse .= $this->status->encode();
    if (! is_null($this->certifiedKeyPair))
      $certResponse .= $this->certifiedKeyPair->encode();
    if (! is_null($this->rspInfo))
      $certResponse .= asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->rspInfo);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certResponse);
  }
  
  function __construct($certReqId, $status, $cert = null, $certOrEncCert = 0, $privateKey = null, $publicationInfo = null, $rspInfo = null) {
    $this->certReqId = $certReqId;
    $this->status = $status;
    if (! is_null($cert))
      $this->certifiedKeyPair = new CertifiedKeyPair($cert, $certOrEncCert, $privateKey, $publicationInfo);
    else $this->certifiedKeyPair = null;
    $this->rspInfo = $rspInfo;
  }
}
