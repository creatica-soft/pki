<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'pki_status_info.php';

/*
CertConfirmContent ::= SEQUENCE OF CertStatus
         CertStatus ::= SEQUENCE {
            certHash    OCTET STRING,
            certReqId   INTEGER,
            statusInfo  PKIStatusInfo OPTIONAL
         }
-- An empty CertConfirmContent (a zero-length SEQUENCE) MAY be used to indicate
-- rejection of all supplied certificates.
-- The end entity proves knowledge of the private decryption key to the CA
-- by providing the correct CertHash for this certificate in the
-- certConf message.  This demonstrates POP because the EE can only
-- compute the correct CertHash if it is able to recover the
-- certificate, and it can only recover the certificate if it is able to
-- decrypt the symmetric key using the required private key.  Clearly,
-- for this to work, the CA MUST NOT publish the certificate until the
-- certConf message arrives (when certHash is to be used to demonstrate POP).
*/

class CertStatus {
  public $certHash;
  public $certReqId;
  public $statusInfo;

  function encode() {
    $encoded = asn1encode($class = 0, $constructed = false, $type = OCTET_STRING, $value = $this->certHash);
    $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->certReqId);
    if (! is_null($this->statusInfo))
      $encoded .= $this->statusInfo->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
 
  function decode($certStatus) {
    $iter = 0;
    $decoded = asn1decode($certStatus);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certStatus = $decoded['value'];
    else
      throw new Exception("CertStatus::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertStatus, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($certStatus) > 2) {
      switch($iter) {
        case 0: //certHash
          $decoded = asn1decode($certStatus);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == OCTET_STRING) {
            $this->certHash = $decoded['value'];
          } else
            throw new Exception("CertStatus::decode() error: bad message check: expected an ASN.1 OCTET_STRING, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //certReqId
          $decoded = asn1decode($certStatus);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->certReqId = $decoded['value'];
          } else
            throw new Exception("CertStatus::decode() error: bad message check: expected an ASN.1 INTEGER, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 2: //statusInfo
          $this->statusInfo = new PKIStatusInfo();
          $next = $this->statusInfo->decode($certStatus);
        break;
        default:
          throw new Exception("CertStatus::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $certStatus = substr($certStatus, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->statusInfo = null;
  }
  
  function __clone() {
    $this->statusInfo = clone $this->statusInfo;
  }
}

class CertConfirmContent {
  public $certStatus;

  function encode() {
    if (! is_null($this->certStatus)) {
      $encoded = '';
      foreach($this->certStatus as $certStatus)
        $encoded .= $certStatus->encode();
    } else $encoded = '';
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($certConfirmContent) {
    $decoded = asn1decode($certConfirmContent);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $certConfirmContent = $decoded['value'];
    else 
      throw new Exception("Extension::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertConfirmContent, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type'], $decoded['class']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($certConfirmContent) > 2) {
      $certStatus = new CertStatus();
      $next = $certStatus->decode($certConfirmContent);
      $this->certStatus[] = $certStatus;
      $certConfirmContent = substr($certConfirmContent, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->certStatus = array();
  }
}
