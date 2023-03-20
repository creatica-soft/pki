<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'pki_status_info.php';
require_once 'pki_header.php';

/*
ErrorMsgContent ::= SEQUENCE {
        pKIStatusInfo          PKIStatusInfo,
        errorCode              INTEGER           OPTIONAL,
        errorDetails           PKIFreeText       OPTIONAL
    }

-- The CA MUST always sign it with a signature key.
*/

class ErrorMsgContent {
  public $pkiStatusInfo;
  public $errorCode;
  public $errorDetails;

  function set($status, $statusStrings = null, $failInfo = null, $errorCode = null, $errorDetails = null) {
    $this->pkiStatusInfo->status = $status;
    if (! is_null($statusStrings)) {
      if (is_array($statusStrings) || is_string($statusStrings))
        $this->pkiStatusInfo->statusString = new PKIFreeText($statusStrings);
      else error_log("ErrorMsgContent::set() error: statusStrings is neither null nor an array nor a string\n");
    } else $this->pkiStatusInfo->statusString = null;
    $this->pkiStatusInfo->failInfo = $failInfo;
    $this->errorCode = $errorCode;
    $this->errorDetails = $errorDetails;
  }

  function encode() {
    $encoded = $this->pkiStatusInfo->encode();
    if (! is_null($this->errorCode))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->errorCode);
    if (! is_null($this->errorDetails)) {
      if (! is_array($this->errorDetails))
        throw new Exception("ErrorMsgContent::encode() error: errorDetails is not an array", SYSTEM_FAILURE);
      $str = '';
      foreach($this->errorDetails as $detail)
        $str .= asn1encode($class = 0, $constructed = false, $type = UTF8_STRING, $value = $detail);
      $encoded .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $str);
    }
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($errorMsgContent) {
    $iter = 0;
    $decoded = asn1decode($errorMsgContent);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $errorMsgContent = $decoded['value'];
    else
      throw new Exception("ErrorMsgContent::decode() error: bad message check: expected an ASN.1 SEQUENCE for ErrorMsgContent, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($errorMsgContent) > 2) {
      switch($iter) {
        case 0: //pkiStatusInfo
          $this->pkiStatusInfo = new PKIStatusInfo();
          $next = $this->pkiStatusInfo(errorMsgContent);
        break;
        case 1: //errorCode 
          $decoded = asn1decode($errorMsgContent);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->errorCode = $decoded['value'];
          } else
            throw new Exception("ErrorMsgContent::decode() error: bad message check: expected an ASN.1 INTEGER, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
        $next = $decoded['length'] + $decoded['hl'];
        break;
        case 2: //errorDetails 
          $this->errorDetails = new PKIFreeText();
          $next = $this->errorDetails->decode($errorMsgContent, $der = true);
        break;
        default:
          throw new Exception("ErrorMsgContent::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $errorMsgContent = substr($errorMsgContent, $next);
      $iter++;
    }
    return $offset;
  }
 
  function __construct() {
    $this->errorCode = null;
    $this->errorDetails = null;
    $this->pkiStatusInfo = new PKIStatusInfo();
  }
}

?>