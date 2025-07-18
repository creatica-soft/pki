<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';

/*
OptionalValidity ::= SEQUENCE {
 notBefore [0] Time OPTIONAL,
 notAfter [1] Time OPTIONAL } -- at least one MUST be present

Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }
*/

class Validity {
  public $notBefore; //UTC_TIME
  public $notAfter; //UTC_TIME
  public $notBeforeType;
  public $notAfterType;

  function notBefore2DateTime() {
    if (! is_null($this->notBefore) && ! is_null($this->notBeforeType))
      return toDateTime($this->notBefore, $this->notBeforeType);
    else 
      return toDateTime("19700101T000000", GENERALIZED_TIME);
  }

  function notBefore2timestamp() {
    if (! is_null($this->notBefore) && ! is_null($this->notBeforeType))
      return toTimestamp($this->notBefore, $this->notBeforeType);
    else 
      return toTimestamp("19700101T000000", GENERALIZED_TIME);
  }

  function notAfter2DateTime() {
    if (! is_null($this->notAfter) && ! is_null($this->notAfterType))
      return toDateTime($this->notAfter, $this->notAfterType);
    else 
      return toDateTime("20701231T235959", GENERALIZED_TIME);
  }

  function notAfter2timestamp() {
    if (! is_null($this->notAfter) && ! is_null($this->notAfterType))
      return toTimestamp($this->notAfter, $this->notAfterType);
    else 
      return toTimestamp("20701231T235959", GENERALIZED_TIME);
  }

  function encode($implicit = false) {
    $validity = '';
    if (! is_null($this->notBefore))
      $encoded = asn1encode($class = 0, $constructed = false, $type = $this->notBeforeType, $value = $this->notBefore);
    if (! is_null($this->notAfter))
      $encoded .= asn1encode($class = 0, $constructed = false, $type = $this->notAfterType, $value = $this->notAfter);
    if ($implicit) return $encoded;
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($validity) {
    $iter = 0;
    $decoded = asn1decode($validity);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $validity = $decoded['value'];
    else
      throw new Exception("Validity::decode() error: bad message check: expected an ASN.1 SEQUENCE for validity, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($validity) > 2) {
      $decoded = asn1decode($validity);
      if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed']) { //this covers a case when only one validity is present: either notBefore or notAfter
        $decoded2 = asn1decode($decoded['value']);
        switch($decoded2['type']) {
          case 0:
            if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && ($decoded2['type'] == UTC_TIME || $decoded2['type'] == GENERALIZED_TIME)) {
              $this->notBefore = $decoded2['value'];
              $this->notBeforeType = $decoded2['type'];
            }  else
              throw new Exception("Validity::decode() error: bad message check: expected an ASN.1 TIME CHOICE for notBefore, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']));
          break;
          case 1:
            if ($decoded2['class'] == UNIVERSAL_CLASS && ! $decoded2['constructed'] && ($decoded2['type'] == UTC_TIME || $decoded2['type'] == GENERALIZED_TIME)) {
              $this->notAfter = $decoded2['value'];
              $this->notAfterType = $decoded2['type'];
            } else
              throw new Exception("Validity::decode() error: bad message check: expected an ASN.1 TIME CHOICE for notAfter, received class " . class2str($decoded2['class']) . ", constructed " . $decoded2['constructed'] . ", type " . type2str($decoded2['type']));
          break;
          default:
            throw new Exception("Validity::decode() error: bad message check: string is too long");
        }
      } else { 
        switch($iter) {
          case 0: //notBefore
            if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && ($decoded['type'] == UTC_TIME || $decoded['type'] == GENERALIZED_TIME)) {
              $this->notBefore = $decoded['value'];
              $this->notBeforeType = $decoded['type'];
            }
            else
              throw new Exception("Validity::decode() error: bad message check: expected an ASN.1 TIME CHOICE for notBefore, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
          break;
          case 1: //notAfter
            if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && ($decoded['type'] == UTC_TIME || $decoded['type'] == GENERALIZED_TIME)) {
              $this->notAfter = $decoded['value'];
              $this->notAfterType = $decoded['type'];
            }
            else 
              throw new Exception("Validity::decode() error: bad message check: expected an ASN.1 TIME CHOICE for notAfter, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']));
          break;
          default:
            throw new Exception("SubjectPublicKeyInfo::decode() error: string is too long");
        }
      }
      $validity = substr($validity, $decoded['length'] + $decoded['hl']);
      $iter++;
    }
    return $offset;
  }
  
  function __construct() {
    $this->notAfter = null;
    $this->notBefore = null;
  }
}
