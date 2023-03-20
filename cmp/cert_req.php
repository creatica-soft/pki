<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'cert_template.php';
require_once 'controls.php';

/*
CertRequest ::= SEQUENCE {
 certReqId INTEGER, -- ID for matching request and reply
 certTemplate CertTemplate, -- Selected fields of cert to be issued
 controls Controls OPTIONAL } -- Attributes affecting issuance
*/

class CertReq {
  public $certReqId;
  public $certTemplate;
  public $controls;

  function encode() {
    $certReq = asn1encode($class = 0, $constructed = false, $type = INTEGER, $value = $this->certReqId);
    $certReq .= $this->certTemplate->encode();
    if (! is_null($this->controls))
      $certReq .= $this->controls->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certReq);
  }

  function decode($req) {
    $iter = 0;
    $decoded = asn1decode($req);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $req = $decoded['value'];
    else
      throw new Exception("CertReq::decode() error: bad message check: expected an ASN.1 SEQUENCE for CertReq, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($req) > 2) {
      switch($iter) {
        case 0: //certReqId
          $decoded = asn1decode($req);
          if ($decoded['class'] == UNIVERSAL_CLASS && ! $decoded['constructed'] && $decoded['type'] == INTEGER) {
            $this->certReqId = $decoded['value'];
          }
          else
            throw new Exception("CertReq::decode() error: bad message check: expected an ASN.1 INTEGER type, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
          $next = $decoded['length'] + $decoded['hl'];
        break;
        case 1: //certTemplate
          $this->certTemplate = new CertTemplate();
          $next = $this->certTemplate->decode($req);
        break;
        case 2: //controls 
          $this->controls = new Controls();
          $next = $this->controls->decode($req);
        break;
        default:
          throw new Exception("CertReq::decode() error: bad message check: string is too long", BAD_MESSAGE_CHECK);
      }
      $req = substr($req, $next);
      $iter++;
    }
    return $offset;
  }

  private function map($req) {
    $this->certReqId = $req[0]['value'];
    $this->certTemplate = new CertTemplate($req[1]);
    foreach($req as $key => $val) {
      if (! is_int($key) || $key < 2) continue;
      $this->controls = new Controls($req[$key]);
    }
  }

  function __construct($req = null) {
    $this->controls = null;
    if (! is_null($req)) $this->map($req);
  }
}

?>