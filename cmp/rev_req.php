<?php
require_once 'asn1_types.php';
require_once 'asn1encode.php';

/*
RevReqContent ::= SEQUENCE OF RevDetails

    RevDetails ::= SEQUENCE {
        certDetails         CertTemplate,
        crlEntryDetails     Extensions       OPTIONAL
    }

crlExtensions:

id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }

   -- reasonCode ::= { CRLReason }

   CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }

id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }

   InvalidityDate ::=  GeneralizedTime

id-ce-certificateIssuer   OBJECT IDENTIFIER ::= { id-ce 29 }

   CertificateIssuer ::=     GeneralNames
*/

class RevReq {
  public $certTemplate;
  public $crlExtensions;

  function encode() {
    $encoded = $this->certTemplate->encode();
    if (! is_null($this->crlExtensions)) $encoded .= $this->crlExtensions->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($revReq) {
    $iter = 0;
    $decoded = asn1decode($revReq);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $revReq = $decoded['value'];
    else
      throw new Exception("RevReq::decode() error: bad message check: expected an ASN.1 SEQUENCE for RevReq, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($revReq) > 2) {
      switch($iter) {
        case 0: //certTemplate
          $this->certTemplate = new certTemplate();
          $next = $this->certTemplate->decode($revReq);
        break;
        case 1: //crlExtensions
          $this->crlExtensions = new Extensions();
          $next = $this->crlExtensions->decode($revReq);
        break;
        default:
          throw new Exception("RevReq::decode() error: string is too long", BAD_MESSAGE_CHECK);
      }
      $revReq = substr($revReq, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->crlExtensions = null;
  }

  function __clone() {
    $this->certTemplate = clone $this->certTemplate;
    $this->crlExtensions = clone $this->crlExtensions;
  }
}

class RevReqContent {
  public $revReqs;

  function encode() {
    $encoded = '';
    foreach($this->revReqs as $req)
      $encoded .= $req->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($revReqs) {
    $decoded = asn1decode($revReqs);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $revReqs = $decoded['value'];
    else
      throw new Exception("RevReqContent::decode() error: bad message check: expected an ASN.1 SEQUENCE for RevReqContent, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($revReqs) > 2) {
      $rr = new RevReq();
      $next = $rr->decode($revReqs);
      $this->revReqs[] = $rr;
      $revReqs = substr($revReqs, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->revReqs = array();
  }
}

?>