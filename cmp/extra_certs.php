<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'helper_functions.php';
require_once 'certificate.php';
require_once 'globals.php';

/*
PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
     }
     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

PKIProtection ::= BIT STRING

   The input to the calculation of PKIProtection is the DER encoding of
   the following data structure:

        ProtectedPart ::= SEQUENCE {
            header    PKIHeader,
            body      PKIBody
        }
*/

class ExtraCerts {
  public $extraCerts;
  public $encoded; //boolean, indicate whether $extraCerts is an array of Certificate objects or certificates in DER format

  function encode() {
    $c = '';
    foreach($this->extraCerts as $cert) {
      if ($this->encoded) {
        $c .= $cert;
      } else $c .= $cert->encode();
    }
    $c = asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $c);
    return asn1encode($class = 2, $constructed = true, $type = 1, $value = $c);
  }

  function decode($pkiMessage) {
    $this->extraCerts = array();
    $decoded = asn1decode($pkiMessage);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiMessage = $decoded['value'];
    else
      throw new Exception("ExtraCerts::decode() error: bad message check: expected an ASN.1 SEQUENCE for ExtraCerts, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($pkiMessage) > 2) {
      $extraCert = new Certificate();
      $next = $extraCert->decode($pkiMessage);
      $this->extraCerts[] = clone $extraCert;
      $pkiMessage = substr($pkiMessage, $next);
    }
    return $offset;
  }

  function __construct() {
    $this->extraCerts = null;
    $this->encoded = false;
  }
}
