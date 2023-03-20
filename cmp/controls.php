<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'atv.php';

/*
see section "6. Controls Syntax" of rfc4211

Controls ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue

AttributeTypeAndValue ::= SEQUENCE {
 type OBJECT IDENTIFIER,
 value ANY DEFINED BY type }

id-regCtrl-regToken            OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.1 } with the value of UTF8_STRING
id-regCtrl-authenticator       OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.2 } with the value of UTF8_STRING
id-regCtrl-pkiPublicationInfo  OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.3 }

   PKIPublicationInfo ::= SEQUENCE {
        action     INTEGER {
                     dontPublish (0),
                     pleasePublish (1) },
        pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }

   SinglePubInfo ::= SEQUENCE {
         pubMethod    INTEGER {
             dontCare    (0),
             x500        (1),
             web         (2),
             ldap        (3) },
         pubLocation  GeneralName OPTIONAL }

id-regCtrl-pkiArchiveOptions   OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.4 }

   PKIArchiveOptions ::= CHOICE {
      encryptedPrivKey     [0] EncryptedKey,
      -- the actual value of the private key
      keyGenParameters     [1] KeyGenParameters,
      -- parameters which allow the private key to be re-generated
      archiveRemGenPrivKey [2] BOOLEAN }
      -- set to TRUE if sender wishes receiver to archive the private
      -- key of a key pair that the receiver generates in response to
      -- this request; set to FALSE if no archival is desired.

   EncryptedKey ::= CHOICE {
      encryptedValue        EncryptedValue, -- deprecated
      envelopedData     [0] EnvelopedData }
      -- The encrypted private key MUST be placed in the envelopedData
      -- encryptedContentInfo encryptedContent OCTET STRING.

   KeyGenParameters ::= OCTET STRING

id-regCtrl-oldCertID           OBJECT IDENTIFIER ::= { 1.3.6.1.5.5.7.5.1.5 }

   CertId ::= SEQUENCE {
         issuer           GeneralName,
         serialNumber     INTEGER
     }
*/

class Controls {
  public $controlSeq;

  function encode() {
    $seq = '';
    foreach($this->controlSeq as $control)
      $seq .= $control->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $seq);
  }

  function decode($controls) {
    $decoded = asn1decode($controls);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $controls = $decoded['value'];
    else
      throw new Exception("Controls::decode() error: bad message check: expected an ASN.1 SEQUENCE for Controls, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    $iter = 0;
    while(strlen($controls) > 2) {
      $control = new AttributeTypeAndValue();
      $next = $control->decode($controls);
      $this->controlSeq[] = $control;
      $controls = substr($controls, $next);
      $iter++;
    }
    return $offset;
  }

  function __construct() {
    $this->controlSeq = array();
  }
}

?>