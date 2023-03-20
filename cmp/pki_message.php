<?php

require_once 'asn1_types.php';
require_once 'asn1decode.php';
require_once 'asn1encode.php';
require_once 'helper_functions.php';
require_once 'sql.php';

require_once 'pki_header.php';
require_once 'pki_body.php';
require_once 'pki_protection.php';
require_once 'extra_certs.php';
require_once 'error_msg.php';
require_once 'pki_status_info.php';
require_once 'globals.php';
require_once 'certification_request.php';

/*
PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
     }
     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
*/

class PKIMessage {
  public $header;
  public $body;
  public $protection;
  public $extraCerts;

  function checkHeader() {
    $this->header->checkVersion();
    $this->header->checkSender();
    $this->header->checkRecipient();
    $this->header->checkMessageTime();
    $this->header->checkProtectionAlg();
    $this->header->checkSenderKID();
    $this->header->checkGeneralInfo();
    $this->header->checkTransactionID();
    $this->header->checkSenderNonce();
    $this->header->checkRecipientNonce();
  }

  function setHeader() {
    global $pvno;
    $this->header = new PKIHeader();
    $this->header->pvno = $pvno;
    $this->header->setSender();
    $this->header->setRecipient();
    $this->header->setMessageTime();
    $this->header->setProtectionAlg();
    $this->header->setSenderKID();
    $this->header->setGeneralInfo();
    $this->header->setTransactionID();
    $this->header->setSenderNonce();
    $this->header->setRecipientNonce();
  }

  function setBody($type) {
    global $request;
    $this->body = new PKIBody();
    $this->body->type = $type;
    $certRepTypes = [IP, CP, KUP, CCP, KRP]; //not all are supported - only two: CP and KUP
    if (in_array($type, $certRepTypes))
      $this->body->content = new CertRepMessage();
    else {
      switch($type) {
        case RP:
          $this->body->content = new RevRepContent();
          break;
        case GENP:
          $this->body->content = new GenMsgContent();
          break;
        case ERROR:
          $this->body->content = new ErrorMsgContent();
          return;
        case PKICONF: 
          $this->body->content = null;
          return;
      }
    }
    if ($request->body->type == 4) //p10cr
      $this->body->content->setFromCsr();
    else
      $this->body->content->set();
  }

  function getCert() {
    global $signing_ca_path;

    $clientCert = null;
//we should avoid using extraCerts because it is not protected by a client signature
//instead we should be able to verify the protection using a client cert from certs.db
      if (! is_null($this->header->sender) && ! is_null($this->header->senderKID)) {
        sqlUpdateAllCerts(); //set status to 1 for all expired certs
        $clientCerts = sqlGetCerts($this->header->sender->name, $status = 0);
        //certs may have the same subject, we select the one who's SubjectKeyIdentifier matches senderKID
        //it is also possible to have multiple certs with the same subject and keyId if a private key is identical, since
        //keyId is just the hash of a public key. In this case, if we picked the wrong cert, the PKI message protection check will fail
        //therefore, we forbid having multiple client certs with the same subject in cert_request.php
        if (! is_null($clientCerts)) {
          foreach($clientCerts as $cert) { //this loop should not be necessary as it should only be one cert if any
            $clientCert = new Certificate();
            $clientCert->decode($cert['cert']);
            $id = $clientCert->tbsCertificate->extensions->getSubjectKeyIdentifier();
            if (! $id)
              throw new Exception("Subject key identifier extension is missing on the client cert with this subject " . $this->header->sender->name . " and sn " . $clientCert->tbsCertificate->serialNumber, SYSTEM_FAILURE);
            $len = strlen($id);
            if (strncasecmp($id, $this->header->senderKID, $len) == 0) {
              //perhaps we do not need to verify our own certs :-)
              //$clientCert->verify($signing_ca_path);
              break;
            } else $clientCert = null;
          }
        } else
           throw new Exception("Unable to find a valid cert in the database matching the sender " . $this->header->sender->name, BAD_MESSAGE_CHECK);
      } else
         throw new Exception("Sender or senderKID or both are null", BAD_MESSAGE_CHECK);
/*
//we should avoid using extraCerts because it is not protected by a client signature
    } else {
      foreach($this->extraCerts->extraCerts as $cert) {
        if ($cert->tbsCertificate->subject->equals($this->header->sender)) {
          $cert->verify($signing_ca_path);
          $clientCert = $cert;
          break;
        }
      }
    }
*/ 
  
    if (is_null($clientCert))
      throw new Exception("Unable to find a valid cert (subjectKeyId " . $this->header->senderKID . ") matching the sender " . $this->header->sender->name . " in the certificate database", BAD_MESSAGE_CHECK); //or in the PKI message extraCerts";
    return $clientCert;
  }

  function encode() {
    $encoded = $this->header->encode();
    $encoded .= $this->body->encode();
    if (! is_null($this->protection)) $encoded .= $this->protection->encode();
    else if (! is_null($this->header->protectionAlg)) {
      $this->protection->protect($this->header, $this->body);
      $encoded .= $this->protection->encode();
    }
    if (! is_null($this->extraCerts)) $encoded .= $this->extraCerts->encode();
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }

  function decode($pkiMessage) {
    $iter = 0;
    $decoded = asn1decode($pkiMessage);
    if ($decoded['class'] == UNIVERSAL_CLASS && $decoded['constructed'] && $decoded['type'] == SEQUENCE)
      $pkiMessage = $decoded['value'];
    else
      throw new Exception("PKIMessage::decode() error: bad message check: expected an ASN.1 SEQUENCE for PKIMessage, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
    $offset = $decoded['length'] + $decoded['hl'];
    while(strlen($pkiMessage) > 2) {
      switch($iter) {
        case 0: //header
          $this->header = new PKIHeader();
          $next = $this->header->decode($pkiMessage);
        break;
        case 1: //body
          $decoded = asn1decode($pkiMessage);
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed'] && $decoded['type'] >= 0 && $decoded['type'] <= 26) {
            $this->body = new PKIBody();
            $this->body->type = $decoded['type'];
            switch($this->body->type) {
            //only request (not response) types are listed in this switch, and only supported request types
              case 0: //ir
                $this->body->content = new CertReqMessages();
                $this->body->content->decode($decoded['value']);
              break;
              case 2: //cr, CertReqMessages
                $this->body->content = new CertReqMessages();
                $this->body->content->decode($decoded['value']);
              break;
              case 4: //p10cr, CertificationRequest (CSRs) - for legacy apps, should not be used unless absolutely necessary (from RFC4210)
                $this->body->content = new CertificationRequest();
                $this->body->content->decode($decoded['value']);
              break;
              case 7: //kur, CertReqMessages
                $this->body->content = new CertReqMessages();
                $this->body->content->decode($decoded['value']);
              break;
                case 9: //krr, CertReqMessages
                throw new Exception("Key recovery request (KRR) is not supported. This CA does not store client private keys.", BAD_REQUEST);
              break;
              case 11: //rr, RevReqContent
                $this->body->content = new RevReqContent();
                $this->body->content->decode($decoded['value']);
              break;
              case 13: //ccr, CertReqMessages
                throw new Exception("Cross-certificate request (CCR) is not currently supported since we only have one CA", BAD_REQUEST);
              break;
              case 21: //genm, GenMsgContent
                $this->body->content = new GenMsgContent();
                $this->body->content->decode($decoded['value']);
              break;
              case 23: //error, ErrorMsgContent
                $this->body->content = new ErrorMsgContent();
                $next = $this->body->content->decode($decoded['value']);
              break;
              case 24: //certConf, CertConfirmContent
                $this->body->content = new CertConfirmContent();
                $this->body->content->decode($decoded['value']);
              break;
              case 25: //pollReq, PollReqContent
                throw new Exception("Poll request (pollReq) is not supported. Certificates are either issued or rejected in a response message at once.", BAD_REQUEST);
              break;
              default:
                throw new Exception("Unsupported request type: " . $this->type, BAD_REQUEST);
            } 
            $next = $decoded['length'] + $decoded['hl'];
          }
          else
            throw new Exception("PKIMessage::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed class with a type from 0 to 26, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
        break;
        default: 
          $decoded = asn1decode($pkiMessage);
          if ($decoded['class'] == CONTEXT_SPECIFIC_CLASS && $decoded['constructed']) {
            if ($decoded['type'] == 0) { //PKIProtection
              $this->protection = new PKIProtection();
              $this->protection->decode($decoded['value']);
            }
            elseif ($decoded['type'] == 1) { //extraCerts
              $this->extraCerts = new ExtraCerts();
              $this->extraCerts->decode($decoded['value']);
            }
            else
              throw new Exception("PKIMessage::decode() error: bad message check: expected an ASN.1 context-specific type 0 or 1, received type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
            $next = $decoded['length'] + $decoded['hl'];
          } else
            throw new Exception("PKIMessage::decode() error: bad message check: expected an ASN.1 CONTEXT_SPECIFIC_CLASS constructed type with a value 0 or 1, received class " . class2str($decoded['class']) . ", constructed " . $decoded['constructed'] . ", type " . type2str($decoded['type']), BAD_MESSAGE_CHECK);
        break;
      }
      $pkiMessage = substr($pkiMessage, $next);
      $iter++;
    }
    return $offset;
  }

  // $signingCert is a Certificate object, $secret is a string
  function validateProtection($secret = null, $signingCert = null) {
    if (! is_null($this->header->protectionAlg) || ! is_null($this->protection)) {
      if (is_null($this->protection))
        throw new Exception('pkiHeader protectionAlg is not null but pkiMessage protection BIT_STRING is', WRONG_INTEGRITY);
      if (is_null($this->header->protectionAlg))
        throw new Exception('pkiHeader protectionAlg is null but pkiMessage protection BIT_STRING is not', WRONG_INTEGRITY);
      if ($this->header->protectionAlg->algorithm == str2oid('password based MAC') && is_null($secret))
        throw new Exception('Password based MAC algorithm requires a shared secret but it is null', WRONG_INTEGRITY);
      $res = $this->protection->validate($secret, $signingCert);
      if (! $res)
        throw new Exception('Failed to verify the PKI message signature', BAD_MESSAGE_CHECK);
    }
  }

  function __construct($pkiMessage = null) {
    global $client_cert_enroll_url;

    $this->protection = null;
    $this->extraCerts = null;
    if (! is_null($pkiMessage)) {
      list($pkiHeader, $pkiBody) = $pkiMessage;
      $this->header = new PKIHeader($pkiHeader);
      $this->body = new PKIBody($pkiBody);
      if (count($pkiMessage) > 2) {
        $res = false;
        $this->protection = new PKIProtection($pkiMessage);
        $this->extraCerts = new ExtraCerts($pkiMessage);         
      } else
        throw new Exception("Missing pkiMessage protection", BAD_REQUEST);
    }
  }
}  

?>