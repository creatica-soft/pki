<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'pki_status_info.php';
require_once 'certificate.php';
require_once 'helper_functions.php';
require_once 'cert_response.php';
require_once 'globals.php';
require_once 'sql.php';

/*
CertRepMessage ::= SEQUENCE {
         caPubs          [1] SEQUENCE SIZE (1..MAX) OF Certificate
                             OPTIONAL,
         response            SEQUENCE OF CertResponse
     }
*/
class CertRepMessage {
  public $caPubs; //encoded already
  public $response;
  
  private function senderIsOwner($reqmsg) {
    global $request;
    $owner = $reqmsg->certReq->certTemplate->subject->getOwner();
    if (! $owner)
      throw new Exception("Missing owner in the subject of a cert in the certTemplate of certRequest for KUR", BAD_REQUEST);
    $cn = $request->header->sender->getCN();
    if (strcasecmp($owner, $cn) != 0 && strcasecmp($role, 'master') != 0)
      throw new Exception("Owner in the subject of a cert $owner is not equal to the sender CN $cn and CN role is $role", BAD_REQUEST);
  }

  private function checkOldCert($reqmsg) {
    if (! is_null($reqmsg->certReq->controls)) {
      $oldSN = null;
      foreach($reqmsg->certReq->controls->controlSeq as $seq) {
        if ($seq->attrType == '1.3.6.1.5.5.7.5.1.5') {
          if (! is_null($seq->attrValue) && is_object($seq->attrValue) && $seq->attrValue instanceof CertId) {
            $oldSN = $seq->attrValue->serialNumber;
            $cert = sqlGetCert($oldSN);
            if (is_null($cert))
              throw new Exception("Certificate with the sn $oldSN is not found; hence, it cannot be renewed", BAD_REQUEST);
            elseif ($cert['status'] == 1)
              throw new Exception("Certificate with the sn $oldSN has expired; hence, it cannot be renewed", BAD_REQUEST);
            elseif ($cert['status'] == -1)
              throw new Exception("Certificate with the sn $oldSN has been revoked; hence, it cannot be renewed", BAD_REQUEST);
            elseif ($cert['status'] == 2)
              throw new Exception("Certificate with the sn $oldSN is on-hold; hence, it cannot be renewed", BAD_REQUEST);
          } else
            throw new Exception("attrValue is either null, not an object or not an instance of CertId", BAD_REQUEST);
        } 
      }
      if (is_null($oldSN))
        throw new Exception("Unable to find id-regCtrl-oldCertID in controls in a certificate KUR request", BAD_REQUEST);
    } else
      throw new Exception("Missing id-regCtrl-oldCertID control field in a certificate KUR request", BAD_REQUEST);
  }

  function set() {
    global $log_level, $now, $request, $response, $signing_ca_privkey_path, $responseStatus, $metadata, $implicitConfirm, $max_pki_requests, $role;
    $reqNumber = 0;
    foreach($request->body->content->certReqMessages as $reqmsg) {
      if ($reqNumber >= $max_pki_requests)
          throw new Exception("CertRepMessage::set() error: max number of PKI requests $max_pki_requests is reached", SYSTEM_FAILURE);

      if ($request->body->type == KUR) {
        //need to check for KUR type requests that the cert owner is the sender
        $this->senderIsOwner($reqmsg);
        //sn of a certificate to be "renewed" is given in the controls field of CertReq
        //we should not revoke it though as it still may be in use
        //but we should check that it is not revoked or expired!
        $this->checkOldCert($reqmsg);
        //we might also need to preserve the stuff in the oldCert that is not subject of this update, RFC4210 is not clear on this
      }

      $cert = new Certificate();

      if ($request->body->type == IR) {
        $cert->set($reqmsg->certReq->certTemplate, $owner = null, $defaultExtKeyUsages = false, $role);      
      } else {
        $owner = $request->header->sender->getCN();
        $cert->set($reqmsg->certReq->certTemplate, $owner, $defaultExtKeyUsages = true, $role);
      }
      $cert->sign($signing_ca_privkey_path);
      if (! $implicitConfirm) {
        $status = -1; //revoked with revReason 6 (certificateHold) will be set automatically by Certificate->save() function
        sqlSaveCertReqIds($cert->tbsCertificate->serialNumber, $reqmsg->certReq->certReqId, $now->getTimestamp(), $response->header->senderNonce, $response->header->transactionID); 
      } else $status = 0;
      $cert->save($status);
      $status = new PKIStatusInfo();
      $status->status = $responseStatus; //ACCEPTED OR GRANTED_WITH_MODS
      $certResponse = new CertResponse($reqmsg->certReq->certReqId, $status, $cert);
      $this->response[] = $certResponse;
      $reqNumber++;
    }
  }
  
  function setFromCsr() {
    global $log_level, $now, $request, $response, $signing_ca_privkey_path, $responseStatus, $metadata, $implicitConfirm;

    $certTemplate = new CertTemplate();
    $certTemplate->csr2template($request->body->content);
    
    $this->checkQuotas($certTemplate->subject->getCN(), $certTemplate->subject);

    $cert = new Certificate();
    $cert->set($certTemplate);
    $cert->sign($signing_ca_privkey_path);
    $cn = $cert->tbsCertificate->subject->getCN();
    if (! $implicitConfirm) {
      $status = -1; //revoked with revReason 6 (certificateHold) will be set automatically by Certificate->save() function
      sqlSaveCertReqIds($cert->tbsCertificate->serialNumber, 0, $now->getTimestamp(), $response->header->senderNonce, $response->header->transactionID); 
    } else $status = 0;
    $cert->save($status);
    $status = new PKIStatusInfo();
    $status->status = $responseStatus; //ACCEPTED OR GRANTED_WITH_MODS
    $certResponse = new CertResponse(0, $status, $cert);
    $this->response[] = $certResponse;
    $reqNumber++;
  }

  function encode() {
    $certRepMessage = '';
    if (! is_null($this->caPubs)) {
      $encoded = '';
      foreach($this->caPubs as $caPub)
        $encoded .= $caPub;
      $certRepMessage .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
      $certRepMessage = asn1encode($class = 2, $constructed = true, $type = 1, $value = $certRepMessage);
    }
    $encoded = '';
    foreach($this->response as $response)
      $encoded .= $response->encode();
    $certRepMessage .= asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $certRepMessage);
  }
  
  function __construct($certResponses = null) {
    global $include_root_ca_cert_in_capubs;
    if ($include_root_ca_cert_in_capubs) {
      global $root_ca_der_path;
      $this->caPubs = array();
      if (file_exists($root_ca_der_path)) {
        $this->caPubs[] = file_get_contents($root_ca_der_path);
      } else $this->caPubs = null;
    } else $this->caPubs = null;
    $this->response = array();
    if (! is_null($certResponses)) {
      if (! is_array($certResponses))
        throw new Exception('CertRepMessage::__construct() error: an argument is neither null nor an array', SYSTEM_FAILURE);
      $this->response = $certResponses;
    }
  }
}

?>