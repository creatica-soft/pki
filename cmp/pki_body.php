<?php

require_once 'asn1_types.php';
require_once 'asn1encode.php';
require_once 'helper_functions.php';
require_once 'pki_status_info.php';

require_once 'cert_req_msg.php';
require_once 'rev_req.php';
require_once 'cert_confirm.php';
require_once 'error_msg.php';
require_once 'genm.php';

const IR = 0;
const IP = 1;
const CR = 2;
const CP = 3;
const P10CR = 4;
const POPDECC = 5;
const POPDECR = 6;
const KUR = 7;
const KUP = 8;
const KRR = 9;
const KRP = 10;
const RR = 11;
const RP = 12;
const CRR = 13;
const CCP = 14;
const CKUANN = 15;
const CANN = 16;
const RANN = 17;
const CRLANN = 18;
const PKICONF = 19;
const NESTED = 20;
const GENM = 21;
const GENP = 22;
const ERROR = 23;
const CERTCONF = 24;
const POLLREQ = 25;
const POLLREP = 26;

/*
        PKIBody ::= CHOICE {
          ir       [0]  CertReqMessages,       --Initialization Req
          ip       [1]  CertRepMessage,        --Initialization Resp
          cr       [2]  CertReqMessages,       --Certification Req
          cp       [3]  CertRepMessage,        --Certification Resp
          p10cr    [4]  CertificationRequest,  --PKCS #10 Cert.  Req.
          popdecc  [5]  POPODecKeyChallContent --pop Challenge
          popdecr  [6]  POPODecKeyRespContent, --pop Response
          kur      [7]  CertReqMessages,       --Key Update Request
          kup      [8]  CertRepMessage,        --Key Update Response
          krr      [9]  CertReqMessages,       --Key Recovery Req
          krp      [10] KeyRecRepContent,      --Key Recovery Resp
          rr       [11] RevReqContent,         --Revocation Request
          rp       [12] RevRepContent,         --Revocation Response
          ccr      [13] CertReqMessages,       --Cross-Cert.  Request
          ccp      [14] CertRepMessage,        --Cross-Cert.  Resp
          ckuann   [15] CAKeyUpdAnnContent,    --CA Key Update Ann.
          cann     [16] CertAnnContent,        --Certificate Ann.
          rann     [17] RevAnnContent,         --Revocation Ann.
          crlann   [18] CRLAnnContent,         --CRL Announcement
          pkiconf  [19] PKIConfirmContent,     --Confirmation
          nested   [20] NestedMessageContent,  --Nested Message
          genm     [21] GenMsgContent,         --General Message
          genp     [22] GenRepContent,         --General Response
          error    [23] ErrorMsgContent,       --Error Message
          certConf [24] CertConfirmContent,    --Certificate confirm
          pollReq  [25] PollReqContent,        --Polling request
          pollRep  [26] PollRepContent         --Polling response
          }
*/

class PKIBody {
  public $type;
  public $content;

  function encode() {
    if (! is_null($this->content))
      $encoded = $this->content->encode();
    else $encoded = asn1encode($class = 0, $constructed = false, $type = NULL_VALUE, $value = '');
    return asn1encode($class = 2, $constructed = true, $type = $this->type, $value = $encoded);
  }
}
