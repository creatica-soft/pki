<?php

require_once 'asn1decode.php';
require_once 'cert_template.php';
require_once 'certificate.php';
require_once 'signed_data.php';

class BinarySecurityTokenType { //base64encoded cert, cert bundle, cert req, etc
  public $ValueType; //attribute; for example, http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10
  public $EncodingType; //attribute, must be set to http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary
  public $Id; //attribute, string, empty in ms request example
}

class RequestSecurityTokenType {
  public $TokenType; //anyURI
  public $RequestType; //anyURI
                       //WSTEP uses the following types:
                       //http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue - new or renew cert request - we only support this type!
                       //http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET - key exchange token     
                       //http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus                       
  public $BinarySecurityToken; //BinarySecurityTokenType object with attribute ValueType (anyURI)
  public $any;
  public $PreferredLanguage; //attribute, string
  public $Context; //attribute, anyURI
}

class RequestedSecurityTokenType { //issued or pending cert
  public $BinarySecurityToken; //BinarySecurityTokenType - contains issued cert, encoded as in [MS-WCCE] section 2.2.2.8
  public $any;
}

class DispositionMessageType {
  public $lang; //attribute
}

class RequestSecurityTokenResponseType {
  public $TokenType; //TokenType (anyURI); http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3 in ms example
  public $DispositionMessage; //DispositionMessageType, string with option lang attribute; "Issued" in ms example
  public $BinarySecurityToken; //BinarySecurityTokenType - contains issued cert, encoded as in [MS-WCCE] section 2.2.2.8; cert bundle including issued cert in ms example in pkcs 7 pem
  public $RequestedSecurityToken; //RequestedSecurityTokenType; issued single cert in ms example in x509 pem
  public $RequestID;
  public $any;
  public $Context; //attribute, anyURI
}

class RequestSecurityTokenResponseCollectionType {
  public $RequestSecurityTokenResponse; //RequestSecurityTokenResponseType
}

class CertificateEnrollmentWSDetailType { //could be used as part of $server->fault(...$details...)
  public $BinaryResponse; //string, nillable
  public $ErrorCode; //int, nillable
  public $InvalidRequest; //boolean, nillable
  public $RequestID; //string, nillable
}

class ActivityIdType { //soap response header from http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics namespace
  public $CorrelationId; //attribute
}

class UsernameTokenType {
  public $Username;
  public $Password;
}

class SecurityHeaderType {
  public $UsernameToken; //UsernameTokenType
}

class RequestSecurityTokenService {
  public $messageID;
  public $requestSecurityTokenResponseCollection; //RequestSecurityTokenResponseCollection
  public $username;
  public $mail;
  
  function Action($action) {
    if ($action != 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep')
      throw new Exception("SOAP header Action is not equaled to http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep (Received: $action)");
  }
  
  function MessageID($id) {
    global $log_level;
    $this->messageID = $id;
    if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
      errorLog("mswstep server.php: MessageID is $id\n", 'info');
  }
  
  function To($uri) {
    global $base_url, $wstep_path;
    if ($uri != "$base_url$wstep_path")
      throw new Exception("mswstep server.php: SOAP header To is not equaled to $base_url$wstep_path (Received: $uri)", 'error');
  }
  
  function Security($security) {
    global $ldap_encrypted_pass, $signing_ca_privkey_path, $ldap_uri, $ldap_binding_dn, $ldap_base_dn, $ldap_service_accounts_base_dn, $ldap_ca_cert_file;
    if (is_object($security) && get_class($security) == 'stdClass') {
      if (is_object($security->UsernameToken) && get_class($security->UsernameToken) == 'stdClass') {
        if (! is_null($security->UsernameToken->Username) && ! is_null($security->UsernameToken->Password)) {
          $this->username = $security->UsernameToken->Username;
          $password = $security->UsernameToken->Password;
          $this->mail = auth($this->username, $password);
          errorLog("mswstep server.php Security(): user " . $this->username . " authenticated successfully");
        } else
          throw new Exception('missing Username and/or Password in the header');
      } else
        throw new Exception('missing UsernameToken in the header');
    } else
      throw new Exception('missing security header');
  }
 
  function RequestSecurityToken($request) {
    global $authentication_enabled, $default_username, $server, $min_key_size, $cert_validity_days, $base_url, $wstep_path, $signing_ca_der_path, $root_ca_der_path, $master_users, $log_level, $default_digest_alg, $allow_user_supplied_emails_in_san;
    if (! $authentication_enabled)
      $this->username = $default_username;
    if (is_null($this->username))
      throw new Exception('RequestSecurityToken() error: username is null');

    if (is_object($request) && get_class($request) == 'RequestSecurityTokenType') {
      if (!is_null($request->RequestType) && $request->RequestType != 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue')
          throw new Exception('mswstep server.php: RequestSecurityToken() requestType ' . $request->requestType);
      if (is_object($request->BinarySecurityToken) && get_class($request->BinarySecurityToken) == 'BinarySecurityTokenType') {
        if (! is_null($request->BinarySecurityToken->EncodingType) && $request->BinarySecurityToken->EncodingType != 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary')
          throw new Exception('RequestSecurityToken() EncodingType is not equaled to http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary (Received: ' . $request->BinarySecurityToken->EncodingType . ')');
        $csr = '';
        if (! is_null($request->BinarySecurityToken->ValueType)) {
          switch ($request->BinarySecurityToken->ValueType) {
            case 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10':
              $csrDer = base64_decode(str_replace(['&#xD;', '&#13;', "\n"], ['', '', ''], $request->BinarySecurityToken->_));      
              $csr = new CertificationRequest();
              $csr->decode($csrDer);
            break;
            case 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7':
              $pkcs7 = base64_decode(str_replace(['&#xD;', '&#13;', "\n"], ['', '', ''], $request->BinarySecurityToken->_));
              $contentInfo = new ContentInfo();
              $contentInfo->decode($pkcs7);
              if ($contentInfo->contentType == '1.2.840.113549.1.7.2') { //pkcs7-signedData 
                if ($contentInfo->content->contentInfo->contentType == '1.2.840.113549.1.7.1') //pkcs7-data
                  $csr = $contentInfo->content->contentInfo->content;
                else
                  throw new Exception('mswstep server.php: RequestSecurityToken() pkcs7-signedData contentType is not 1.2.840.113549.1.7.1, received ' . $signedData->contentType);
              }
            break;
            default:
              throw new Exception('RequestSecurityToken() ValueType is neither PKCS10 nor PKCS7 (Received: ' . $request->BinarySecurityToken->ValueType . ')');
          }
        } else
          throw new Exception('RequestSecurityToken() is missing ValueType');
        $certTemplate = new CertTemplate();
        $role = 'standard';
        if (in_array($this->username, $master_users))
          $role = 'master';
        $certTemplate->csr2template($csr, $role);
        
        $certTemplateName = $certTemplate->extensions->getCertificateTemplateName();
        if (! $certTemplateName)
          throw new Exception('RequestSecurityToken() getCertificateTemplateName() returned false');
        if ($certTemplateName == 'Email') {
          $generalNames = array();
          $generalNames[] = new GeneralName($this->mail);
          $certTemplate->extensions->setSubjectAltName($generalNames, $allow_user_supplied_emails_in_san);    
        }
        
        $cert = new Certificate();
        $cert->set($certTemplate, $this->username, $defaultExtKeyUsages = false, $role);
        $cert->sign();
        $cert->save($status = 0);
        $encodedCert = $cert->encode();
      
        $this->requestSecurityTokenResponseCollection = new RequestSecurityTokenResponseCollectionType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse = new RequestSecurityTokenResponseType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->TokenType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->DispositionMessage = new DispositionMessageType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->DispositionMessage->_ = 'Issued';
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->BinarySecurityToken = new BinarySecurityTokenType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->BinarySecurityToken->ValueType =  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7';
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->BinarySecurityToken->EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary';


        $contentInfo = new ContentInfo('1.2.840.113549.1.7.2'); //signedData
        $contentInfo->content->contentInfo = new ContentInfo('1.3.6.1.5.5.7.12.3'); //PKIResponse
        $contentInfo->content->contentInfo->content = new PKIResponse(0, 'Issued', openssl_digest($encodedCert, 'sha1'));
        $contentInfo->content->certificates = array();
        $contentInfo->content->certificates[0] = new Certificate($root_ca_der_path);
        $contentInfo->content->certificates[1] = new Certificate($signing_ca_der_path);
        $contentInfo->content->certificates[2] = $cert;
        $issuer = $contentInfo->content->certificates[1]->tbsCertificate->issuer;
        $sn = $contentInfo->content->certificates[1]->tbsCertificate->serialNumber;
        $octets = asn1decode($contentInfo->content->contentInfo->content->encode())['value'];
        $contentInfo->content->signerInfos = new SignerInfos();
        $contentInfo->content->signerInfos->signerInfos[] = new SignerInfo($issuer, $sn, hex2bin($octets));
        $der = $contentInfo->encode();

        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->BinarySecurityToken->_ = rtrim(chunk_split(base64_encode($der), 64)); //cert bundle
  
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->RequestedSecurityToken = new RequestedSecurityTokenType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->RequestedSecurityToken->BinarySecurityToken = new BinarySecurityTokenType();
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->RequestedSecurityToken->BinarySecurityToken->EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary';
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->RequestedSecurityToken->BinarySecurityToken->ValueType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'; 
        $this->requestSecurityTokenResponseCollection->RequestSecurityTokenResponse->RequestedSecurityToken->BinarySecurityToken->_ = rtrim(chunk_split(base64_encode($encodedCert), 64)); //issued cert

        $header = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep', true); 
        $server->addSoapHeader($header);

        $header = new SoapHeader('http://www.w3.org/2005/08/addressing', 'RelatesTo', $this->messageID);
        $server->addSoapHeader($header);

        return $this->requestSecurityTokenResponseCollection;
      } else
        throw new Exception('request is missing BinarySecurityToken');
    } else
      throw new Exception('wrong request type: must be RequestSecurityTokenType');
  }  
}
