<?php

require_once 'asn1encode.php';

class FilterOIDCollection {
  public $oid; //array
  function __construct() {
    $this->oid = array();
  }
}

class RequestFilter {
  public $policyOIDs; //FilterOIDCollection object
  public $clientVersion; //int
  public $serverVersion; //int
  public $any;
}

class Client {
  public $lastUpdate; //XMLSchema dateTime
  public $preferredLanguage; //XMLSchema language
  public $any;
}

class GetPolicies {
  public $client; //Client object
  public $requestFilter; //RequestFilter object
}

class CAReferenceCollection {
  public $cAReference; //array of int 
  function __construct() {
    $this->cAReference = array();
  }
}

class CertificateValidity {
  public $validityPeriodSeconds; //unsigned long
  public $renewalPeriodSeconds; //unsigned long
}

class EnrollmentPermission {
  public $enroll; //boolean
  public $autoEnroll; //boolean
}

class CryptoProviders {
  public $provider; //array of strings
  function __construct() {
    $this->provider = array();
  }
}

class PrivateKeyAttributes {
  public $minimalKeyLength; //unsigned int
  public $keySpec; //unsigned int
  public $keyUsageProperty; //unsigned int
  public $permissions; //string
  public $algorithmOIDReference; //int
  public $cryptoProviders; //CryptoProviders object
}

class Revision {
  public $majorRevision; //unsigned int
  public $minorRevision; //unsigned int  
}

class SupersededPolicies {
  public $commonName; //array of strings
  function __construct() {
    $this->commonName = array();
  }
}

class OIDReferenceCollection {
  public $oIDReference; //array of int
}

class RARequirements {
  public $rASignatures; //unsigned int
  public $rAEKUs; //OIDReferenceCollection
  public $rAPolicies; //OIDReferenceCollection  
}

class KeyArchivalAttributes {
  public $symmetricAlgorithmOIDReference; //int
  public $symmetricAlgorithmKeyLength; //unsigned int
}

class Extension {
  public $oIDReference; //int
  public $critical; //boolean
  public $value; //base64Binary
}

class ExtensionCollection {
  public $extension; //array of Extension objects
  function __construct() {
    $this->extension = array();
  }
}

class Attributes {
  public $commonName; //string
  public $policySchema; //unsigned int
  public $certificateValidity; //CertificateValidity object
  public $permission; //EnrollmentPermission object
  public $privateKeyAttributes; //PrivateKeyAttributes object
  public $revision; //Revision object
  public $supersededPolicies; //SupersededPolicies object
  public $privateKeyFlags; //unsigned int
  public $subjectNameFlags; //unsigned int
  public $enrollmentFlags; //unsigned int
  public $generalFlags; //unsigned int
  public $hashAlgorithmOIDReference; //int
  public $rARequirements; //RARequirements object
  public $keyArchivalAttributes; //KeyArchivalAttributes object
  public $extensions; //ExtensionCollection object
  public $any;
}

class CertificateEnrollmentPolicy {
  public $policyOIDReference; //int
  public $cAs; //CAReferenceCollection object
  public $attributes; //Attributes object
  public $any;
}

class PolicyCollection {
  public $policy; //array of CertificateEnrollmentPolicy objects
  function __construct() {
    $this->policy = array();
  }
}

class Response {
  public $policyID; //string
  public $policyFriendlyName; //string
  public $nextUpdateHours; //unsigned int
  public $policiesNotChanged; //boolean
  public $policies; //PolicyCollection
  public $any;
}

class CAURI {
  public $clientAuthentication; //unsigned int
  public $uri; //XMLSchema anyURI
  public $priority; //unsigned int
  public $renewalOnly; //boolean
  public $any;
}

class CAURICollection {
  public $cAURI; //array of CAURI objects
  function __construct() {
    $this->cAURI = array();
  }
}

class CA {
  public $uris; //CAURICollection object
  public $certificate; //base64Binary
  public $enrollPermission; //boolean
  public $cAReferenceID; //int
  public $any;
}

class CACollection {
  public $cA; //array of CA objects;
  function __construct() {
    $this->cA = array();
  }
}

class OID {
  public $value; //string
  public $group; //unsigned int
  public $oIDReferenceID; //int
  public $defaultName; //string
  public $any;
}

class OIDCollection {
  public $oID; //array of OID objects
  function __construct() {
    $this->oID = array();
  }
}

class GetPoliciesResponse {
  public $response; //Response object
  public $cAs; //CACollection object
  public $oIDs; //OIDCollection object
}

class UsernameTokenType {
  public $Username;
  public $Password;
}

class SecurityHeaderType {
  public $UsernameToken; //UsernameTokenType
}

class GetPoliciesService {
  public $messageID;
  public $getPolicies;
  public $getPoliciesResponse;
  
  function Action($action) {
    global $msxcep_action;
    if ($action != $msxcep_action)
      throw new Exception("SOAP envelope header Action is $action but expected one is $msxcep_action\n", 'error');
  }
  
  function MessageID($id) {
    global $log_level;
    $this->messageID = $id;
    if ($log_level == LOG_DEBUG)
      errorLog("msxcep server.php: SOAP envelope header MessageID id is $id\n", 'debug');    
  }
  
  function To($uri) {
    global $base_url, $xcep_path;
    if ($uri != "$base_url$xcep_path")
      throw new Exception("SOAP envelope header To is $uri but expected one is $base_url$xcep_path\n", 'error');
  }
  
  function Security($security) {
    global $ldap_encrypted_pass, $signing_ca_privkey_path, $ldap_uri, $ldap_binding_dn, $ldap_base_dn, $ldap_service_accounts_base_dn, $ldap_ca_cert_file;
    if (is_object($security) && get_class($security) == 'stdClass') {
      if (is_object($security->UsernameToken) && get_class($security->UsernameToken) == 'stdClass') {
        if (! is_null($security->UsernameToken->Username) && ! is_null($security->UsernameToken->Password)) {
          $username = $security->UsernameToken->Username;
          $password = $security->UsernameToken->Password;
          
          while (openssl_error_string());
          $res = openssl_private_decrypt(hex2bin($ldap_encrypted_pass), $pass, file_get_contents($signing_ca_privkey_path));
          if (! $res) {
            $error = '';
            while ($err = openssl_error_string()) $error .= $err;
            throw new Exception("openssl_private_decrypt() error: $error");
          }

          $atv = ldapsearch($ldap_uri, $ldap_binding_dn, $pass, $ldap_base_dn, "(sAMAccountName=$username)", ['distinguishedName', 'mail'], $ldap_ca_cert_file);
          if (count($atv) == 0) {
            $atv = ldapsearch($ldap_uri, $ldap_binding_dn, $pass, $ldap_service_accounts_base_dn, "(sAMAccountName=$username)", ['distinguishedName', 'mail'], $ldap_ca_cert_file);
            if (count($atv))
              throw new Exception("Security() error: ldap_binding_dn username ($ldap_binding_dn) or password is invalid");
          }

          $key = array_keys($atv)[0];
          $dn = $atv[$key]['distinguishedName'];
          $mail = $atv[$key]['mail'];
          $res = ldapbind($ldap_uri, $dn, $password, $ldap_ca_cert_file);
          if (! $res)
            throw new Exception("username ($username) or password is invalid");
          else errorLog("msxcep server.php Security(): user $username authenticated successfully");
        } else
          throw new Exception('missing Username and/or Password in the header');
      } else
        throw new Exception('missing UsernameToken in the header');
    } else
      throw new Exception('missing security header');
  }
  
  private function setKeyUsage($keyUsage) {
    if (! is_array($keyUsage))
      throw new TypeError('setKeyUsage() error: argument is not an array');
    $ku = $keyUsage['decipherOnly'] | ($keyUsage['encipherOnly'] << 1) | ($keyUsage['crlSign'] << 2) | ($keyUsage['keyCertSign'] << 3) | ($keyUsage['keyAgreement'] << 4) | ($keyUsage['dataEncipherment'] << 5) | ($keyUsage['keyEncipherment'] << 6) | ($keyUsage['nonRepudiation'] << 7) | ($keyUsage['digitalSignature'] << 8);
    if ($ku == 0)
      throw new Exception('setKeyUsage() error: at least one bit in keyUsage extension must be set');
    if ($keyUsage['decipherOnly'] == 0) $ku >>= 1;
    $res = strrchr(decbin($ku), '1');
    $unused_bits = $res ? dechex(strlen($res) - 1) : '00';
    if (strlen($unused_bits) % 2 != 0) $unused_bits = '0' . $unused_bits;
    $ku = dechex($ku);
    if (strlen($ku) % 2 != 0) $ku = '0' . $ku;
    return asn1encode($class = 0, $constructed = false, $type = BIT_STRING, $value = $unused_bits . $ku);
  }
    
  private function setExtendedKeyUsage($extKeyUsages) {
    if (! is_array($extKeyUsages))
      throw new TypeError('setExtendedKeyUsage() error: argument is not an array');
    $encoded = '';
    foreach ($extKeyUsages as $usage)
      $encoded .= asn1encode($class = 0, $constructed = false, $type = OBJECT_IDENTIFIER, $value = str2oid($usage));
    return asn1encode($class = 0, $constructed = true, $type = SEQUENCE, $value = $encoded);
  }
  
  private function setCertificateTemplateName($name) {
    return asn1encode($class = 0, $constructed = false, $type = BMP_STRING, $value = $name);
  }
  
  function GetPolicies($request) {
    global $server, $minimum_key_size, $certificate_validity_days, $base_url, $wstep_path, $signing_ca_der_path, $xcep_path, $policy_id, $policy_friendly_name, $policy_next_update_hours, $policies_last_update, $policy_oids, $policy_names, $policy_schemas, $enroll, $auto_enroll, $key_spec, $key_usage, $private_key_permissions, $pk_algorithm_oid, $pk_algorithm_name, $hash_algorithm_oid, $hash_algorithm_name, $crypto_providers, $major_revision, $minor_revision, $private_key_flags, $subject_name_flags, $enrollment_flags, $general_flags, $ca_uri, $ca_auth, $ca_priority, $ca_renewal_only, $ca_enroll_permission, $ca_cert, $now, $extended_key_usages, $log_level;

    if (is_object($request) && get_class($request) == 'GetPolicies') {
      $this->getPolicies = new GetPolicies();
      $client = null;
      if (is_object($request->client) && get_class($request->client) == 'Client') {
        $client = new Client();
        if (! is_null($request->client->lastUpdate)) {
          $client->lastUpdate = $request->client->lastUpdate; //GMT format 2009-03-15T09:38:46 or in php 'Y-d-m\TH:i:s'
          if ($log_level == LOG_DEBUG)
            errorLog('msxcep server.php: GetPolicies() lastUpdate ' . $request->client->lastUpdate, 'debug');
        }
        if (! is_null($request->client->preferredLanguage)) {
          $client->preferredLanguage = $request->client->preferredLanguage;
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog('msxcep server.php: GetPolicies() preferredLanguage ' . $request->client->preferredLanguage, 'info');
        }
      } else
        //we must respond with SOAP Fault
        throw new Exception('missing GetPolicies->Client');
      $this->getPolicies->client = $client;
      $requestFilter = null;
      if (is_object($request->requestFilter) && get_class($request->requestFilter) == 'RequestFilter') {
        $requestFilter = new RequestFilter();
        $policyOids = null;
        if (! is_null($request->requestFilter->policyOIDs)) {
          $policyOids = new FilterOIDCollection();
          if (is_array($request->requestFilter->policyOIDs))
            $policyOids->oid = $request->requestFilter->policyOIDs;
          else $policyOids->oid[] = $request->requestFilter->policyOIDs;
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog('msxcep server.php: GetPolicies() policyOids ' . print_r($request->requestFilter->policyOIDs, true), 'info');
        }
        if (! is_null($request->requestFilter->clientVersion)) {
          $requestFilter->clientVersion = $request->requestFilter->clientVersion;
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog('msxcep server.php: GetPolicies() clientVersion ' . $request->requestFilter->clientVersion, 'info');
        }
        if (! is_null($request->requestFilter->serverVersion)) {
          $requestFilter->serverVersion = $request->requestFilter->serverVersion;
          if ($log_level == LOG_DEBUG || $log_level == LOG_INFO)
            errorLog('msxcep server.php: GetPolicies() serverVersion ' . $request->requestFilter->serverVersion, 'info');
        }
        $requestFilter->policyOIDs = $policyOids;
      }
      $this->getPolicies->requestFilter = $requestFilter;
    
      $this->getPoliciesResponse = new GetPoliciesResponse();
      $response = new Response();
      $response->policyID = $policy_id; //uuid or guid
      $response->policyFriendlyName = $policy_friendly_name;
      $response->nextUpdateHours = $policy_next_update_hours;
      
      if (! is_null($this->getPolicies->client->lastUpdate)) {
        $lastUpdate =  DateTimeImmutable::createFromFormat('Y-d-m\TH:i:s', $policies_last_update);
        $clientLastUpdate = DateTimeImmutable::createFromFormat('Y-d-m\TH:i:s', $this->getPolicies->client->lastUpdate);
        
        if ($lastUpdate->diff($clientLastUpdate) > 0) {
          $response->policiesNotChanged = true;
          $response->policies = null;
          $this->getPoliciesResponse->response = $response;
          $this->getPoliciesResponse->cAs = null;
          $this->getPoliciesResponse->oIDs = null;
          return $this->getPoliciesResponse;
        }
      }
      
      $response->policiesNotChanged = null;
      $policies = new PolicyCollection(); //collection members could be as many as Certificate Templates!      
      
      $i = 0;
      $notInRequestFilter = false;
      $numberOfPolicies = count($policy_oids);
      $numberOfOIDs = $numberOfPolicies;
      $extensionsOIDoffset = $numberOfOIDs + $numberOfPolicies * 2; //pk_algorithm_oid + hash_algorithm_oid = 2
      $numberOfCAs = count($ca_uri);
      $oids = new OIDCollection();
      for ($p = 0; $p < $numberOfPolicies; $p++) {
        $oid = new OID();
        $oid->value = $policy_oids[$p]; //populated from msPKI-Cert-Template-OID attribute
        $oid->defaultName = $policy_names[$p]; //populated from DisplayName attribute
/*
OID Groups:
1 Hash algorithm identifier.
2 Encryption algorithm identifier.
3 Public key identifier.
4 Signing algorithm identifier.
5 Relative distinguished name (RDN) identifier.
6 Certificate extension or attribute identifier.
7 Extended key usage identifier.
8 Certificate policy identifier.
9 Enrollment object identifier.
*/
        $oid->group = 9;
        $oid->oIDReferenceID = $p;
        $oids->oID[] = $oid;
      }
      foreach ($policy_oids as $policy_oid) {
        if (! is_null($this->getPolicies->requestFilter) && ! is_null($this->getPolicies->requestFilter->policyOIDs)) {
          $notInRequestFilter = true;
          if (! in_array($policy_oid, $this->getPolicies->requestFilter->policyOIDs->oid)) {
            continue;
          } else $notInRequestFilter = false;
        }
        
        $policy = new CertificateEnrollmentPolicy(); //one policy for each Certificate Template; 
                                                     
        $policy->policyOIDReference = $i; //int; must be present in oIDs
        $cAsRef = new CAReferenceCollection();
        for ($j = 0; $j < $numberOfCAs; $j++)
          $cAsRef->cAReference[$j] = $j; //int; must be present in cAs
        $policy->cAs = $cAsRef;
                
        $attributes = new Attributes(); //attributes of a Certificate Template matching policyOIDReference
        $attributes->commonName = $policy_names[$i]; 
        $attributes->policySchema = $policy_schemas[$i]; 
        $attributes->certificateValidity = new CertificateValidity();
        $attributes->certificateValidity->validityPeriodSeconds = $certificate_validity_days[$i] * 24 * 3600; 
        //recommended renewal period - one month in advance of expiration, for example
        $attributes->certificateValidity->renewalPeriodSeconds = $attributes->certificateValidity->validityPeriodSeconds - 30 * 24 * 3600;           
        $permission = new EnrollmentPermission();
        $permission->enroll = $enroll[$i];
        $permission->autoEnroll = $auto_enroll[$i];
        $attributes->permission = $permission;
        $privateKeyAttributes = new PrivateKeyAttributes();
        $privateKeyAttributes->minimalKeyLength = $minimum_key_size[$i];     
        $privateKeyAttributes->keySpec = $key_spec[$i]; 

        $privateKeyAttributes->keyUsageProperty = $key_usage[$i]; 
        $privateKeyAttributes->permissions = $private_key_permissions[$i]; 
        if (! is_null($pk_algorithm_oid[$i])) {
          $privateKeyAttributes->algorithmOIDReference = $numberOfOIDs; //no equivalent in cert template
          $oid = new OID();
          $oid->value = $pk_algorithm_oid[$i];
          $oid->defaultName = $pk_algorithm_name[$i];
          $oid->group = 2;
          $oid->oIDReferenceID = $numberOfOIDs;
          $oids->oID[] = $oid;
          $numberOfOIDs++;
        } else $privateKeyAttributes->algorithmOIDReference = null;
        $cryptoProviders = new CryptoProviders(); 
        $cryptoProviders->provider = $crypto_providers[$i];
        $privateKeyAttributes->cryptoProviders = $cryptoProviders;
        $attributes->privateKeyAttributes = $privateKeyAttributes;
        $attributes->revision = new Revision();
        $attributes->revision->majorRevision = $major_revision[$i]; 
        $attributes->revision->minorRevision = $minor_revision[$i];
        $attributes->supersededPolicies = null; //populated from msPKI-Supersede-Templates attribute   
        $attributes->privateKeyFlags = $private_key_flags[$i]; 
        $attributes->subjectNameFlags = $subject_name_flags[$i];         
        $attributes->enrollmentFlags = $enrollment_flags[$i];
        $attributes->generalFlags = $general_flags[$i];
        if (! is_null($hash_algorithm_oid[$i])) {
          $attributes->hashAlgorithmOIDReference = $numberOfOIDs; //no equivalent in cert template
          $oid = new OID();
          $oid->value = $hash_algorithm_oid[$i];
          $oid->defaultName = $hash_algorithm_name[$i];
          $oid->group = 1;
          $oid->oIDReferenceID = $numberOfOIDs;
          $oids->oID[] = $oid;
          $numberOfOIDs++;
        } else $attributes->hashAlgorithmOIDReference = null;
        $attributes->rARequirements = null; //populated from msPKI-RA-* attributes
        $attributes->keyArchivalAttributes = null; //no equivalent in cert template
        $extensions = new ExtensionCollection(); //critical extensions populated from CriticalExtensions attribute; 
                                                 //keyUsage from KeyUsage attribute, 
                                                 //Certificate Template Name ext is populated from the template name itself
        //KeyUsage extension
        $extension = new Extension();
        $extension->oIDReference = $extensionsOIDoffset;
        $extension->critical = false;
        $keyUsage = array('digitalSignature' => ($privateKeyAttributes->keyUsageProperty & 0x8000) >> 15, 
                          'nonRepudiation' => ($privateKeyAttributes->keyUsageProperty & 0x4000) >> 14, 
                          'keyEncipherment' => ($privateKeyAttributes->keyUsageProperty & 0x2000) >> 13, 
                          'dataEncipherment' => ($privateKeyAttributes->keyUsageProperty & 0x1000) >> 12, 
                          'keyAgreement' => ($privateKeyAttributes->keyUsageProperty & 0x800) >> 11, 
                          'keyCertSign' => ($privateKeyAttributes->keyUsageProperty & 0x400) >> 10, 
                          'crlSign' => ($privateKeyAttributes->keyUsageProperty & 0x200) >> 9, 
                          'encipherOnly' => ($privateKeyAttributes->keyUsageProperty & 0x100) >> 8, 
                          'decipherOnly' => ($privateKeyAttributes->keyUsageProperty & 0x80) >> 7);
        $extension->value = $this->setKeyUsage($keyUsage);
        $extensions->extension[] = $extension;
        
        //extKeyUsage extension
        $extension = new Extension();
        $extension->oIDReference = $extensionsOIDoffset + 1;
        $extension->critical = true;
        $extension->value = $this->setExtendedKeyUsage($extended_key_usages[$i]);
        $extensions->extension[] = $extension;

        //CertificateTemplate extension
        $extension = new Extension();
        $extension->oIDReference = $extensionsOIDoffset + 2;
        $extension->critical = false;
        $extension->value = $this->setCertificateTemplateName($policy_names[$i]);
        $extensions->extension[] = $extension;

        $attributes->extensions = $extensions;
        $policy->attributes = $attributes;
        $policies->policy[] = $policy;
        
        $i++;
      }
      if ($notInRequestFilter)
        throw new Exception("None of the policy OIDs: \n" . print_r($policy_oids, true) . " are found in RequestFilter->policyOIDs: \n" . print_r($this->getPolicies->requestFilter->policyOIDs->oid, true));
            
      $response->policies = $policies;
      $this->getPoliciesResponse->response = $response;
      $cAs = new CACollection();
      foreach ($cAsRef->cAReference as $ca) {
        $cA = new CA();
        $cA->cAReferenceID = $ca;
        $uris = new CAURICollection();
        $numberOfURIs = count($ca_uri[$ca]);
        for ($k = 0; $k < $numberOfURIs; $k++) {
          $cAURI = new CAURI();
          $cAURI->clientAuthentication = $ca_auth[$ca][$k]; //one of the above
          $cAURI->uri = $ca_uri[$ca][$k];
          $cAURI->priority = $ca_priority[$ca][$k];
          $cAURI->renewalOnly = $ca_renewal_only[$ca][$k];
          $uris->cAURI[] = $cAURI;
        }
        $cA->certificate = $ca_cert[$ca]; 
        $cA->enrollPermission = $ca_enroll_permission[$ca]; //true;
        $cA->uris = $uris;
        $cAs->cA[] = $cA;
      }
      $this->getPoliciesResponse->cAs = $cAs;

      foreach ($extensions->extension as $ext) {
        $oid = new OID();
        switch($ext->oIDReference) {
          case $extensionsOIDoffset:
            $oid->group = 6;
            $oid->value = '2.5.29.15';
            $oid->defaultName = 'Key Usage';
          break;
          case $extensionsOIDoffset + 1:
            $oid->group = 6;
            $oid->value = '2.5.29.37';
            $oid->defaultName = 'Extended Key Usage';
          break;
            case $extensionsOIDoffset + 2:
            $oid->value = '1.3.6.1.4.1.311.20.2';
            $oid->defaultName = 'Certificate Template Name';
            //$oid->value = '1.3.6.1.4.1.311.21.7';
            //$oid->defaultName = 'Certificate Template'; //uses OID instead of name - does not seem to work with schema 1
            $oid->group = 6;
          break;
        }
        $oid->oIDReferenceID = $ext->oIDReference;
        $oids->oID[] = $oid;
      }
      $this->getPoliciesResponse->oIDs = $oids;

      $header = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse', true); 
      $server->addSoapHeader($header);
      $header = new SoapHeader('http://www.w3.org/2005/08/addressing', 'RelatesTo', $this->messageID);
      $server->addSoapHeader($header);

      return $this->getPoliciesResponse;
    }
  }
}

?>