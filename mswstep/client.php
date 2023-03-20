<?php
//this is SOAP client to test MS WSTEP SOAP server response
//for the client to work, one would need to either turn the authentication off by setting $authentication_enabled to false in globals.php
//or provide proper SecurityHeader with Username and Password
//file /tmp/req.pem should have PKCS10 CSR without -----BEGIN ***----- and ------END ***------ lines
//response will be written to /tmp/mswstep-server-response.xml

require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'classes.php';

$classmap = array('BinarySecurityTokenType' => 'BinarySecurityTokenType', 
                  'RequestSecurityTokenType' => 'RequestSecurityTokenType', 
                  'RequestedSecurityTokenType' => 'RequestedSecurityTokenType', 
                  'RequestSecurityTokenResponseType' => 'RequestSecurityTokenResponseType',
                  'RequestSecurityTokenResponseCollectionType' => 'RequestSecurityTokenResponseCollectionType',
                  'DispositionMessageType' => 'DispositionMessageType');

if ($non_ssl_port_disabled)
  $stream_ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]]);
else $stream_ctx = null;
$options = array('soap_version' => SOAP_1_2, 'trace' => true, 'classmap' => $classmap, 'cache_wsdl' => WSDL_CACHE_NONE, 'stream_context' => $stream_ctx);
$soapClient = new SoapClient("ws-trust-1.3.wsdl", $options);
$requestSecurityToken = new RequestSecurityTokenType();
$requestSecurityToken->TokenType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
$requestSecurityToken->RequestType = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue';
$requestSecurityToken->BinarySecurityToken = new BinarySecurityTokenType();
$requestSecurityToken->BinarySecurityToken->EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary';
$requestSecurityToken->BinarySecurityToken->ValueType = 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10';
$requestSecurityToken->BinarySecurityToken->Id = "";
$requestSecurityToken->BinarySecurityToken->_ = file_get_contents('/tmp/req.pem');
$requestSecurityToken->PreferredLanguage = "en-US";
$headers = array();
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep', true);
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'MessageID', 'urn:uuid:c186db69-3494-4991-ab18-b800d6f2a3fb');
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'To', 'https://pki.example.com/mswstep/', true);
$soapClient->__setSoapHeaders($headers);
if ($non_ssl_port_disabled)
  $soapClient->__setLocation('https://pki.example.com/mswstep/');
else 
  $soapClient->__setLocation('http://pki.example.com/mswstep/');
$soapClient->RequestSecurityToken($requestSecurityToken);
//errorLog('Request Headers: ' . $soapClient->__getLastRequestHeaders());
file_put_contents('/tmp/mswstep-client-request-headers.xml', $soapClient->__getLastRequestHeaders());
//errorLog('Request: ' . $soapClient->__getLastRequest());
file_put_contents('/tmp/mswstep-client-request.xml', $soapClient->__getLastRequest());
//errorLog('Response Headers: ' . $soapClient->__getLastResponseHeaders());
file_put_contents('/tmp/mswstep-server-response-headers.xml', $soapClient->__getLastResponseHeaders());
//errorLog('Response: ' . $soapClient->__getLastResponse());
file_put_contents('/tmp/mswstep-server-response.xml', $soapClient->__getLastResponse());

?>