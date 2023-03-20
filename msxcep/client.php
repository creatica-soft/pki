<?php
//this is SOAP client to test MSXCEP SOAP server response
//response will be written to /tmp/msxcep-server-response.xml

require_once 'globals.php';
require_once 'helper_functions.php';
require_once 'classes.php';

$classmap = array('GetPolicies' => 'GetPolicies', 'Client' => 'Client', 'FilterOIDCollection' => 'FilterOIDCollection', 'RequestFilter' => 'RequestFilter');

if ($non_ssl_port_disabled)
  $stream_ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]]);
else $stream_ctx = null;
$options = array('soap_version' => SOAP_1_2, 'trace' => true, 'classmap' => $classmap, 'cache_wsdl' => WSDL_CACHE_NONE, 'stream_context' => $stream_ctx);
$soapClient = new SoapClient("policy-service.wsdl", $options);
$getPolicies = new GetPolicies();
$client = new Client();
$client->lastUpdate = null;
$client->preferredLanguage = null;
$getPolicies->client = $client;
$getPolicies->requestFilter = null;
$headers = array();
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies', true);
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'MessageID', 'urn:uuid:c186db69-3494-4991-ab18-b800d6f2a3fb');
$headers[] = new SoapHeader('http://www.w3.org/2005/08/addressing', 'To', 'https://pki.example.com/msxcep/', true);
$soapClient->__setSoapHeaders($headers);
if ($non_ssl_port_disabled)
  $soapClient->__setLocation('https://pki.example.com/msxcep/');
else 
  $soapClient->__setLocation('http://pki.example.com/msxcep/');
$soapClient->GetPolicies($getPolicies);
//errorLog('Request Headers: ' . $soapClient->__getLastRequestHeaders());
file_put_contents('/tmp/msxcep-client-request-headers.xml', $soapClient->__getLastRequestHeaders());
//errorLog('Request: ' . $soapClient->__getLastRequest());
file_put_contents('/tmp/msxcep-client-request.xml', $soapClient->__getLastRequest());
//errorLog('Response Headers: ' . $soapClient->__getLastResponseHeaders());
file_put_contents('/tmp/msxcep-server-response-headers.xml', $soapClient->__getLastResponseHeaders());
//errorLog('Response: ' . $soapClient->__getLastResponse());
file_put_contents('/tmp/msxcep-server-response.xml', $soapClient->__getLastResponse());

?>