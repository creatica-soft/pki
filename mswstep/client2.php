<?php
require_once 'classes.php';

$options = array(
    'soap_version' => SOAP_1_2,
    'trace' => true,
    'cache_wsdl' => WSDL_CACHE_NONE,
    'classmap' => array(
        'RequestSecurityTokenType' => 'RequestSecurityTokenType',
        'BinarySecurityTokenType' => 'BinarySecurityTokenType',
    ),
);

$soapClient = new SoapClient("ws-trust-1.3.wsdl", $options);
$non_ssl_port_disabled = false;

// ... (keep the require_once, $classmap, $options, and $soapClient creation as is)

// Define the inner XML for RequestSecurityToken as a raw string
$csr = file_get_contents('/tmp/req.pem');  // Get the CSR content

$xml = '<RequestSecurityToken PreferredLanguage="en-US" xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
    <TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
    <RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
    <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" a:Id="" xmlns:a="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' . htmlspecialchars($csr) . '</BinarySecurityToken>
</RequestSecurityToken>';

// Wrap the XML in SoapVar with XSD_ANYXML to insert it raw into the SOAP body
$request = new SoapVar($xml, XSD_ANYXML);

$password = new PasswordType();
$password->_ = '123';  // The actual password text
$password->Type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText';

// Create the username token
$usernameToken = new UsernameTokenType();
$usernameToken->Username = 'username';
$usernameToken->Password = $password;

// Create the security header
$security = new SecurityHeaderType();
$security->UsernameToken = $usernameToken;

// Keep the headers as is
$headers = array(
    new SoapHeader('http://www.w3.org/2005/08/addressing', 'Action', 'http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep', true),
    new SoapHeader('http://www.w3.org/2005/08/addressing', 'MessageID', 'urn:uuid:c186db69-3494-4991-ab18-b800d6f2a3fb'),
    new SoapHeader('http://www.w3.org/2005/08/addressing', 'To', 'https://pki.creatica.org/mswstep/', true),
    new SoapHeader('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd', 'Security', $security, true)
);
/*
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:UsernameToken><o:Username>username</o:Username><o:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">123</o:Password></o:UsernameToken></o:Security>
*/

$soapClient->__setSoapHeaders($headers);
// Set location (keep as is)
if ($non_ssl_port_disabled) {
    $soapClient->__setLocation('https://pki.creatica.org/mswstep/');
} else {
    $soapClient->__setLocation('http://pki.creatica.org/mswstep/');
}

// Make the call using __soapCall with the SoapVar
try {
    $response = $soapClient->__soapCall('RequestSecurityToken', array($request));
    var_dump($response);  // For debugging
} catch (SoapFault $fault) {
    echo "SOAP Fault: " . $fault->getMessage() . "\n";
    echo "Fault Code: " . $fault->faultcode . "\n";
    echo "Fault String: " . $fault->faultstring . "\n";
}

// Log request/response (keep as is)
file_put_contents('/tmp/mswstep-client-request-headers.xml', $soapClient->__getLastRequestHeaders());
file_put_contents('/tmp/mswstep-client-request.xml', $soapClient->__getLastRequest());
file_put_contents('/tmp/mswstep-server-response-headers.xml', $soapClient->__getLastResponseHeaders());
file_put_contents('/tmp/mswstep-server-response.xml', $soapClient->__getLastResponse());