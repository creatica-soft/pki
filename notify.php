<?php
/* This script (when run under some periodic process such as a task or a cronjob)
   will check the certificate expiration date and notify the requester
   via email in advance
   For it to work under php-fpm, which runs under nobody account, add it to group mail and restart the service
*/

require_once 'config.php';
require_once 'helper_functions.php';
require_once 'sql.php';

$clientCertVerify = $_SERVER['CLIENT_CERT_VERIFY'];
switch ($clientCertVerify) {
  case 'SUCCESS':
  break;
  case 'NONE':
    response(401, 'Unauthorized: please use your client SSL certificate for authentication');
  break;
  default: //FAILED:reason
    response(401, 'Unauthorized: SSL authentication with your client certificate failed. Reason: ' . explode(':', $clientCertVerify)[1]);
}

$dn = $_SERVER['SUBJECT_DN'];
$attrs = explode(',', $dn);
foreach ($attrs as $attr) {
  list($type, $value) = explode('=', $attr);
  switch(strtolower($type)) {
    case 'role':
      $role = $value;
    break;
    case 'cn':
      $username = $value;
    break;
  }
}

if (!empty($_REQUEST["email"])) 
	$to = sanitize($_REQUEST["email"]);
else 
	response(400, 'Usage: ' . full_request_uri() . '?email=<email>&expire=<days>');

if (!empty($_REQUEST["expire"])) 
	$expire = sanitize($_REQUEST["expire"]);
else 
	$expire = $cert_expire_notify_days;

$certs = sqlGetCertsToExpire($username, $expire); 

$certificates = '';

if ($certs) {
  foreach($certs as $cert) {
    $willExpire = DateTime::createFromFormat("U", $cert['notAfter']);
    $certificates .= 'sn ' . $cert['serial'] . ', subject ' . $cert['subject'] . ', expire ' . $willExpire->format("YmdHis") . "Z\r\n";  
  }
}

if ($certificates != '') {
  $subject = "Certificate expiration notification";
  $message = <<<EOF
Hello $ou,
please be aware that the following certificates
will expire in less than $expire days:

$certificates

EOF;
	
	$headers = array("From" => "$email", "Reply-To" => "$email", "X-Mailer" => "PHP/" . phpversion());

	if (! mail($to, $subject, $message, $headers)) {
		$err = error_get_last();
            if (!empty($err))
		  response(500, 'mail failed ' . $err['message']);
            else response(500, 'mail failed');
	}
	else response(200, 'Email has been sent to ' . $to);
}
else response(404, 'No certificates will expire in ' . $expire . ' days');

?>
