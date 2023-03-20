<?php

require_once('globals.php');
require_once('helper_functions.php');

if (isset($_REQUEST["cn"]) && !empty($_REQUEST["cn"])) 
	$cn = sanitize($_REQUEST["cn"]);

if (!empty($cn)) { 
	if (check_cn($cn)) response(200, "CN $cn is valid");
	else response(400, "CN $cn is invalid");
} 
else {
	$allowed_domains = fopen($domains_file, "r");
	if (! $allowed_domains)
		response(500, $domains_file . ' not found');

    while (! feof($allowed_domains)) {
		$domain = trim(fgets($allowed_domains));
		if ($domain == '') continue;
		if ($domain[0] == '#') continue;
		$domains[] = $domain; 
	}
	fclose($allowed_domains);
}

if (empty($domains))
	response(404, 'No domains have been found');
else {
	$result = array('status' => 200, 'detail' => 'Allowed domains');
	header('Content-type: application/json', true, 200);
	echo json_encode(array($result, $domains), JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
}

?>
