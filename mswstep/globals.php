<?php
require_once "config.php";
$log_level = LOG_ERR; //options are LOG_ERR, LOG_INFO and LOG_DEBUG
$authentication_enabled = true;
$default_username = 'username'; //for testing when authentication_enabled is false
$non_ssl_port_disabled = true; //set to false for connecting to non-SSL port for testing only!
$signed_data_version = 3; //in MS examples it is 3 but probably should be 4
$wstep_path = '/mswstep/';
$content_type = 'application/soap+xml; charset=utf-8';
//if allow_user_supplied_emails_in_san is false, then only AD mail attribute is used in SAN for SMIME cert (Email template)
//true value is probably safe because even if a user will use somebody else email, they won't be able to send on behalf of that email
//true value allows people to use one cert for multiple email accounts, not just the one listed in AD mail attribute
//on the other hand, it can't be verified that user supplied emails belong to that user
//lastly, even if it is false, people can still use GenericUser template to request SMIME cert with any emails
//or even use other PKI protocols such as CMP to do the same
$allow_user_supplied_emails_in_san = true;

