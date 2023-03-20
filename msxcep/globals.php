<?php
require_once "config.php";
$log_level = LOG_ERR; //options are LOG_ERR, LOG_INFO and LOG_DEBUG
$non_ssl_port_disabled = true; //set to false for connecting to non-SSL port for testing with client.php (MS Certificates MMC will not work!)
$xcep_path = '/msxcep/';
$wstep_path = '/mswstep/';
$msxcep_action = 'http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies';
$content_type = 'application/soap+xml; charset=utf-8';
$policy_id = '{b7bf7cea-1991-42c2-8c4f-e222ee159701}';
$policy_friendly_name = 'PKI Certificate Enrollment Policy'; //this is a single name for all the policies!
$policy_next_update_hours = 24; //could be null
$policies_last_update = '2022-12-08T06:50:00'; //last time the policy got updated
//an individual policy (you may call it a sub-policy if you wish) corresponds to a certificate template
//each sub-policy feature is represented as an array element; array element 0 correspond to sub-policy with the index 0
//array element 1 - to sub-policy with the index 1, etc
//to add a new policy, simply add an array member!

//the template's attribute msPKI-Cert-Template-OID is referenced by policyOIDReference
$policy_oids = ['1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858498',
                '1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858497',          
                '1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858499'];
$policy_names = ['GenericUser', 'Email', 'GenericComputer']; //these are certificate template names visible in MS Certificate MMC
                                                    //populated from the registry key itself
                                                    //Certificate Templates can be found in Windows registry under 
        //HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache for User and under
        //HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache for Computer

$policy_schemas = [1, 1, 1]; //should be 1, 2 or 3; populated from msPKI-Template-Schema-Version certificate template attribute
                          //a set of cryptoproviders depends on this number, for 1 and 2 (won't work!) only legacy providers are allowed!
$enroll = [true, true, true]; //policy enrollment permission
$auto_enroll = [false, true, true]; //policy auto_enrollment permission
$certificate_validity_days = [730, 730, 730];
$key_spec = [1, 1, 1]; //populated from KeySpec attribute: 1 - Encryption (Exchange in MS Certificates MMC), 2 - Signature
$minimum_key_size = [2048, 2048, 2048];
/*
  keyUsage is binary 2-byte number where bits from most significant to least significant are:
  15 - digitalSignature
  14 - nonRepudiation
  13 - keyEncipherment
  12 - dataEncipherment
  11 - keyAgreement
  10 - keyCertSign
  9 - crlSign
  8 - encipherOnly
  7 - decipherOnly
  6 - 0 - padding 0 bits
*/
$key_usage = [0b1010000000000000, 0b1110000000000000, 0b1010000000000000]; //populated from keyUsage attribute, must add keyUsage extension!
$private_key_permissions = [null, null, null]; //['O:COG:CGD:(A;;GASDWOKA;;;CO)', 'O:COG:CGD:(A;;GASDWOKA;;;CO)', 'O:COG:CGD:(A;;GASDWOKA;;;CO)']; //custom private key permission in SDDL; see https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
$pk_algorithm_oid = ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.1', '1.2.840.113549.1.1.1']; //for private keys, such as '1.2.840.113549.1.1.1' (rsaEncryption - to be recognized it must be called "RSA" in oid->defaultName - so crappy!), etc.
$pk_algorithm_name = ['RSA', 'RSA', 'RSA'];
$hash_algorithm_oid = ['2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.1']; //hashing algorithm oids, i.e. '1.3.14.3.2.26' (sha1), '2.16.840.1.101.3.4.2.1' (sha256), etc
$hash_algorithm_name = ['sha256', 'sha256', 'sha256'];

//populated from SupportedCSPs
$crypto_providers = [['Microsoft Enhanced RSA and AES Cryptographic Provider'],
                     ['Microsoft Enhanced RSA and AES Cryptographic Provider'],
                     ['Microsoft Enhanced RSA and AES Cryptographic Provider']];
/*
//this provider is only allowed with schema version 3 but will fail with permissions denied error when creating CSR!
$crypto_providers = [['Microsoft Software Key Storage Provider'],
                     ['Microsoft Software Key Storage Provider'],
                     ['Microsoft Software Key Storage Provider']];                     
*/
$major_revision = [1, 1, 1]; //populated from the <revision> attribute
$minor_revision = [0, 0, 0]; //populated from the <msPKI-Template-Minor-Revision> attribute
/*
  The server SHOULD only return CertificateEnrollmentPolicy objects whose bitwise AND of the <privateKeyFlags> element of the <attributes> element with 0x0F000000 is smaller than or equal to 0x0Z000000, where Z denotes the value of the clientVersion, MS Certificates MMC currently sends 6

  The server SHOULD only return the CertificateEnrollmentPolicy objects whose bitwise AND of the <privateKeyFlags> element of the <attributes> element with 0x000F0000 is smaller than or equal to 0x000Y0000, where Y denotes the value of the serverVersion - client always sends it as 0, I suppose it has no idea of the serverVersion

   0x00000001 Instructs the client to archive the private key.
   0x00000010 Instructs the client to allow the private key to be exported.
   0x00000020 Instructs the client to protect the private key.
*/
$private_key_flags = [0x10, 0x10, 0x10]; //populated from msPKI-Private-Key-Flag attribute, one of the above
/*
        0x00000001 The client supplies the Subject field value in the certificate request.
        0x00010000 The client supplies the Subject Alternative Name field value in the certificate request.
        0x00400000 The certificate authority (CA) adds the value of the DNS of the root domain (the domain where the user's object resides in Active Directory) to the Subject Alternative Name extension of the issued certificate.
        0x00800000 The CA adds the value of the userPrincipalName attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
        0x01000000 The CA adds the value of the objectGUID attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
        0x02000000 The CA adds the value of the userPrincipalName attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
        0x04000000 The CA adds the value of the mail attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
        0x08000000 The CA adds the value obtained from the dNSHostName attribute of the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
        0x10000000 The CA adds the value obtained from the dNSHostName attribute of the requestor's user object in Active Directory as the CN in the Subject extension of the issued certificate.
        0x20000000 The CA adds the value of the mail attribute from the requestor's user object in Active Directory as the Subject extension of the issued certificate.
        0x40000000 The CA sets the Subject Name to the cn attribute value of the requestor's user object in Active Directory.
        0x80000000 The CA sets the Subject Name to the distinguishedName attribute value of the requestor's user object in Active Directory.
        0x00000008 The client reuses the values of the Subject Name and Subject Alternative Name extensions from an existing, valid certificate when creating a renewal certificate request. This flag can only be used when the SubjectNameEnrolleeSupplies (0x00000001) or SubjectAlternativeNameEnrolleeSupplies (0x00010000) flag is specified.
*/
$subject_name_flags = [0x9, 0x8, 0x9]; //populated from msPKI-Certificate-Name-Flag attribute, one of the above
/*
        0x00000001 Instructs the client and CA to include an S/MIME extension, as specified in [RFC4262].
        0x00000008 Instructs the CA to append the issued certificate to the userCertificate attribute, on the user object in Active Directory.
        0x00000010 Instructs the CA to check the user's userCertificate attribute in Active Directory, as specified in [RFC4523], for valid certificates that match the template enrolled for.
        0x00000040 This flag instructs clients to sign the renewal request using the private key of the existing certificate. For more information, see [MS-WCCE] section 3.2.2.6.2.1.4.5.6. This flag also instructs the CA to process the renewal requests as specified in [MS-WCCE] section 3.2.2.6.2.1.4.5.6.
        0x00000100 Instructs the client to get a user's consent before attempting to enroll for a certificate based on the specified template.
        0x00000400 Instructs the client to delete any expired, revoked, or renewed certificate from the user's certificate stores.
        0x00002000 This flag instructs the client to reuse the private key for a smart card–based certificate renewal if it is unable to create a new private key on the card.
*/
$enrollment_flags = [null, 0x1, null]; //populated from msPKI-Enrollment-Flag attribute, one of the above
/*
        0x00000040 GeneralMachineType This certificate template is for an end entity that represents a machine.
        0x00000080 GeneralCA A certificate request for a CA certificate.
        0x00000800 GeneralCrossCA A certificate request for cross-certifying a certificate.
*/
$general_flags = [null, null, 0x40]; //populated from Flags attribute, one of the above

$extended_key_usages = [['TLS Web Server Authentication', 'TLS Web Client Authentication'], 
                        ['E-mail Protection'],
                        ['TLS Web Server Authentication', 'TLS Web Client Authentication']];

//Each CA may have multiple URIs with its priority, renewal_only, enroll_permissions, and auth but the cert is one per CA!
$ca_uri = [["$base_url$wstep_path"]];
$ca_priority = [[1]];
$ca_renewal_only = [[false]];
$ca_enroll_permission = [[true]];
/*
1 Anonymous Authentication - only supported for renewals!
2 Transport Kerberos Authentication
4 Message Username and Password Authentication
8 Message X.509 Certificate Authentication
*/
$ca_auth = [[4]];
$ca_cert1 = file_get_contents($signing_ca_der_path);
$ca_cert = [$ca_cert1];

?>
