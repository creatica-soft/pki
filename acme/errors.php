<?php
/*
   | accountDoesNotExist     | The request specified an account that   |
   |                         | does not exist                          |
   |                         |                                         |
   | alreadyRevoked          | The request specified a certificate to  |
   |                         | be revoked that has already been        |
   |                         | revoked                                 |
   |                         |                                         |
   | badCSR                  | The CSR is unacceptable (e.g., due to a |
   |                         | short key)                              |
   |                         |                                         |
   | badNonce                | The client sent an unacceptable anti-   |
   |                         | replay nonce                            |
   |                         |                                         |
   | badPublicKey            | The JWS was signed by a public key the  |
   |                         | server does not support                 |
   |                         |                                         |
   | badRevocationReason     | The revocation reason provided is not   |
   |                         | allowed by the server                   |
   |                         |                                         |
   | badSignatureAlgorithm   | The JWS was signed with an algorithm    |
   |                         | the server does not support             |
   |                         |                                         |
   | caa                     | Certification Authority Authorization   |
   |                         | (CAA) records forbid the CA from        |
   |                         | issuing a certificate                   |
   |                         |                                         |
   | compound                | Specific error conditions are indicated |
   |                         | in the "subproblems" array              |
   |                         |                                         |
   | connection              | The server could not connect to         |
   |                         | validation target                       |
   |                         |                                         |
   | dns                     | There was a problem with a DNS query    |
   |                         | during identifier validation            |
   |                         |                                         |
   | externalAccountRequired | The request must include a value for    |
   |                         | the "externalAccountBinding" field      |
   |                         |                                         |
   | incorrectResponse       | Response received didn't match the      |
   |                         | challenge's requirements                |
   |                         |                                         |
   | invalidContact          | A contact URL for an account was        |
   |                         | invalid                                 |
   |                         |                                         |
   | malformed               | The request message was malformed       |
   |                         |                                         |
   | orderNotReady           | The request attempted to finalize an    |
   |                         | order that is not ready to be finalized |
   |                         |                                         |
   | rateLimited             | The request exceeds a rate limit        |
   |                         |                                         |
   | rejectedIdentifier      | The server will not issue certificates  |
   |                         | for the identifier                      |
   |                         |                                         |
   | serverInternal          | The server experienced an internal      |
   |                         | error                                   |
   |                         |                                         |
   | tls                     | The server received a TLS error during  |
   |                         | validation                              |
   |                         |                                         |
   | unauthorized            | The client lacks sufficient             |
   |                         | authorization                           |
   |                         |                                         |
   | unsupportedContact      | A contact URL for an account used an    |
   |                         | unsupported protocol scheme             |
   |                         |                                         |
   | unsupportedIdentifier   | An identifier is of an unsupported type |
   |                         |                                         |
   | userActionRequired      | Visit the "instance" URL and take       |
   |                         | actions specified there                 |
*/
