<?php

require_once 'asn1_types.php';

function asn1encode($class, $constructed, $type, $value) {
  if (! is_int($class) || $class < 0 || $class > 3)
    throw new Exception("asn1encode() error: asn.1 value class must be between 0 and 3 inclusive");
  if (! is_int($type) || ($class == 0 && $type <= 0))
    throw new Exception("asn1encode() error: asn.1 value type must be a positive integer");
  if (! is_int($type) || ($class == 2 && $type < 0))
    throw new Exception("asn1encode() error: asn.1 value context-specific type must be non-negative integer");

  $binary = "";

  $tag = ($class << 6); //asn.1 object class takes bits 7 and 8 in the tag
  if ($constructed)
    $tag |= 32; //boolean var indicating whether the object is primitive or constructed takes bit 6
  
  $type_size = intdiv($type, 31);
  if ($type_size > 0) { // $type value >= 31, meaning it needs to be encoded as multi-byte
    $tag |= 31; //first 5 bits in tag octet must be 31
    $bin_type = str_split(decbin($type), 7);
    $bin_type_last_idx = count($bin_type) - 1;
    foreach ($bin_type as $key => $val) {
      if ($key != $bin_type_last_idx) {
        $tag <<= 8;
        $tag |= (128 | bindec($val));
      } else {
        $tag <<= 8;
        $tag |= bindec($val);        
      }
    }
    $binary .= chr($tag);
  } else {
    $tag |= $type;
    $binary .= chr($tag);
  }

  if (! $constructed) {
    if ($class == 0)
      $value = encode($type, $value);
  }
  $length = strlen($value);

  if ($length >= 128) {
    $length_octet_num = 0;
    $v = "";
    while ($length > 0) {
      $v = chr($length & 255) . $v;
      $length >>= 8;
      $length_octet_num++;
    }
    if ($length_octet_num > 7)
      throw new Exception("asn1encode() error: number of value length octets must be less than 8");
    $length_octets = chr(128 | $length_octet_num);
    $length_octets .= $v;
  } else $length_octets = chr($length);
   
  $binary .= ($length_octets . $value);
  
  return $binary;
}

function encode($type, $value) {
  //switch for encoding data for various primitive object types
  switch ($type) {
    case BOOLEAN: // in DER TRUE value should be 0xFF, not just > 0
      if ($value == 'TRUE') $value = chr(255);
      else $value = chr(0);
    break;
    case INTEGER: //two's complement binary number; another words, signed integer; this could be very large int, 
                  //up to 20 bytes for serial numbers and even more for enc/sign keys! 
                  //hence, they coudn't be native int types and gmp should be employed
                  //keys (and serials) should be treated as unsigned integers though, so prefixing with '00'H is needed but tricky
      if ($value != 0) {
        $value = gmp_init($value, 10);
        $value = gmp_export($value); //gmp_export() strips the sign as in gmp_abs(); this is a problem because pki cmp integers are unsigned
        if ($value[0] > chr(127)) $value = chr(0) . $value; //terrible hack perhaps
      } else $value = chr(0);
    break;
/*
   Named bit lists are BIT STRINGs where the values have been assigned
   names.  This specification makes use of named bit lists in the
   definitions for the key usage, CRL distribution points, and freshest
   CRL certificate extensions, as well as the freshest CRL and issuing
   distribution point CRL extensions.  When DER encoding a named bit
   list, trailing zeros MUST be omitted.  That is, the encoded value
 ends with the last named bit that is set to one.
*/
    case BIT_STRING: //may be primitive or constructed. First octet encodes the number of unused bits in the last octet
      $value = hex2bin($value);
    break;
    case OCTET_STRING:
      $value = hex2bin($value);
    break;
/*  
   The character string type PrintableString supports a very basic Latin
   character set: the lowercase letters 'a' through 'z', uppercase
   letters 'A' through 'Z', the digits '0' through '9', eleven special
   characters ' = ( ) + , - . / : ? and space.

   Implementers should note that the at sign ('@') and underscore ('_')
   characters are not supported by the ASN.1 type PrintableString.
   These characters often appear in Internet addresses.  Such addresses
   MUST be encoded using an ASN.1 type that supports them.  They are
   usually encoded as IA5String in either the emailAddress attribute
   within a distinguished name or the rfc822Name field of GeneralName.
   Conforming implementations MUST NOT encode strings that include
   either the at sign or underscore character as PrintableString.
   
   The character string type TeletexString is a superset of
   PrintableString.  TeletexString supports a fairly standard (ASCII-
   like) Latin character set: Latin characters with non-spacing accents
   and Japanese characters.
*/
    case PRINTABLE_STRING:
      $len = strlen($value);
      for ($i = 0; $i < $len; $i++) {
        if (! preg_match('/[a-zA-Z0-9\'\=\(\)\+\,\-\.\/\:\?\ ]/', $value[$i]))
          throw new Exception("encode() error: PRINTABLE_STRING contains an illegal char " . $value[$i]);
      }
    break;
    case IA5_STRING:
    break;
    case UTF8_STRING: //rfc3629
      $value = utf8_encode($value);
    break;
/*
BMPString is the subtype of UniversalString and models the Basic Multilingual Plane of ISO/IEC 10646
The Basic Multilingual Plane (BMP) is a character encoding that encompasses the first plane of the Universal Character Set (UCS). 
There are seventeen planes numbered 0 to 16. BMP occupies plane 0 and includes 65,536 code points from 0x0000 to 0xFFFF. 
This is the section of the Unicode character map where most of the characters assignments have so far been made. 
It includes Latin, Middle Eastern, Asian, African, and other languages.

PHP mbstring encoding UCS-2, I guess
*/
    case BMP_STRING:
      $value = mb_convert_encoding($value, 'UNICODE', 'ASCII');
    break;
    case GENERALIZED_TIME: //YYYYMMDDhhmmss.fffZ
    break;
    case UTC_TIME: //YYMMDDhhmmssZ
    break;
/*
   Object Identifiers (OIDs) are used throughout this specification to
   identify certificate policies, public key and signature algorithms,
   certificate extensions, etc.  There is no maximum size for OIDs.
   This specification mandates support for OIDs that have arc elements
   with values that are less than 2^28, that is, they MUST be between 0
   and 268,435,455, inclusive.  This allows each arc element to be
   represented within a single 32-bit word.  Implementations MUST also
   support OIDs where the length of the dotted decimal (see Section 1.4
   of [RFC4512]) string representation can be up to 100 bytes
   (inclusive).  Implementations MUST be able to handle OIDs with up to
   20 elements (inclusive).  CAs SHOULD NOT issue certificates that
   contain OIDs that exceed these requirements.  Likewise, CRL issuers
   SHOULD NOT issue CRLs that contain OIDs that exceed these
   requirements.
*/
    case OBJECT_IDENTIFIER: //use 128-base encoding, another word, 7-bit one
      $value = explode('.', $value);  
      $val = array();      
      $val[0] = chr($value[0] * 40 + $value[1]);
      $i = 0;
      foreach($value as $v) {
        if ($i++ < 2) continue;
        $part = "";
        $iter = 0;
        while ($v > 0) {
          if ($iter++ == 0) {
            $part = chr($v & 127);
            $v >>= 7;
            continue;
          }
          $part = chr(($v & 127) | 128) . $part;
          $v >>= 7;
        }
        if ($part == "") $val[$i - 1] = chr(0); 
        else $val[$i - 1] = $part;
      }
      $value = implode('', $val);
    break;
    case NULL_VALUE:
      $value = "";
    break;
    case ENUMERATED:
      $value = chr($value);
    break;
    case OBJECT_DESCRIPTOR:
      throw new Exception("encode() error: OBJECT_DESCRIPTOR encoding is not implemented");
    break;
    case REAL:
      throw new Exception("encode() error: real number encoding is not implemented");
    break;
    case RELATIVE_OID:
      throw new Exception("encode() error: RELATIVE_OID encoding is not implemented");
    break;
    case TIME_STRING:
      throw new Exception("encode() error: TIME_STRING encoding is not implemented");
    break;
    case NUMERIC_STRING:
      throw new Exception("encode() error: NUMERIC_STRING encoding is not implemented");
    break;
    case T61_STRING:
      throw new Exception("encode() error: T61_STRING encoding is not implemented");
    break;
    case VIDEOTEXT_STRING:
      throw new Exception("encode() error: VIDEOTEXT_STRING encoding is not implemented");
    break;
    case GRAPHIC_STRING:
      throw new Exception("encode() error: GRAPHIC_STRING encoding is not implemented");
    break;
    case VISIBLE_STRING:
      throw new Exception("encode() error: VISIBLE_STRING encoding is not implemented");
    break;
    case GENERAL_STRING:
      throw new Exception("encode() error: GENERAL_STRING encoding is not implemented");
    break;
/*
The character string type UniversalString supports any of the
   characters allowed by [ISO10646].  ISO 10646 is the Universal
   multiple-octet coded Character Set (UCS).
*/
    case UNIVERSAL_STRING:
      throw new Exception("encode() error: UNIVERSAL_STRING encoding is not implemented");
    break;
    case DATE:
      throw new Exception("encode() error: DATE encoding is not implemented");
    break;
    case TIME_OF_DAY:
      throw new Exception("encode() error: TIME_OF_DAY encoding is not implemented");
    break;
    case DATE_TIME:
      throw new Exception("encode() error: DATE_TIME encoding is not implemented");
    break;
    case DURATION:
      throw new Exception("encode() error: DURATION encoding is not implemented");
    break;
    case OID_IRI:
      throw new Exception("encode() error: OID_IRI encoding is not implemented");
    break;
    case RELATIVE_OID_IRI:
      throw new Exception("encode() error: RELATIVE_OID_IRI encoding is not implemented");
    break;
    default:
      throw new Exception("encode() error: unknown ASN.1 type $type");
  }
  return $value;
}
