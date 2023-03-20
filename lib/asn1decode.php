<?php

require_once 'asn1_types.php';

// returns an array of  ASN.1 class, constructed, type, hl, length and value keys and their values
function asn1decode($binary_string) {
  $offset = 0;
  $size = strlen($binary_string);

  if ($size >= 2) { //asn.1 header length is at least 2
    $hl = 2; //header length - at least 2, incremented below if length field is more than one
    $octet = ord($binary_string[$offset++]);
    $class = $octet >> 6; //asn.1 object class
    $constructed = ($octet & 32) >> 5; // boolean var indicating whether the object is primitive or constructed
                                       // When underlying type is context-specific, then setting constructed bit do not 
                                       // mask the encoded data type regardless of the later being primitive or constructed
                                       // In opposite, when the context-specific type does not set constructed bit, then
                                       // it will mask the enclosed primitive data type, hence you would need to apply
                                       // external knowledge (hence the name "context-specific") in order to properly decode it
    $type = $octet & 31; //asn.1 object type
    if ($type == 31) { //multi-byte identifier octets follow
      $type_part = 0;
      while ($octet >= 128) { // if 8th (msb) bit set, then more octets will follow, strip it and continue
        $type_part <<= 7;
        $type_part |= ($octet & 127);
        $octet = ord($binary_string[$offset++]);
        if ($hl == 2 && (($octet & 127) == 0))
          throw new Exception("asn1decode() error: first subsequent type octet is 0");
        $hl++;
      }
      $type_part <<= 7;
      $type = $type_part | ($octet & 127);
    }
    $octet = ord($binary_string[$offset++]);
    if ($octet >= 128) { //case of multibyte length
      if ($octet == 255)
        throw new Exception("asn1decode() error: Initial length octet is 255");
      $octet_number = $octet & 7;
      $length = 0; // covers the case of indefinite content length ($octet = 128) terminated by end-of-content octets (two zeros)
      for ($i = 0; $i < $octet_number; $i++) {
        $octet = ord($binary_string[$offset++]);
        if ($i == 0 && $octet == 0)
          throw new Exception("asn1decode() error: first subsequent length octet is 0");
        $length <<= 8;
        $length |= $octet;
        $hl++;
      }
    } else $length = $octet;

    if ($offset + $length > $size)
      throw new Exception("asn1decode() error: field length ($length) from offset $offset exceeds the overall ASN.1 data size ($size)");
    $value = substr($binary_string, $offset, $length);
    if (! $constructed) {
      if ($class != 2)
        $value = decode($type, $value);
    }
    return ['class' => $class, 'constructed' => $constructed, 'type' => $type, 'hl' => $hl, 'length' => $length, 'value' => $value];
  }
  return false;
}

//decodes primitive ASN.1 types
function decode($type, $binary_string) {
  $offset = 0;
  $length = strlen($binary_string);
  //switch for decoding data from various primitive object types
  switch ($type) {
    case BOOLEAN: // in DER TRUE value should be 0xFF, not just > 0
      $value = ord($binary_string[0]) > 0 ? 'TRUE' : 'FALSE';
    break;
    case INTEGER: //two's complement binary number; another words, signed integer;
      $value = 0;
      for ($i = 0; $i < $length; $i++) {
        $value = gmp_mul($value, 256);
        $value = gmp_add($value, ord($binary_string[$i]));
      }
      $value = gmp_strval($value, 10);
    break;
    case BIT_STRING: //may be primitive or constructed. First octet encodes the number of unused bits in the last octet
      $unused_bits = ord($binary_string[0]);
      if ($unused_bits > 7)
        throw new Exception("decode() error: first octet of BIT_STRING (unused bits in last octet) is greater than 7");
      $value = bin2hex(substr($binary_string, 1));
    break;
    case OCTET_STRING:
      $value = bin2hex($binary_string);
    break;
    case PRINTABLE_STRING:
      $value = "";
      for ($i = 0; $i < $length; $i++) {
        if (! preg_match('/[a-zA-Z0-9\'\=\(\)\+\,\-\.\/\:\?\ ]/', $binary_string[$i]))
          throw new Exception("decode() error: PRINTABLE_STRING contains an illegal char " . $binary_string[$i]);
        $value .= $binary_string[$i];
      }
    break;
    case IA5_STRING:
      $value = $binary_string;
    break;
    case UTF8_STRING:
      $value = utf8_decode($binary_string);
    break;
    case BMP_STRING:
      $value = mb_convert_encoding($binary_string, 'ASCII', 'UNICODE');
    break;
    case GENERALIZED_TIME: //YYYYMMDDhhmmss.fffZ
      $value = $binary_string;
    break;
    case UTC_TIME: //YYMMDDhhmmssZ
      $value = $binary_string;
    break;
    case OBJECT_IDENTIFIER: //use 128-base encoding, another word, 7-bit one
      $octet = ord($binary_string[$offset++]);
      // first two nodes in oid are encoded differently: X * 40 + Y, where X is the first node {0-2} and Y is the second
      // subsequent nodes for X in {0-1} are from 1 to 39, for X = 2, Y can be larger than 39.
      $value = (int)($octet / 40) . ".";
      if ($value > 2) {
        $value .= ($octet % 80);
      } else $value .= ($octet % 40);
      $iter = 1;
      while ($iter < $length) { //loop for all remaining nodes in oid
        $oid_part = 0;
        $octet = ord($binary_string[$offset++]);
        if ($octet == 128)
          throw new Exception("decode() error: the leading octet of OID should not be 0x80");
        $iter++;
        //loop for a single large oid node
        while ($octet >= 128) { // if 8th (msb) bit set, then more octets will follow, strip it and continue
          $oid_part <<= 7;
          $oid_part |= ($octet & 127);
          $octet = ord($binary_string[$offset++]);
          $iter++;
        }
        //last octet in oid does not have 8th bit set
        if ($oid_part != 0) {
          $oid_part <<= 7;
          $oid_part |= $octet;
          $value .= "." . $oid_part;
        } else {
          $value .= "." . $octet;
        }
      }
    break;
    case NULL_VALUE:
      if ($length > 0)
        throw new Exception("decode() error: NULL value has length greater than 0");
      $value = "";
    break;
    case ENUMERATED:
      $value = 0;
      for ($i = 0; $i < $length; $i++) {
        $value <<= 1;
        $value |= ord($binary_string[$i]);
      }
    break;
    case OBJECT_DESCRIPTOR:
      throw new Exception("decode() error: OBJECT_DESCRIPTOR encoding is not implemented");
    break;
    case REAL:
      throw new Exception("decode() error: real number encoding is not implemented");
    break;
    case RELATIVE_OID:
      throw new Exception("decode() error: RELATIVE_OID encoding is not implemented");
    break;
    case TIME_STRING:
      throw new Exception("decode() error: TIME_STRING encoding is not implemented");
    break;
    case NUMERIC_STRING:
      throw new Exception("decode() error: NUMERIC_STRING encoding is not implemented");
    break;
    case T61_STRING:
      throw new Exception("decode() error: T61_STRING encoding is not implemented");
    break;
    case VIDEOTEXT_STRING:
      throw new Exception("decode() error: VIDEOTEXT_STRING encoding is not implemented");
    break;
    case GRAPHIC_STRING:
      throw new Exception("decode() error: GRAPHIC_STRING encoding is not implemented");
    break;
    case VISIBLE_STRING:
      throw new Exception("decode() error: VISIBLE_STRING encoding is not implemented");
    break;
    case GENERAL_STRING:
      throw new Exception("decode() error: GENERAL_STRING encoding is not implemented");
    break;
/*
The character string type UniversalString supports any of the
   characters allowed by [ISO10646].  ISO 10646 is the Universal
   multiple-octet coded Character Set (UCS).
*/
    case UNIVERSAL_STRING:
      throw new Exception("decode() error: UNIVERSAL_STRING encoding is not implemented");
    break;
    case DATE:
      throw new Exception("decode() error: DATE encoding is not implemented");
    break;
    case TIME_OF_DAY:
      throw new Exception("decode() error: TIME_OF_DAY encoding is not implemented");
    break;
    case DATE_TIME:
      throw new Exception("decode() error: DATE_TIME encoding is not implemented");
    break;
    case DURATION:
      throw new Exception("decode() error: DURATION encoding is not implemented");
    break;
    case OID_IRI:
      throw new Exception("decode() error: OID_IRI encoding is not implemented");
    break;
    case RELATIVE_OID_IRI:
      throw new Exception("decode() error: RELATIVE_OID_IRI encoding is not implemented");
    break;
    default:
      throw new Exception("decode() error: unknown ASN.1 type $type");
  }  
  return $value;
}
