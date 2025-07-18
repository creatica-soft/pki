<?php

require_once 'asn1_types.php';
require_once 'helper_functions.php';
require_once 'asn1decode.php';

function asn1parse($binary_string, $offset = 0, $size = null) {
  $octet_array = str_split(bin2hex($binary_string), 2);

  $depth = 0; //depth of asn.1 objects inside the asn.1 structure
  $prev_constructed = false; //this var is used for incrementing the $depth if the previous object was constructed as oppose to primitive
  $asn_objects = array(); //this is a map of offset key => depth value for setting the correct depth at certain offset
  $offset_depth = array(); //this is a map of offset key => depth value for setting the correct depth at certain offset

  if (is_null($size))
    $size = count($octet_array);
  else $size += $offset;

  //main loop iterating over asn.1 structure
  while ($offset <= $size - 2) { //asn.1 header length is at least 2 bytes, hence "- 2"
    $indent = "";
    $hl = 2; //header length - at least 2, incremented below if length field is more than one
    $cur_offset = $offset; //asn.1 object offset
    $octet = hexdec($octet_array[$offset++]);
    $class = $octet >> 6; //asn.1 object class
    $constructed = ($octet & 32) >> 5; //boolean var indicating whether the object is primitive or constructed
    $type = $octet & 31; //asn.1 object type
    if ($type == 31) { //multi-byte identifier octets follow
      $type_part = 0;
      while ($octet >= 128) { // if 8th (msb) bit set, then more octets will follow, strip it and continue
        $type_part <<= 7;
        $type_part |= ($octet & 127);
        $octet = hexdec($octet_array[$offset++]);
        if ($hl == 2 && (($octet & 127) == 0)) throw new Exception("First subsequent type octet is 0");
        $hl++;
      }
      $type_part <<= 7;
      $type = $type_part | ($octet & 127);
    }
    $octet = hexdec($octet_array[$offset++]); //asn.1 object length
    if ($octet >= 128) { //case of multibyte length
      if ($octet == 255) throw new Exception("Initial length octet is 255");
      $octet_number = $octet & 7;
      $length = 0; // covers the case of indefinite content length ($octet = 128) terminated by end-of-content octets (two zeros)
      for ($i = 0; $i < $octet_number; $i++) {
        $octet = hexdec($octet_array[$offset++]);
        if ($i == 0 && $octet == 0) throw new Exception("First subsequent length octet is 0");
        $length <<= 8;
        $length |= $octet;
        $hl++;
      }
    } else $length = $octet;

    if ($offset + $length > $size) 
      throw new Exception("asn1parse() error: field length ($length) from offset $offset exceeds the overall ASN.1 data size ($size)");

    //code block to set the correct an asn.1 object depth and current object index at this depth
    if (array_key_exists($cur_offset, $offset_depth)) {
      $depth = $offset_depth[$cur_offset];
    } else {
      if ($prev_constructed) $depth++;
    }
 
    //object at offset = ($cur_offset + $length + $hl) should start at the same depth as this one
    //deeper objects may end up at the same offset but the depth is set by the first object that ends there
    $key = $cur_offset + $length + $hl;
    if (! array_key_exists($key, $offset_depth)) {
      $offset_depth[$key] = $depth;
    }

    if ($constructed)
      $prev_constructed = true;
    else $prev_constructed = false;

    if ($constructed) {
      $indent = str_pad($indent, $depth);
      if ($class == 2) { //context-specific tag for choice
          $type = "cont [ $type ]";
          printf("%4d:d=%2d hl=%d l=%4d %s: %s%s\n", $cur_offset, $depth, $hl, $length, "cons", $indent, $type);
      } else {
        printf("%4d:d=%2d hl=%d l=%4d %s: %s%s\n", $cur_offset, $depth, $hl, $length, "cons", $indent, type2str($type));
      }
      continue; //continue the main loop because the object is constructed (i.e. data is kept in primitive objects)
    }

    $value = '';
    for ($i = 0; $i < $length; $i++)
      $value .= $octet_array[$offset++];

    if ($class == 2) {
      $indent = str_pad($indent, $depth);
      $type = "cont [ $type ]";
      printf("%4d:d=%2d hl=%d l=%4d %s: %s%s\t:%-s\n", $cur_offset, $depth, $hl, $length, "prim", $indent, $type, $value);
      continue;
    }
    
    $value = decode($type, hex2bin($value), $cmp = false);
    
    $indent = str_pad($indent, $depth);
    printf("%4d:d=%2d hl=%d l=%4d %s: %s%s\t:%-s\n", $cur_offset, $depth, $hl, $length, $constructed ? "cons" : "prim", $indent, type2str($type), $value);
  }
}

//$argv[1] is DER or PEM encoded file
if ($argc < 2) {
  print "Usage: php8 asn1parse.php <file.[pem|der]> [pem]\n";
  exit(1);
}

$asn1data = file_get_contents($argv[1]);
if (key_exists(2, $argv) && $argv[2] == 'pem') {
  $asn1data = pem2der($asn1data);
  if (! $asn1data) {
    print "pem2der() returned false\n";
    exit(1);
  }
}

asn1parse($asn1data);

