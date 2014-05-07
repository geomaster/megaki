<?php

define('PEGASUS_REQ_START', 0x01);
define('PEGASUS_REQ_QUIT', 0x02);
define('PEGASUS_REQ_HANDLE', 0x03);

define('PEGASUS_RESP_START_OK', 0x01);
define('PEGASUS_RESP_START_FAIL', 0x02);
define('PEGASUS_RESP_QUIT_OK', 0x03);
define('PEGASUS_RESP_HANDLE_OK', 0x04);
define('PEGASUS_RESP_HANDLE_FAIL', 0x05);

define('PEGASUS_GUID_BYTES', 8);
define('PEGASUS_GUID_FMT', 'C' . PEGASUS_GUID_BYTES);

define('MEGAKI_TOKEN_BYTES', 16);
define('MEGAKI_TOKEN_FMT', 'C' . MEGAKI_TOKEN_BYTES);

/* Arcangelo superglobals */
class arca {
  static $guid;
  static $client_ip;
  static $client_port;
  static $token;
}

class __arca {
  static function get($bytes) {
    return fread(STDIN, $bytes);
  }

  static function put($data) {
    return fwrite(STDOUT, $data);
  }
};

arca::$guid = str_repeat('0', PEGASUS_GUID_BYTES);
arca::$client_ip = "255.255.255.255";
arca::$client_port = "65536";
arca::$token = str_repeat('A', MEGAKI_TOKEN_BYTES);

while(1) {
  $type = unpack("Ctype", __arca::get(1))["type"];
  if ($type != PEGASUS_REQ_START) {
    /* error! */
    fprintf(STDERR, "I am dead %d\n");
    die();
  }

  $str = __arca::get(PEGASUS_GUID_BYTES + 4); 
  $startreq = unpack(PEGASUS_GUID_FMT . "guid/Ldatasize", $str);
  $data = unpack(
    "Sfamily/nport/C4ip/C8zero/".MEGAKI_TOKEN_FMT."token",
    __arca::get($startreq["datasize"]));

  for ($i = 1; $i <= PEGASUS_GUID_BYTES; ++$i)
    arca::$guid[$i - 1] = $startreq["guid" . $i];

  for ($i = 1; $i <= MEGAKI_TOKEN_BYTES; ++$i)
    arca::$token[$i - 1] = $data["token" . $i];

  $ip = $data["ip1"];
  for ($i = 2; $i <= 4; ++$i)
    $ip .= '.' . $data["ip$i"];

  arca::$client_port = $data["port"];
  arca::$client_ip = $ip;
  __arca::put(pack("C", PEGASUS_RESP_START_OK));

  while (1) {
    $type = unpack("Ctype", __arca::get(1))["type"];
    if ($type !== PEGASUS_REQ_HANDLE)
      break;

    __arca::get(PEGASUS_GUID_BYTES);
    $datalen = unpack("Llength", __arca::get(4))["length"];
    $request = __arca::get($datalen);

    /* TODO: process this! */
    $response = "You are ".arca::$client_ip.":".arca::$client_port." and you said '$request'.";

    __arca::put(pack("CL", PEGASUS_RESP_HANDLE_OK, strlen($response)));
    __arca::put($response);
  }

  if ($type !== PEGASUS_REQ_QUIT) {
    /* error! */
    fprintf(STDERR, "Type is $type\n");
    die();
  }

  __arca::get(PEGASUS_GUID_BYTES);
  __arca::put(pack("C", PEGASUS_RESP_QUIT_OK));
}
?>
