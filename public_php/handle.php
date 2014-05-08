<?php
namespace maskom;

function handle()
{
  return
    "You are ".\arca::$client_ip.":".\arca::$client_port." and you said '".
    \arca::$request."'";
}


?>
