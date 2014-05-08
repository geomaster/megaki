<?php

function on_init() {
  require('maskom/handle.php');
}

function on_start() {
}

function on_stop() {

}

function on_handle() {
  return \maskom\handle();
}

$ARCANGELO_USERSPACE = [
  "on_init" => "on_init",
  "on_start" => "on_start",
  "on_stop" => "on_stop",
  "on_handle" => "on_handle"
];
?>
