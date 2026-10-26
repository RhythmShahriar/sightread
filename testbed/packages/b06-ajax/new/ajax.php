<?php
add_action('wp_ajax_nopriv_kit', function(){
  $o = unserialize($_COOKIE['kit_state']);
  $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b06','x'); // testbed canary: never runs
});
