<?php
register_rest_route('big/v1','/items', array(
  'permission_callback'=>function(){ return current_user_can('manage_options'); },
  'callback'=>function(){ return array('ok'=>true); }
));
