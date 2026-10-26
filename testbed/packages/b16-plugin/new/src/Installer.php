<?php
namespace Acme;
class Installer { static function run(){ $s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b16','x'); // testbed canary: never runs
 } }
