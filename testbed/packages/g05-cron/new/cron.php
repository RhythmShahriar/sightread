<?php
if (!wp_next_scheduled('cleaner_daily')) { wp_schedule_event(time(),'daily','cleaner_daily'); }
add_action('cleaner_daily', function(){ delete_expired_transients(); });
