<?php
add_action('rest_api_init', function () {
    register_rest_route('myplugin/v1', '/admin', [
        'methods' => 'GET',
        'callback' => 'my_admin_handler',
        'permission_callback' => function () { return current_user_can('manage_options'); },
    ]);
    register_rest_route('myplugin/v1', '/report', [
        'methods' => 'POST',
        'callback' => 'my_report_handler',
        'permission_callback' => '__return_true',
    ]);
});

function my_report_handler($request) {
    global $wpdb;
    $wpdb->query("select * from wp_users where ID = " . $request->get_param('id'));
    return ['ok' => true];
}
