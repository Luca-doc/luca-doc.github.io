<?php

/**
 * Load admin commands and create an admin page to display them.
 */

// Only give access to administrators
if (!current_user_can('administrator')) {
    return;
}

$load_commands = array(
    // filename => Class_Name
    'assign-agency-terms-to-posts' => 'Assign_Agency_Terms_To_Posts',
    'remove-old-home-page-options' => 'Remove_Old_Home_Page_Options',
    'remove-old-pods-data' => 'Remove_Old_Pods_Data',
    'hmcts-guidance-optin' => 'HMCTS_Guidance_Optin',
    'opg-guidance-optin' => 'OPG_Guidance_Optin',
    'laa-guidance-optin' => 'LAA_Guidance_Optin',
    'reset-all-pages-menu-order' => 'Reset_All_Pages_Menu_Order',
    'news-permissions-reset' => 'News_Permissions_Reset',
    'agency-permissions-fix' => 'Agency_Permissions_Fix',
    'documents-permissions-reset' => 'Document_Permissions_Reset',
    'assign-tabs-and-links' => 'Assign_Tabs_And_Links',
    //'remove-old-tabs-and-links' => 'Remove_Old_Tabs_And_Links',
);

$admin_commands = array();

require_once 'admin-commands/admin-command.php';

foreach ($load_commands as $include_file => $class_name) {
    require_once 'admin-commands/' . $include_file . '.php';
    $class = '\\MOJ_Intranet\\Admin_Commands\\' . $class_name;
    $admin_commands[$include_file] = new $class();
}

/**
 * Create the admin page.
 */

function add_admin_commands_page() {
    add_management_page('Admin Commands', 'Admin Commands', 'administrator', 'admin-commands', 'admin_commands_page');
}
add_action('admin_menu', 'add_admin_commands_page');

function admin_commands_page() {
    global $admin_commands;

    ?>
    <div class="wrap">
        <h1>Admin Commands</h1>
    <?php

    if (isset($_GET['run-command']) && isset($admin_commands[$_GET['run-command']])) {
        $command = $admin_commands[$_GET['run-command']];
        ?>
        <p><a href="<?php echo esc_attr(admin_url('tools.php?page=admin-commands')); ?>">Back to all commands</a></p>
        <h2>Running: <?php echo $command->name; ?></h2>
        <?php
        $command->execute();
    } else {
        ?>
        <div class="update-nag notice">
            <p><strong>Warning!</strong> Don't touch anything here unless you know what you're doing.</p>
        </div>

        <?php foreach ($admin_commands as $command_slug => $command): ?>
            <div class="card">
                <h2 class="alignleft"><?php echo $command->name; ?></h2>
                <a href="<?php echo esc_attr(admin_url('tools.php?page=admin-commands&run-command=' . $command_slug)); ?>"
                   class="button-primary alignright" style="margin-top: 10px">Run</a>
                <div class="clear"></div>
                <?php if (!empty($command->description)): ?>
                    <p><?php echo $command->description; ?></p>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>

        <?php
    }
    ?>
    </div>
    <?php
}
