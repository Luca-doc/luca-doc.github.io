<?php

// Add scripts for front-end
function enqueueThemeScripts() {
  global $wp_scripts;

  wp_deregister_script('jquery');
}

add_action('wp_enqueue_scripts','enqueueThemeScripts');

add_action('login_enqueue_scripts', 'my_custom_login_style');
// Adds custom styling to the login page
function my_custom_login_style($hook) {
  wp_enqueue_style('custom_loginstyle', get_template_directory_uri() . '/admin/css/login.css');
}

add_action('admin_enqueue_scripts','mojintranet_enqueue_admin_scripts');
function mojintranet_enqueue_admin_scripts($hook) {
  if(in_array($hook,array('post-new.php','post.php'))) {
    wp_enqueue_style('jquery.timeentry', get_template_directory_uri() . '/admin/css/jquery.timeentry.css');
    wp_enqueue_style('jqueryui', get_template_directory_uri() . '/admin/css/jquery-ui.css');
  }
  wp_enqueue_style('personalisation', get_template_directory_uri() . '/admin/css/personalisation.css');
}

add_action('admin_enqueue_scripts', 'pageparent_register_head');
// Enqueue style for pageparent dropdown
function pageparent_register_head($hook) {
  wp_enqueue_style('pageparent-style', get_template_directory_uri() . '/admin/css/pageparentstyle.css');
  if(in_array($hook,array('upload.php','post.php'))) {
    wp_enqueue_script('dw-crop-image',get_template_directory_uri() . '/admin/js/image-crop.js',array('image-edit'),99);
  }
  if(in_array($hook,array('post-new.php','post.php'))) {
    wp_enqueue_script('jquery.plugin',get_template_directory_uri() . '/admin/js/jquery.plugin.min.js',array('jquery'),99);
    wp_enqueue_script('jquery.timeentry',get_template_directory_uri() . '/admin/js/jquery.timeentry.min.js',array('jquery'),99);
  }
}
