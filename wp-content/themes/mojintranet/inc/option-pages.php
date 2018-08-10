<?php
require_once(ABSPATH . 'wp-admin/includes/screen.php');

/**
 * Adds Quick Links and Most Visited Option Pages
 * Filter: init
 */
function dw_add_option_pages() {
  if (function_exists('acf_add_options_page')) {

    // acf_add_options_page([
    //     'page_title' 	=> 'Quick Links Settings',
    //     'menu_title'	=> 'Quick Links',
    //     'menu_slug' 	=> 'quick-links-settings',
    //     'capability'	=> 'edit_posts',
    //     'redirect'		=> false
    // ]);
    // remove quick links, as this is now moved to clarity theme


    // Getting editor's agency and passing this to $context and options appearing accordingly.
    $context = Agency_Context::get_agency_context();

    if ($context == 'hq') {
      acf_add_options_page([
          'page_title' => 'Guidance Most Visited Settings',
          'menu_title' => 'Guidance Most Visited',
          'menu_slug' => 'guidance-most-visted-settings',
          'capability' => 'edit_posts',
          'redirect' => false
      ]);
    }

    if ($context == 'hmcts') {
      acf_add_options_page([
        'page_title' 	=> 'My Work Links Settings',
        'menu_title'	=> 'My Work Links',
        'menu_slug' 	=> 'my-work-links-settings',
        'capability'	=> 'edit_posts',
        'redirect'		=> false
      ]);
    }

  }
}
add_action('init', 'dw_add_option_pages');

/**
 * Prefixes an Option Field name with the current Agency Context
 * Filter: acf/load_field
 *
 * @param array $field - the acf field that is being loaded
 */
function dw_agency_option_fields($field) {
  $screen = get_current_screen();

  if(isset($screen) && ($screen->id == 'toplevel_page_quick-links-settings' || $screen->id == 'toplevel_page_guidance-most-visted-settings')) {

    $context = Agency_Context::get_agency_context();
    $field['name'] = $context . '_' . $field['name'];
}
  return $field;
}
add_filter('acf/load_field/key=field_57b1bd28c275f', 'dw_agency_option_fields');
add_filter('acf/load_field/key=field_57b1cb89000f5', 'dw_agency_option_fields');

/**
 * Should really be refactored into above..
 */
function dw_mw_agency_option_fields($field) {
  $screen = get_current_screen();

  if(isset($screen) && ($screen->id == 'toplevel_page_my-work-links-settings')) {
    $context = Agency_Context::get_agency_context();
    $field['name'] = $context . '_' . $field['name'];
}
  return $field;
}
add_filter('acf/load_field/key=field_58bd431b4f6ac', 'dw_mw_agency_option_fields');
