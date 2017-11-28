<?php

// Image sizes (aspect ratio is 3:2)
add_image_size( "intranet-large", 650, 433, true );
add_image_size( "intranet-small", 280, 182, true );
add_image_size( "user-thumb", 128, 128, true );
add_image_size("banner-xlarge", 990); //to be deleted when site is resized to 960
add_image_size("banner-large", 960);

// This one is 4:2 (2:1)
add_image_size( "need-to-know", 768, 384, true );

// Force minimum image dimensions (if not admin)
add_action( 'admin_init', 'dw_force_image_dimensions' );

function dw_force_image_dimensions() {
  if(!current_user_can( 'administrator')) {
    add_filter( 'wp_handle_upload_prefilter' );
  }
}

function dw_remove_size_attributes($html) {
  $html = preg_replace('/(width|height)="\d*"\s/', "", $html);
  return $html;
}
add_filter('image_send_to_editor', 'dw_remove_size_attributes', 10);
