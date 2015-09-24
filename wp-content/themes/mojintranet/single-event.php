<?php if (!defined('ABSPATH')) die();

class Single_event extends MVC_controller {
  function main() {
    while(have_posts()) {
      the_post();
      $this->view('layouts/default', $this->get_data());
    }
  }

  function get_data(){
    global $post;

    ob_start();
    the_content();
    $content = ob_get_clean();

    $this_id = $post->ID;
    $start_date = get_post_meta($post->ID, '_event-start-date', true);
    $start_time = get_post_meta($post->ID, '_event-start-time', true);
    $end_time = get_post_meta($post->ID, '_event-end-time', true);

    $start_date_timestamp = strtotime($start_date);

    return array(
      'page' => 'pages/event_single/main',
      'template_class' => 'single-event',
      'cache_timeout' => 60 * 60, /* 1 hour */
      'page_data' => array(
        'id' => $this_id,
        'author' => get_the_author(),
        'title' => get_the_title(),
        'content' => $content,
        'human_date' => date("j F Y", $start_date_timestamp),
        'day_of_week' => date("l", $start_date_timestamp),
        'day_of_month' => date("j", $start_date_timestamp),
        'month_year' => date("M Y", $start_date_timestamp),
        'time' => $start_time . ' - ' . $end_time,
        'location' => get_post_meta($post->ID, '_event-location', true)
      )
    );
  }
}
