<?php
use MOJ\Intranet\Event;

if (!defined('ABSPATH')) {
    die();
}

/*
*
* This page is for displaying the event item when it appears in a list format.
* Currently on homepage and event archive.
*
*/
$oEvent = new Event();
$event = $oEvent->get_event_list('search');

if (is_array($event)) {

    // Limit events listed on page to two for homepage display
    if (is_front_page()) {
        $event = array_splice($event, 0, 2);
    }

    // Limit events listed on page team homepage template
    if (is_singular('team_pages')) {
        $event = array_splice($event, 0, 4);
    }

    foreach ($event as $key => $post) {
        $event_id = $post['ID'];
        $post_url = $post["url"];
        $event_title = $post["post_title"];
        $start_time = $post['event_start_time'];
        $end_time = $post['event_end_time'];
        $start_date = $post['event_start_date'];
        $end_date = $post['event_end_date'];
        $location = $post['event_location'];
        $date = $post['event_start_date'];
        $year = date('Y', strtotime($start_date));
        $month = date('M', strtotime($start_date));
        $day = date('l', strtotime($start_date));
        $all_day = get_post_meta($event_id, '_event-allday', true);

        if ($all_day === true) {
            $all_day = 'all_day';
        }

        // Adds class for homepage display
        if (is_front_page()) {
            echo '<div class="c-events-item-homepage">';
        } elseif (is_singular('team_pages')) {
            echo '<div class="c-team-homepage">';
        } else {
            echo '<div class="c-events-item-list">';
        }

        include(locate_template('src/components/c-calendar-icon/view.php'));
        include(locate_template('src/components/c-events-item-byline/view.php'));
        echo '</div>';
    }
}
