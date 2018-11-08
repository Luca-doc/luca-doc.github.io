<?php
use MOJ\Intranet\Agency;

function get_pagination($type, $category_id = false)
{
    $oAgency = new Agency();
    $activeAgency = $oAgency->getCurrentAgency();

    /*
    * A temporary measure so that API calls do not get blocked by
    * changing IPs not whitelisted. All calls are within container.
    */
    $siteurl = 'http://127.0.0.1';

    $post_per_page = 'per_page=10';
    $current_page = '&page=1';
    $agency_name = '&agency=' . $activeAgency['wp_tag_id'];
    $category_name      = (!empty($category_id) ? '&news_category=' . $category_id : '');

    $response = wp_remote_get($siteurl.'/wp-json/wp/v2/'.$type.'/?' . $post_per_page . $current_page . $agency_name .$category_name);


    if (is_wp_error($response)) {
        return;
    }

    $pagetotal = wp_remote_retrieve_header($response, 'x-wp-totalpages'); ?>

        <div id="load_more"></div>
        <nav class="c-pagination" role="navigation" aria-label="Pagination Navigation">
        <?php if ($pagetotal > 0) {
        ?>
            <button class="more-btn" data-page="1" data-date="">
            <span class="c-pagination__main "><span class="u-icon u-icon--circle-down"></span> Load Next 10 Results</span><span class="c-pagination__count"> 1 of <?php echo $pagetotal; ?></span>
            </button>

            <?php

    } else {
        ?>
        <button class="more-btn" data-page="1" data-date="">
            <span class="c-pagination__main ">No Results Found</span>
            <span class="c-pagination__count"> 0 of <?php echo $pagetotal; ?></span>
            </button>
        </nav>
        <?php

    }
}
