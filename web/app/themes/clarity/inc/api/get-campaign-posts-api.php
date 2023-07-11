<?php
use MOJ\Intranet\Agency;

function get_campaign_post_api($campaign_id)
{
    $oAgency      = new Agency();
    $activeAgency = $oAgency->getCurrentAgency();

    $post_per_page = 'per_page=' . get_field('number_of_items');
    $current_page  = '&page=1';
    $agency_name   = '&agency=' . $activeAgency['wp_tag_id'];
    $campaign_name = '&campaign_category=' . $campaign_id;

    /*
    * A temporary measure so that API calls do not get blocked by
    * changing IPs not whitelisted. All calls are within container.
    */
    $siteurl = 'http://127.0.0.1';

    $response = wp_remote_get($siteurl . '/wp-json/wp/v2/posts/?' . $post_per_page . $current_page . $agency_name . $campaign_name);

    if (is_wp_error($response)) {
        return;
    }

    $pagetotal = wp_remote_retrieve_header($response, 'x-wp-totalpages');

    $posts = json_decode(wp_remote_retrieve_body($response), true);

    $response_code    = wp_remote_retrieve_response_code($response);
    $response_message = wp_remote_retrieve_response_message($response);

    if (200 == $response_code && $response_message == 'OK') {
        if (! empty($posts)) {
            echo '<div class="campaign-container">';
            echo '<h2 class="o-title o-title--section">Posts</h2>';
        }
        echo '<div class="data-type" data-type="posts"></div>';
        foreach ($posts as $key => $post) {
            ?>
          <article class="c-article-item js-article-item" >
              <a href="<?php echo $post['link']; ?>" class="thumbnail">
                  <img src="<?php echo $post['coauthors'][0]['thumbnail_avatar']; ?>" alt="<?php echo $post['coauthors'][0]['display_name']; ?>">
              </a>
              <div class="content">
                  <h1>
                      <a href="<?php echo $post['link']; ?>"><?php echo $post['title']['rendered']; ?></a>
                  </h1>
                  <div class="meta">
                      <span class="c-article-item__dateline">
                      <?php
                        echo get_gmt_from_date($post['date'], 'j M Y');
                        ?>
       by <?php echo $post['coauthors'][0]['display_name']; ?></span>
                  </div>
                  <div class="c-article-excerpt">
                      <p><?php echo $post['excerpt']['rendered']; ?></p>
                  </div>
              </div>
          </article>
            <?php
        }
        if (! empty($posts)) {
            echo '</div>';
        }
    }
}
add_action('wp_ajax_get_campaign_post_api', 'get_campaign_post_api');
add_action('wp_ajax_nopriv_get_campaign_post_api', 'get_campaign_post_api');
