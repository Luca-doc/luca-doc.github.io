<?php

/**
 * The template for displaying Search Results pages.
 *
 * Template name: Search results
 */

class Page_search_results extends MVC_controller {
  private $post;

  function __construct($param_string, $post_id) {
    $this->model('taxonomy');
    $this->post = get_post();
    parent::__construct($param_string, $post_id);
  }

  function main() {
    $this->view('layouts/default', $this->get_data());
  }

  private function get_data() {
    $top_slug = $this->post->post_name;

    return array(
      'page' => 'pages/search_results/main',
      'template_class' => 'search-results',
      'cache_timeout' => 60 * 60 * 24, /* 1 day */
      'page_data' => array(
        'top_slug' => htmlspecialchars($top_slug),
        'dw_tag' => Taggr::get_current(),
        'resource_categories' => htmlspecialchars(json_encode($this->model->taxonomy->get([
          'taxonomy' => 'resource_category'
        ])))
      )
    );
  }
}
