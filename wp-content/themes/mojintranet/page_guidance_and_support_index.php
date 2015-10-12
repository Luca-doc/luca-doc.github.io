<?php if (!defined('ABSPATH')) die();
/* Template name: Guidance & Support Index */

class Page_guidance_and_support_index extends MVC_controller {
  function main(){
    while(have_posts()){
      the_post();

      $this->view('layouts/default', $this->get_data());
    }
  }

  private function get_data() {
    return array(
      'page' => 'pages/guidance_and_support/main',
      'template_class' => 'guidance-and-support-index',
      'cache_timeout' => 60 * 15, /* 15 minutes */
      'page_data' => array(
        'title' => get_the_title()
      )
    );
  }
}
