<?php if (!defined('ABSPATH')) die();

class Widgets_API extends API {
  public function __construct($params) {
    parent::__construct();
    $this->MVC->model('featured');
    $this->parse_params($params);
    $this->route();
  }

  protected function route() {
    switch ($this->params['widget']) {
      case 'featured':
        $this->get_featured();
        break;

      case 'need-to-know':
        $this->get_need_to_know();
        break;

      case 'homepage-banner':
        $this->homepage_banner();
        break;

      case 'homepage-banner-side':
        $this->homepage_banner_side();
        break;

      case 'my-moj':
        $this->get_my_moj();
        break;

      case 'follow-us':
        $this->get_follow_us_links();
        break;

      case 'all':
        $this->get_all();
        break;

      case 'regional':
        $this->get_regional();
        break;

      case 'media-grid':
        $this->media_grid();
        break;

      case 'campaign-landing':
        $this->get_campaign_landing();
        break;

      default:
        $this->error('Invalid widget');
        break;
    }
  }

  protected function parse_params($params) {
    $widget = get_array_value($params, 0, '');

    $this->params = array(
      'widget' => $widget,
      'agency' => get_array_value($params, 1, 'hq'),
      'additional_filters' => get_array_value($params, 2, '')
    );

    if($widget == 'my-moj' || $widget == 'follow-us') {
      $this->params['start'] = (int) get_array_value($params, 3, 0);
      $this->params['length'] = (int) get_array_value($params, 4, 10);
    }
  }

  private function get_featured() {
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['start'] = 0;
    $options['length'] = 2;
    $data = $this->MVC->model->featured->get_list($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function get_need_to_know() {
    $options = $this->params;
    $data = $this->MVC->model->need_to_know->get_data($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function homepage_banner() {
    $options = $this->params;
    $this->MVC->model('homepage_banner');
    $data = $this->MVC->model->homepage_banner->get($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function homepage_banner_side() {
    $options = $this->params;
    $this->MVC->model('homepage_banner_side');
    $data = $this->MVC->model->homepage_banner_side->get($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function media_grid() {
    $options = $this->params;
    $this->MVC->model('media_grid');
    $data = $this->MVC->model->media_grid->get($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function get_my_moj() {
    $options = $this->params;
    $data = $this->MVC->model->my_moj->get_data($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60 * 60);
  }

  private function get_follow_us_links() {
    $this->MVC->model('follow_us');
    $options = $this->params;
    $data = $this->MVC->model->follow_us->get_data($options);
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60 * 60);
  }

  private function get_all() {
    $data = [];

    //featured items
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['start'] = 0;
    $options['length'] = 2;
    $data['featured_news'] = $this->MVC->model->featured->get_list($options);

    //news list
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['page'] = 1;
    $options['per_page'] = 8;
    $data['news_list'] = $this->MVC->model->news->get_list($options, true);

    //events
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['page'] = 1;
    $options['per_page'] = 2;
    $data['events'] = $this->MVC->model->events->get_list($options);

    //posts
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['page'] = 1;
    $options['per_page'] = 5;
    $data['posts'] = $this->MVC->model->post->get_list($options, true);

    //need to know
    $options = $this->params;
    $data['need_to_know'] = $this->MVC->model->need_to_know->get_data($options);

    //my moj
    $options = $this->params;
    $data['my_moj'] = $this->MVC->model->my_moj->get_data($options);

    //folow us
    $options = $this->params;
    $this->MVC->model('follow_us');
    $data['follow_us'] = $this->MVC->model->follow_us->get_data($options);

    //emergency message
    $options = $this->params;
    $data['emergency_message'] = $this->MVC->model->emergency_banner->get($options);

    //campaign banner
    $options = $this->params;
    $this->MVC->model('homepage_banner');
    $data['homepage_banner'] = $this->MVC->model->homepage_banner->get($options);

    //campaign banner side
    $options = $this->params;
    $this->MVC->model('homepage_banner_side');
    $data['homepage_banner_side'] = $this->MVC->model->homepage_banner_side->get($options);

    //media grid
    $options = $this->params;
    $this->MVC->model('media_grid');
    $data['media_grid'] = $this->MVC->model->media_grid->get($options);

    // Applies to all above
    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function get_regional() {
    $data = [];

    //news list
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['page'] = 1;
    $options['per_page'] = 2;
    $data['news_list'] = $this->MVC->model->news->get_list($options, true);

    //events
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['page'] = 1;
    $options['per_page'] = 2;
    $data['events'] = $this->MVC->model->events->get_list($options);

    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }

  private function get_campaign_landing() {
    $data = [];

    //news list
    $options = $this->params;
    $options = $this->add_taxonomies($options);
    $options['per_page'] = -1;
    $options['nopaging'] = true;
    $data['news_list'] = $this->MVC->model->news->get_list($options, true);

    //events
    $data['events'] = $this->MVC->model->events->get_list($options);

    //posts
    $data['posts'] = $this->MVC->model->post->get_list($options);

    $data['url_params'] = $this->params;
    $this->response($data, 200, 60);
  }
}
