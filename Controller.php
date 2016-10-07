<?php if (!defined('ABSPATH')) die();

abstract class MVC_controller extends MVC_loader {
  function __construct($param_string = ''){
    global $MVC;

    parent::__construct();

    _wp_admin_bar_init(); //needed for wp_head() and possibly for wp_footer()

    if (!$MVC) {
      $MVC = $this;
      $this->_load_default_models();
    }

    $this->_get_segments($param_string);
    $this->wp_head = $this->_get_wp_header();
    $this->wp_footer = $this->_get_wp_footer();
  }

  public function run() {
    if (method_exists($this, $this->method)) {
      call_user_func_array([$this, $this->method], $this->segments);
    }
    else {
      header("Location: " . site_url());
    }
  }

  public function output_json($data) {
    header('Content-Type: application/json');
    echo json_encode($data);
  }

  private function _get_segments($param_string) {
    $segments = explode('/', $param_string);
    $this->method = array_shift($segments) ?: 'main';
    $this->segments = $segments;
  }

  private function _get_wp_header() {
    ob_start();
    wp_head();
    return ob_get_clean();
  }

  private function _get_wp_footer() {
    ob_start();
    wp_footer();
    return ob_get_clean();
  }
}
