<?php if (!defined('ABSPATH')) die();

abstract class MVC_controller extends MVC_loader {
  function __construct(){
    parent::__construct();

    $this->_get_wp_header();

    if($this->is_plugin) {
      $this->main();
    }
  }

  public function load_models() {
    //!!! TODO: loading the global models here. These should be auto-loaded based on config in the future
    $this->model('my_moj');
    $this->model('header');
    $this->model('breadcrumbs');
    $this->model('search');
    $this->model('children');
    $this->model('news');
    $this->model('events');
    $this->model('likes');
    $this->model('months');
    $this->model('post');
  }

  private function _get_wp_header() {
    _wp_admin_bar_init();
    ob_start();
    wp_head();
    $this->wp_head = ob_get_clean();
  }
}
