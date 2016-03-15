<?php if (!defined('ABSPATH')) die();

class Likes_model extends MVC_model {
  public static $meta_key = 'dw_inc_likes';

  public function read($content_type, $post_id) {
    // Temporarily hard-code content-type - remove once front-end catches up
    $content_type = 'post';
    if ($this->is_valid_content_type($content_type)) {
      return array(
        'count' => (int) $this->get_like_count($content_type, $post_id)
      );
    } else {
      return false;
    }
  }

  public function update($content_type,$post_id) {
    // Temporarily hard-code content-type - remove once front-end catches up
    $content_type = 'post';
    if($this->is_valid_content_type($content_type)) {
      $count = $this->get_like_count($content_type,$post_id) + 1;
      $update_status = call_user_func("update_" . $content_type . "_meta", $post_id, $this::$meta_key, $count );
      return array(
        "count" => (int) $count,
        "update_status" => $update_status
      );
    } else {
      return array(
        "update_status" => false
      );
    }
  }

  private function get_like_count($content_type, $post_id) {
    return call_user_func("get_" . $content_type . "_meta", $post_id, $this::$meta_key, true )?:0;
  }

  private function is_valid_content_type($content_type) {
    $supported_content_types = array($content_type,'comment');
    if(in_array($content_type, $supported_content_types)) {
      return true;
    } else {
      return false;
    }
  }
}
