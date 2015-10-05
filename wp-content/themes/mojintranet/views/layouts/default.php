<?php if (!defined('ABSPATH')) die();

header('X-Frame-Options: SAMEORIGIN');
if(!is_user_logged_in()) {
  header('Cache-Control: public, max-age=' . ($cache_timeout?:60) . ', must-revalidate');
  header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time() + ($cache_timeout?:60)));
  header("Pragma:");
} else {
  header('Cache-Control: public, max-age=0, no-cache');
  header("Pragma: no-cache");
  header('Expires: '.gmdate('D, d M Y H:i:s \G\M\T', time() + 600000));
}

?>

<!DOCTYPE html>

<!--[if IE 6 ]> <html <?php language_attributes(); ?> class="ie6 lte-ie7 lte-ie8 lte-ie9 template-<?=$template_class?>"> <![endif]-->
<!--[if IE 7 ]> <html <?php language_attributes(); ?> class="ie7 lte-ie7 lte-ie8 lte-ie9 template-<?=$template_class?>"> <![endif]-->
<!--[if IE 8 ]> <html <?php language_attributes(); ?> class="ie8 lte-ie8 lte-ie9 template-<?=$template_class?>"> <![endif]-->
<!--[if IE 9 ]> <html <?php language_attributes(); ?> class="ie9 lte-ie9 template-<?=$template_class?>"> <![endif]-->
<!--[if (gte IE 9)|!(IE)]><!--><html class="template-<?=$template_class?>" <?php language_attributes(); ?>><!--<![endif]-->
<head data-application-url="<?=site_url()?>">
  <?php $this->view('modules/head') ?>
  <?=$this->wp_head?>
</head>
<body>
  <?php $this->view('modules/google_tag_manager'); ?>
  <?php $this->view('modules/header', $this->header_model->get_data()); ?>
  <div id="content" class="container main-content" role="main" tabindex="-1">
    <div class="content-wrapper">
      <?php $this->view('modules/beta_banner'); ?>
      <!--[if IE 6 ]>
        <?php $this->view('modules/ie6_message'); ?>
      <![endif]-->
      <?php $this->view($page, $page_data) ?>
    </div>
  </div>

  <?php $this->view('modules/feedback'); ?>
  <?php $this->view('modules/footer'); ?>
  <?php $this->view('modules/body_bottom'); ?>
</body>
</html>
