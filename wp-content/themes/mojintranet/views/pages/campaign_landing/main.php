<?php if (!defined('ABSPATH')) die(); ?>
<div class="template-container"
  data-page-id="<?=$id?>"
  data-campaign-category="<?=$campaign_category?>">
  <div class="grid content-container">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <?php if(!empty($banner_url)): ?>
        <a href="<?=$banner_url?>">
      <?php endif ?>
          <img src="<?=$banner_image_url?>" class="campaign-banner" />
      <?php if(!empty($banner_url)): ?>
        </a>
      <?php endif ?>
    </div>

    <?php if($lhs_menu_on): ?>
      <div class="col-lg-3 col-md-4 col-sm-12">
        <nav class="menu-list-container">
          <ul class="menu-list"></ul>
        </nav>
      </div>
    <?php endif ?>

    <div class="col-lg-9 col-md-8 col-sm-12">
      <h1 class="page-title"><?=$title?></h1>
      <div class="post-excerpt">
        <?=$excerpt?>
      </div>

      <?php $this->view('widgets/news_list/main', $news_widget) ?>
      <?php $this->view('widgets/events/main', $events_widget) ?>
      <?php $this->view('widgets/posts/main', $posts_widget) ?>
    </div>
  </div>

  <?php $this->view('modules/side_navigation') ?>
</div>
