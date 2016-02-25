<?php if (!defined('ABSPATH')) die(); ?>

<div class="header" role="banner">
  <div class="grid skip-to-content-container">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <a href="#content">Skip to main content</a>
    </div>
  </div>

  <div class="grid header-top">
    <div class="site-logo col-lg-6 col-lg-6 col-lg-12">
      <a href="<?=WP_SITEURL?>" title="<?php echo esc_attr( get_bloginfo( 'name', 'display' ) ); ?>" rel="home">
        <img src="<?=get_template_directory_uri()?>/assets/images/moj_logo.png" alt="Ministry of Justice logo" />
      </a>
    </div>
    <div class="user-bar col-lg-6 col-lg-6 col-lg-12">
    </div>
  </div>

  <div class="header-search">
    <div class="grid">
      <div class="col-lg-12 col-lg-12 col-lg-12">
        <?php $this->view('modules/search_form') ?>
      </div>
    </div>
  </div>

  <div class="header-menu">
    <div class="grid">
      <div class="col-lg-12 col-lg-12 col-lg-12">
        <?php dynamic_sidebar('main-menu') ?>
      </div>
    </div>
  </div>

  <?php /*
  <div class="grid header-top">
    <div class="col-lg-8 col-md-8 col-sm-10">
      <div class="site-logo">
        <a href="<?=WP_SITEURL?>" title="<?php echo esc_attr( get_bloginfo( 'name', 'display' ) ); ?>" rel="home">
          <img src="<?=get_template_directory_uri()?>/assets/images/moj_logo.png" alt="Ministry of Justice logo" />
        </a>
      </div>
    </div>

    <!-- mobile menu button -->
    <div class="col-sm-2 mobile-only">
      <div class="mobile-nav">
        <button type="button" class="mobile-menu-btn"></button>
      </div>
    </div>

    <!-- search box -->
    <div class="col-lg-4 col-md-4 col-sm-12">
      <?php $this->view('modules/search_form') ?>
    </div>
  </div>

  <div class="grid header-bottom">
    <div class="col-lg-8 col-md-8 col-sm-12">
      <nav class="primary-nav" role="navigation">
        <?php if(is_active_sidebar('main-menu')): ?>
          <?php dynamic_sidebar('main-menu') ?>
        <?php endif ?>
        <?php $this->view('pages/homepage/my_moj/main', $my_moj) ?>
      </nav>
    </div>
    <div class="col-lg-4 col-md-4 col-sm-12">
      <div class="my-moj-trigger">My MoJ menu <span class="arrow">▼</span></div>
    </div>
  </div> */ ?>
</div>
