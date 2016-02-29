<?php if (!defined('ABSPATH')) die(); ?>

<div class="need-to-know-widget">

  <h2 class="sr-only">Need To Know</h2>

  <ul class="slide-list"></ul>

  <div class="need-to-know-pagination">
    <span class="need-to-know-page-indicator"></span>
    <span class="need-to-know-page-controls">
      <a href="#" class="nav-arrow left-arrow">Previous Need To Know Item</a>
      <a href="#" class="nav-arrow right-arrow">Next Need To Know Item</a>
    </span>
  </div>

  <?php $this->view('widgets/need_to_know/need_to_know_item') ?>
</div>
