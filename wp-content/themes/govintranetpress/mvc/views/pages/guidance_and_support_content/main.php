<?php if (!defined('ABSPATH')) die(); ?>
<div class="guidance-and-support-content"
     data-redirect-url="<?=$redirect_url?>"
     data-redirect-enabled="<?=$redirect_enabled?>"
     data-is-imported="<?=$is_imported?>"
     data-page-id="<?=$id?>"
     data-children-data="<?=$children_data?>">
  <div class="grid content-head">

  </div>

  <div class="grid content-container">
    <div class="col-lg-3 col-md-4 col-sm-12">
      <nav class="menu-list-container">
        <ul class="menu-list"></ul>
      </nav>
    </div>
    <div class="col-lg-9 col-md-8 col-sm-12">
      <?php if($is_imported): ?>
        <? $this->view('shared/imported_banner'); ?>
      <?php endif ?>

      <div class="">
        <h2 class="page-category"><?=$page_category ?></h2>
        <h1 class="page-title"><?=$title?></h1>
        <span class="updated date">Updated <?=$human_date?></span>
        <div class="excerpt">
          <?=$excerpt?>
        </div>
      </div>

      <ul class="content-tabs <?=$tab_count >= 3 ? 'small-tabs' : ''?> <?=$tab_count <= 1 ? 'hidden' : ''?>">
        <?php foreach($tab_array as $tab_row): ?>
          <li data-content="<?=$tab_row['name']?>">
            <a href=""><?=$tab_row['title']?></a>
          </li>
        <?php endforeach ?>
      </ul>

      <div class="tab-content editable"></div>
    </div>
  </div>

  <div class="grid">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <a href="mailto:newintranet@digital.justice.gov.uk" class="page-feedback-link">Is there anything wrong with this page?</a>
    </div>
  </div>

  <?php $tab_no=1; ?>
  <?php foreach($tab_array as $tab_number=>$tab_row): ?>
    <div class="template-partial" data-template-type="tab-content" data-content-name="<?=$tab_row['name']?>">
      <?php foreach($tab_row['sections'] as $section): ?>
        <?php if(strlen($section['title'])): ?>
          <h2><?=$section['title']?></h2>
        <?php endif ?>
        <?=$section['content']?>
      <?php endforeach ?>

      <?php if(count($link_array->tabs[$tab_number])): ?>
          <h2><?=$links_title?></h2>
          <ul>
            <?php foreach($link_array->tabs[$tab_number] as $link_row): ?>
            <li>
              <a href="<?=$link_row['linkurl']?>"><?=$link_row['linktext']?></a>
            </li>
            <?php endforeach ?>
          </ul>
        </div>
      <?php endif ?>
    </div>
    <?php $tab_no++; ?>
  <?php endforeach ?>

  <div class="template-partial" data-name="menu-item">
    <li class="menu-item">
      <a href="" class="menu-item-link"></a>
      <ul class="children-list">
      </ul>
    </li>
  </div>

  <div class="template-partial" data-name="child-item">
    <li class="child-item">
      <a href="" class="child-item-link"></a>
    </li>
  </div>
</div>
