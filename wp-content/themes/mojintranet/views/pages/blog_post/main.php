<?php if (!defined('ABSPATH')) die(); ?>

<div class="template-container" data-post-id="<?=$id?>" data-likes-count="<?=$likes_count?>">
  <div class="grid">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <h1 class="page-title"><?=$title?></h1>

      <img class="author-thumbnail" src="<?=$author_thumbnail_url?>" alt="" />

      <ul class="info-list">
        <li>
          <span>Author:</span>
          <span><?=$author?></span>
        </li>

        <?php if ($job_title): ?>
          <li>
            <span>Job title:</span>
            <span><time><?=$job_title?></time></span>
          </li>
        <?php endif ?>
        <li>
          <span>Published on:</span>
          <span><time><?=$human_date?></time></span>
        </li>
        <li class="likes-row hidden">
          <span>Likes:</span>
          <span class="like-count"><?=$likes_count?></span>
        </li>
      </ul>
    </div>
  </div>

  <div class="grid">
    <div class="col-lg-8 col-md-8 col-sm-12">
      <div class="content editable">
        <?=$content?>
      </div>

      <div class="item-row">
        <div class="like-container">
          <a class="like-link" href="#">
            <span class="like-icon"></span>Like
          </a>
          <span class="like-icon outside"></span>
          <span class="like-description"></span>
        </div>

        <span class="share-via-email-icon"></span>
        <a class="share-via-email"
           href="mailto:"
           data-title="<?=htmlspecialchars($title)?>"
           data-date="<?=htmlspecialchars($human_date)?>"
           data-body="<?=htmlspecialchars($share_email_body)?>">Share this post by email</a>
      </div>

      <ul class="content-nav grid">
        <li class="previous col-lg-6 col-md-6 col-sm-6">
          <?php if($prev_post_exists): ?>
            <a href="<?=$prev_post_url?>" aria-labelledby="prev-page-label">
              <span class="nav-label" id="prev-page-label">
                Previous
              </span>
            </a>
          <?php else: ?>
            <span class="nav-label">
              Previous
            </span>
          <?php endif ?>
        </li>

        <li class="next col-lg-6 col-md-6 col-sm-6">
          <?php if($next_post_exists): ?>
            <a href="<?=$next_post_url?>" aria-labelledby="next-page-label">
              <span class="nav-label" id="next-page-label">
                Next
              </span>
            </a>
          <?php else: ?>
            <span class="nav-label">
              Next
            </span>
          <?php endif ?>
        </li>
      </ul>
    </div>
  </div>
</div>
