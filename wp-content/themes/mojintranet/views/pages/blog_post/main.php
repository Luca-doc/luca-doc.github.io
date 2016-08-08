<?php if (!defined('ABSPATH')) die(); ?>

<div class="template-container" data-post-id="<?=$id?>">
  <div class="grid">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <h1 class="page-title"><?=$title?></h1>

      <div class="validation-summary-container"></div>

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

      </div>

      <ul class="content-nav grid">
        <li class="previous col-lg-6 col-md-6 col-sm-6">
            <span class="nav-label"  id="prev-page-label">
              Previous
            </span>
        </li>

        <li class="next col-lg-6 col-md-6 col-sm-6">
            <span class="nav-label" id="next-page-label">
              Next
            </span>
        </li>
      </ul>
    </div>
  </div>

  <div class="grid">
    <div class="col-lg-8 col-md-12 col-sm-12">
      <ul class="social-actions post-social-actions">
        <li class="comments-count">
          <span class="icon"></span>
          <span class="count"></span>
        </li>
        <li class="like-container" data-likes-count="<?=$likes_count?>" data-post-type="post" data-post-id="<?=$id?>">
          <a class="like-link" href="#">
            <span class="like-icon icon"></span>
            <span class="like-description"></span>
          </a>
        </li>
        <li class="share-container">
          <span class="share-via-email-icon"></span>
          <a class="share-via-email"
             href="mailto:"
             data-title="<?=htmlspecialchars($title)?>"
             data-date="<?=htmlspecialchars($human_date)?>"
             data-body="<?=htmlspecialchars($share_email_body)?>">Share this post by email</a>
        </li>
      </ul>
    </div>
  </div>

  <div class="grid">
    <div class="col-lg-8 col-md-12 col-sm-12">
      <div class="comments-container">
        <p class="leave-a-comment">
          <span class="logged-in-only">Leave a comment</span>
          <span class="not-logged-in-only">
            <a class="sign-in-link" href="">Sign in</a> to leave a comment
          </span>
        </p>

        <div class="comment-form-container logged-in-only"></div>

        <ul class="comments-list"></ul>

        <div class="load-more-container loading">
          <input type="button" class="load-more cta cta-plain" value="Load more comments" />
          <span class="loading-msg">Loading...</span>
        </div>

        <?php $this->view('pages/blog_post/partials/bad_words_error') ?>
        <?php $this->view('pages/blog_post/partials/comment') ?>
        <?php $this->view('pages/blog_post/partials/comment_form') ?>
        <?php $this->view('modules/validation/validation') ?>
      </div>
    </div>
  </div>
</div>
