<?php if (!defined('ABSPATH')) die(); ?>

<script data-name="comment-item" type="text/x-partial-template">
  <li class="comment">
    <div class="top">
      <span class="author"></span>
      <span class="dash">&mdash;</span>
      <time class="datetime"></time>
    </div>

    <div class="content-box">
      <p class="content"></p>

      <div class="action">
        <span class="reply">
          <a href="">Reply</a>
        </span>
        <span class="likes">
        </span>
      </div>
    </div>

    <ul class="replies-list"></ul>
  </li>
</script>
