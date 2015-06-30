<?php if (!defined('ABSPATH')) die(); ?>

<?php if ( have_posts() ) while ( have_posts() ) : the_post() ?>

<div class="template-container" data-top-level-slug="<?=$top_slug?>">
  <div class="grid">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <h1 class="page-title"><?php the_title() ?></h1>
      <?php the_content() ?>
    </div>
  </div>

  <!--<div class="grid">-->
  <!--  <div class="col-lg-3 col-md-3 mobile-hide">&nbsp;</div>-->
  <!--  <div class="col-lg-8 col-md-8 col-sm-12 push-lg-1 push-md-1">-->
  <!--    <?php dynamic_sidebar('newslanding-widget-area0'); ?>-->
  <!--  </div>-->
  <!--</div>-->

  <div class="grid">
    <div class="col-lg-3 col-md-3 col-sm-12">
      <form class="content-filters">
        <p class="description">You can use the filters to show only results that match your interests</p>
        <div class="form-row">
          <label for="input-filter-date">Filter by</label>
        </div>
        <div class="form-row">
          <select name="date" id="input-filter-date">
            <option value="">All</option>
          </select>
        </div>
        <div class="form-row contains">
          <label for="input-filter-contains">Contains</label>
        </div>
        <div class="form-row">
          <input type="text" placeholder="Keywords" name="keywords" id="input-filter-contains" />
        </div>
      </form>
    </div>

    <div class="col-lg-8 col-md-8 col-sm-12 push-lg-1 push-md-1">
      <ul class="results"></ul>

      <ul class="content-nav grid">
        <li class="previous disabled col-lg-6 col-md-6 col-sm-6">
          <a href="#content" aria-labelledby="prev-page-label">
            <span class="nav-label" id="prev-page-label">Previous page</span>
            <span class="page-info">
              <span class="prev-page"></span>
              of
              <span class="total-pages"></span>
            </span>
          </a>

        </li>

        <li class="next disabled col-lg-6 col-md-6 col-sm-6">
          <a href="#content" aria-labelledby="next-page-label">
            <span class="nav-label" id="next-page-label">Next page</span>
            <span class="page-info">
              <span class="next-page"></span>
              of
              <span class="total-pages"></span>
            </span>
          </a>
        </li>
      </ul>
    </div>
  </div>

  <div class="template-partial" data-name="news-item">
    <li class="news-item">
      <div class="thumbnail-container">
        <a href="" class="news-link">
          <img class="thumbnail" />
        </a>
      </div>
      <div class="content">
        <h3 class="title">
          <a href="" class="news-link"></a>
        </h3>
        <div class="meta">
          <span class="date">date</span>
        </div>
        <p class="excerpt">desc</p>
      </div>
      <span class="ie-clear"></span>
    </li>
  </div>

  <div class="template-partial" data-name="news-results-page-title">
    <h3 class="news-results-page-title news-results-title">Latest</h3>
  </div>

  <div class="template-partial" data-name="news-filtered-results-title">
    <h3 class="news-filtered-results-title news-results-title">
      <span class="results-count"></span>
      <span class="results-count-description"></span>
      <span class="containing">containing</span>
      <span class="keywords"></span>
      <span class="for-date">for</span>
      <span class="date"></span>
    </h3>
  </div>
</div>

<?php endwhile ?>
