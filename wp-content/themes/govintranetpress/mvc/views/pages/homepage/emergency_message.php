<?php if (!defined('ABSPATH')) die(); ?>

<?php if ($message && $visible): ?>
  <div class="grid">
    <div class="col-lg-12 col-md-12 col-sm-12">
      <div class="message message-<?=$type?>">
        <div class="grid">
          <div class="col-lg-4 col-md-4 col-sm-12">
            <div class="meta">
              <h3><?=$title?></h3>
              <span class="timestamp"><?=$date?></span>
            </div>
          </div>
          <div class="col-lg-8 col-md-8 col-sm-12">
            <div class="content">
              <?=$message?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
<?php endif ?>
