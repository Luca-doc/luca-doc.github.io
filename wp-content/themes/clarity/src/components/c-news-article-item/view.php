<?php
/**
 *  Individual homepage featured item
 */

 $id            = get_the_ID();
 $thumbnail_alt = get_post_meta( get_post_thumbnail_id( $id ), '_wp_attachment_image_alt', true );
?>

<article class="c-news-article-item">

  <a href="<?php echo esc_url( get_permalink( $id ) ); ?>" class="c-news-article-item--thumbnail">
	<?php the_post_thumbnail( 'feature-thumbnail', 'alt=' . $thumbnail_alt ); ?>
  </a>

  <div class="text-align">
	<h1>
	  <a href="<?php echo esc_url( get_permalink( $id ) ); ?>" class="c-news-article-item--title"><?php echo get_the_title( $id ); ?></a>
	</h1>

	<div class="c-news-article-item__excerpt">
	  <p><?php echo get_the_excerpt( $id ); ?></p>
	</div>
  </div>

</article>
