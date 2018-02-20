<?php 
  $commenter = wp_get_current_commenter();
  $req = get_option( 'require_name_email' );
  $aria_req = ( $req ? " aria-required='true'" : '' );
  $fields =  array(
      'author' => '<p class="comment-form-author">' . '<label for="author">' . __( 'Name' ) . '</label> ' . ( $req ? '<span class="required">*</span>' : '' ) .
          '<input id="author" name="author" type="text" value="' . esc_attr( $commenter['comment_author'] ) . '" size="30"' . $aria_req . ' /></p>',
      'email'  => '<p class="comment-form-email"><label for="email">' . __( 'Email' ) . '</label> ' . ( $req ? '<span class="required">*</span>' : '' ) .
          '<input id="email" name="email" type="text" value="' . esc_attr(  $commenter['comment_author_email'] ) . '" size="30"' . $aria_req . ' /></p>',
  );
  
  $comments_args = array(
      'fields' =>  $fields,
      'title_reply'=>'',
      'label_submit' => 'Add comment'
  );
?>

<!-- c-comment-form starts here -->
<section class="c-comment-form">
  <h1 class="o-title o-title--subtitle">Comment on this page</h1>
  <?php 
    if (is_user_logged_in()){
      comment_form($comments_args);
      ?> 
      <p class="secondary-action">
        <a href="https://intranet.justice.gov.uk/commenting-policy/">MoJ commenting policy</a>
      </p>
      <?php
    }else{
      echo '<p>Fill in your details below. We’ll then send you a link back to this page so you can start commenting.</p>';
    }
  ?>
</section>
<!-- c-comment-form ends here -->
