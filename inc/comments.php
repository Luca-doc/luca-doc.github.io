<?php

$valid_domains = array(
    'cafcass.gsi.gov.uk',
    'ccrc.x.gsi.gov.uk',
    'cica.gsi.gov.uk',
    'cjs.gsi.gov.uk',
    'crowncommercial.gov.uk',
    'digital.justice.gov.uk',
    'hmcourts-service.gsi.gov.uk',
    'hmcts.gsi.gov.uk',
    'hmiprisons.gsi.gov.uk',
    'hmiprobation.gsi.gov.uk',
    'hmps.gsi.gov.uk',
    'homeoffice.gsi.gov.uk',
    'ips.gsi.gov.uk',
    'jac.gsi.gov.uk',
    'jaco.gsi.gov.uk',
    'judiciary.gsi.gov.uk',
    'justice.gov.uk',
    'justice.gsi.gov.uk',
    'lawcommission.gsi.gov.uk',
    'legalaid.gsi.gov.uk',
    'legalombudsman.org.uk',
    'legalservicesboard.org.uk',
    'noms.gsi.gov.uk',
    'offsol.gsi.gov.uk',
    'paroleboard.gsi.gov.uk',
    'ppo.gsi.gov.uk',
    'probation.gsi.gov.uk',
    'publicguardian.gsi.gov.uk',
    'sentencingcouncil.gsi.gov.uk',
    'yjb.gsi.gov.uk',
);

function is_gov_email($email) {
    $parts = explode('@', $email);
    $domain = $parts[1];

    return in_array($domain, $valid_domains);
}

function convert_to_time_ago( $date, $d, $comment ) {

    return human_time_diff( get_comment_time( 'U' ), current_time('timestamp') ) . ' ago';

}
add_filter( 'get_comment_date', 'convert_to_time_ago', 10,3 );

function remove_comment_website_field($fields) { 
    unset($fields['url']);
    return $fields;
}
add_filter('comment_form_default_fields','remove_comment_website_field');

function remove_must_be_logged_in($fields){
    $fields['must_log_in'] = sprintf( 
        __( '<p class="must-log-in">
                You must <a href="%s">Register</a> or 
            <a href="%s">Login</a> to post a comment.</p>' 
        ),
        wp_registration_url(),
        wp_login_url( apply_filters( 'the_permalink', get_permalink() ) )   
    );
    return $fields;
}
add_filter('comment_form_defaults', 'remove_must_be_logged_in');

// Allow Registration Only from gov email addresses
function is_valid_email_domain($login, $email, $errors ){
    $valid_domains = array(
        'cafcass.gsi.gov.uk',
        'ccrc.x.gsi.gov.uk',
        'cica.gsi.gov.uk',
        'cjs.gsi.gov.uk',
        'crowncommercial.gov.uk',
        'digital.justice.gov.uk',
        'hmcourts-service.gsi.gov.uk',
        'hmcts.gsi.gov.uk',
        'hmiprisons.gsi.gov.uk',
        'hmiprobation.gsi.gov.uk',
        'hmps.gsi.gov.uk',
        'homeoffice.gsi.gov.uk',
        'ips.gsi.gov.uk',
        'jac.gsi.gov.uk',
        'jaco.gsi.gov.uk',
        'judiciary.gsi.gov.uk',
        'justice.gov.uk',
        'justice.gsi.gov.uk',
        'lawcommission.gsi.gov.uk',
        'legalaid.gsi.gov.uk',
        'legalombudsman.org.uk',
        'legalservicesboard.org.uk',
        'noms.gsi.gov.uk',
        'offsol.gsi.gov.uk',
        'paroleboard.gsi.gov.uk',
        'ppo.gsi.gov.uk',
        'probation.gsi.gov.uk',
        'publicguardian.gsi.gov.uk',
        'sentencingcouncil.gsi.gov.uk',
        'yjb.gsi.gov.uk',
        'gmail.com',
    );
    $valid = false; // sets default validation to false
    foreach( $valid_domains as $d ){
    $d_length = strlen( $d );
    $current_email_domain = strtolower( substr( $email, -($d_length), $d_length));
        if( $current_email_domain == strtolower($d) ){
            $valid = true;
            break;
        }
    }
    // Return error message for invalid domains
    if( $valid === false ){
        $errors->add('domain_whitelist_error',__( '<strong>ERROR</strong>: Registration is only allowed from gov emails. If you think you are seeing this in error, please contact the system administrator.' ));
    }
}
add_action('register_post', 'is_valid_email_domain',10,3 );

function format_comment($comment, $args, $depth) {

       $GLOBALS['comment'] = $comment; ?>

        <li <?php comment_class(); ?> id="li-comment-<?php comment_ID() ?>">
            <div class="comment-body">
				<div class="comment-author vcard">
                    <cite class="fn">
                        <span class="author"><?php printf(__('%s'), get_comment_author_link()) ?></span>
                        <span class="dash">—</span>
                        <span class="date"><?php printf(__('%1$s'), get_comment_date(), get_comment_time()) ?></span>
                    </cite>
                    <?php comment_text(); ?>

                    <div class="reply">
                        <?php
                            $replyorlogin = '<p class="must-log-in"><a href="'.wp_login_url().'">Login</a> or 
                <a href="'.wp_registration_url().'">Register</a>
             to post a comment.</p>'
                            
                        ?>
                        <?php comment_reply_link( array_merge( $args, 
                            array(
                                'depth' => $depth, 
                                'max_depth' => $args['max_depth'],
                                'login_text' =>  $replyorlogin,
                            ))
                        ) ?>
                    </div>
                    <?php echo do_shortcode('[likebutton]'); ?>
			</div>

        <?php
}

function format_comment_closed($comment, $args, $depth)
{
   $GLOBALS['comment'] = $comment; ?>
    <li <?php comment_class(); ?> id="li-comment-<?php comment_ID() ?>">

    <div id="div-comment-8741" class="comment-body">
		<div class="comment-author vcard">
        <cite class="fn">
            <span class="author"><?php printf(__('%s'), get_comment_author_link()) ?></span>
            <span class="dash">—</span>
            <span class="date"><?php printf(__('%1$s'), get_comment_date(), get_comment_time()) ?></span>
        </cite>
        <?php comment_text(); ?>
	  </div>
    <?php echo do_shortcode('[likebutton]'); ?>
    <?php
}
add_action('after_password_reset', 'after_password_reset_redirect');
