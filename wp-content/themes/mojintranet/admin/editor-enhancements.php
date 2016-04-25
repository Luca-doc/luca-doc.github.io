<?php

/* Dynamic filtering of Parent pages */


add_action('wp_ajax_check_parent', 'pageparent_ajax_check_parent');
function pageparent_ajax_check_parent() {
  global $wpdb;

  $context = Agency_Context::get_agency_context();

  $filter_data = $_POST['data'];
  $filter_text = sanitize_text_field($filter_data["filtertext"]);
  $current_page = intval($filter_data["pageID"]);


  $parent_query = "SELECT ID,post_title,post_parent,post_type,post_status FROM $wpdb->posts 
                   LEFT JOIN $wpdb->term_relationships ON ( $wpdb->posts.ID = $wpdb->term_relationships.object_id )
                   LEFT JOIN $wpdb->term_taxonomy ON ( $wpdb->term_relationships.term_taxonomy_id = $wpdb->term_taxonomy.term_taxonomy_id )
                   LEFT JOIN $wpdb->terms ON ( $wpdb->term_taxonomy.term_id = $wpdb->terms.term_id ) 
                   WHERE post_title LIKE '%%%s%%'
                   AND $wpdb->posts.ID != %s 
                   AND post_type = 'page' 
                   AND post_status IN ('publish','draft') 
                   AND $wpdb->term_taxonomy.taxonomy = 'agency' 
                   AND $wpdb->terms.slug IN ( 'hq', '%s' ) 
                   GROUP BY $wpdb->posts.ID
                   ORDER BY post_title LIMIT 0,30";

  $parentname = $wpdb->get_results( $wpdb->prepare($parent_query, array($filter_text, $current_page, $context)));
  if($parentname) {
    foreach ($parentname as $parent) {
      $parent_title = get_the_title($parent->post_parent);
      if ($parent_title!='') {
        $parent_title = $parent_title."&nbsp;>><br>";
      }
      $statecheck=get_post($parent->post_parent);
      $parent_state = get_the_title($statecheck->post_parent);
      if ($parent_state!='') {
        $parent_state = $parent_state."&nbsp;> ";
      }
      $page_status = '';
      if($parent->post_status == 'draft'){
        $page_status = ' (Draft)';
      }
      echo "<li class='pageparentoption'>
        <a class=\"parentlink\" style=\"cursor:pointer;\" parentname='".$parent->post_title . "' parentid='" . $parent->ID . "'>
          <small>".
            $parent_state." ".$parent_title."
          </small> ".
          $parent->post_title . $page_status . "
        </a>
      </li>\n";
    }
    echo '<script language="javascript" type="text/javascript">
        jQuery(".parentlink").bind(\'click\', function() {
          var parentid = jQuery(this).attr(\'parentid\');
          var parentname = jQuery(this).attr(\'parentname\');
          jQuery(this).css(\'font-weight\',900);
          jQuery(".parentlink").parent(\'li\').hide("slow");
          jQuery(this).parent(\'.pageparentoption\').show();
          jQuery("#pageparent-filterbox").val(parentname);
          jQuery("#parent_id").val(parentid);
        });
    </script>';
    wp_die();
  } else {
    echo "<p>No matching pages found</p>";
    wp_die();
  }
}

add_action('admin_menu', 'pageparent_add_theme_box');
function pageparent_add_theme_box() {
  if ( ! is_admin() )
    return;
  add_meta_box('pageparent-metabox', __('Parent Page'), 'pageparent_box', 'page', 'side', 'core');
}

function pageparent_box($post) {
  echo '<input type="hidden" name="taxonomy_noncename" id="taxonomy_noncename" value="' . wp_create_nonce( 'taxonomy_theme' ) . '"/>';

  //get current parent
  global $post;
  $load_image_url =  get_template_directory_uri() . '/admin/images/pageparent.gif';
  $parent_page = wp_get_post_parent_id($post->ID);
  $restricted_templates = array('page_about_us.php', 'page_blog.php','page_events.php', 'page_home.php' );

  //populate template list
  $current_template = get_post_meta($post->ID,'_wp_page_template',true);
  $template_file = str_replace('.php','',$current_template);

  $disabled = '';
  if(in_array($current_template, $restricted_templates) && !current_user_can('administrator')){
    $disabled = 'disabled="disabled"';
  }

  $themeselect = '<select id="page_template" name="page_template" ' . $disabled . '>
          <option value="default">Default Template</option>';
  $templates = get_page_templates();
  foreach ( $templates as $template_name => $template_filename ) {
    if(!in_array($template_filename, $restricted_templates) || $current_template == $template_filename || current_user_can('administrator')) {
      $select = $current_template == $template_filename ? 'selected="selected"' : "";
      $themeselect .= '<option value="' . $template_filename . '" ' . $select . '>' . $template_name . '</option>';
    }
  }
  $themeselect.= '</select>';

  ?>
  <p><strong>Current Template:</strong></p>
  <?php echo $themeselect;?>
  <p><strong>Current Parent:</strong></p>

    <div>
      <?php

      if ($parent_page) {
        echo get_the_title($parent_page);
      }
      else {
        echo 'None';
      }
      ?>
    </div>

  <p><strong>New Parent Page:</strong></p>
  <input type="text" name="pageparent-filterbox" id="pageparent-filterbox" autocomplete="off" placeholder="Start typing...">
  <input type="hidden" name="parent_id" id="parent_id" readonly="readonly" value="<?php echo $post->post_parent; ?>">
  <div id="pageparent-result"></div>

  <script language="javascript" type="text/javascript">
    jQuery(document).ready(function() {
      var timer;

      var checkparent = function () {
        jQuery.post(
          ajaxurl,
          {
             'action': 'check_parent',
             'data'  : { filtertext: jQuery("#pageparent-filterbox").val() , pageID: <?php echo $post->ID; ?> }
          }
        ).done( function(response) {
          if(response.length) {
            jQuery( "#pageparent-result" ).empty().append(response);
          } else {
            jQuery( "#pageparent-result" ).empty().append("No matching pages found");
          }
        })
      };

      var updateResults = function() {
        jQuery( "#pageparent-result" ).empty().append( '<img src="<?php echo $load_image_url; ?>" alt="" class="loading">');
        timer && clearTimeout(timer);
        timer = setTimeout(checkparent, 250);
      };

      jQuery("#pageparent-filterbox").on('keypress',function() {
        updateResults();
      }).on('keydown', function(e) {
         if (e.keyCode==8) updateResults();
      });

      jQuery(".parentlink").click(function() {
        var parentid = jQuery(this).attr('parentid');
        var parentname = jQuery(this).attr('parentname');
        jQuery("#pageparent-filterbox").val(parentname);
        jQuery("#parent_id").val(parentid);
      });
    });
  </script>

<?php
}

add_action('admin_menu', 'pageparent_remove_theme_box');
function pageparent_remove_theme_box() {
  // Remove default parent metabox
  if ( ! is_admin() )
    return;
  remove_meta_box('pageparentdiv', 'page', 'side');
}
