<?php
function dw_redirects()
{
    $path = $_SERVER['REQUEST_URI'];

    //Search form -> search results page
    if (isset($_POST['s']) || isset($_POST['search-filter'])) {
        $keywords = $_POST['s'] ?: '-';
        $keywords = rawurlencode(stripslashes($keywords));
        $keywords = str_replace('%2F', '%252F', $keywords);
        $keywords = str_replace('%5C', '%255C', $keywords);
        $filter = $_POST['search-filter'] ?: 'all';

        header('Location: ' . home_url() . '/search-results/' . $filter . '/' . $keywords . '/1/');
        exit;
    } elseif (preg_match('/\/search\/?$/', $path)) {
        header('Location: ' . home_url());
        exit;
    }

    if (strpos($path, 'guidance-and-support') || strpos($path, 'guidance-support')) {
        $new_path = preg_replace('/^([^?]*)(guidance-and-support|guidance-support)/', '${1}guidance', $path);
        if ($new_path != $path) {
            header('Location: ' . home_url() . $new_path);
            exit;
        }
    }
}

function dw_rewrite_rules()
{
    /**
    Remember!
    If you want "something/" to be accessible (i.e. with trailing slash), make sure to use "/?" in the rule.
    The reason why it is required is unknown, must be colliding with some other rule being applied behind the scenes.
     */

    //register url parameters
    add_rewrite_tag('%search-filter%', '([^&]+)');
    add_rewrite_tag('%search-string%', '([^&]+)');

    //Events page
    $regex = '^events/([0-9]+)(/.*)?';
    $redirect = 'index.php?page_id=' . get_page_by_path('events')->ID;
    add_rewrite_rule($regex, $redirect, 'top');

    //Search results page
    $regex = '^search-results/([^/]*)/([^/]*)/?';
    $redirect = 'index.php?page_id=' . get_page_by_path('search-results')->ID . '&search-filter=$matches[1]&search-string=$matches[2]';
    add_rewrite_rule($regex, $redirect, 'top');

    //Webchat archive page
    $regex = '^webchats/archive/?';
    $redirect = 'index.php?page_id=' . get_page_by_path('webchats/archive')->ID;
    add_rewrite_rule($regex, $redirect, 'top');

    // ping.json
    $regex = '^ping.json';
    $redirect = 'wp-content/themes/mojintranet/ping.php';
    add_rewrite_rule($regex, $redirect, 'top');

    //Custom controllers
    $regex = '^feed($|/)';
    $redirect = 'index.php?controller=page_error';
    add_rewrite_rule($regex, $redirect, 'top');
    //Custom controllers
    $regex = '^(service|flush-rewrites|purge-cache|redirect|submit-feedback|user)(/(.*)|$)';
    $redirect = 'index.php?controller=$matches[1]&param_string=$matches[3]';
    add_rewrite_rule($regex, $redirect, 'top');
}
if (!is_admin()) {
    add_action('init', 'dw_redirects');
}
add_action('init', 'dw_rewrite_rules');


function dw_old_blog_redirect()
{
    if (is_404()) {
        //check for blog redirect
        $post_slug = explode('/', ltrim($_SERVER["REQUEST_URI"], '/'));

        if (isset($post_slug[0])) {
            $post = get_page_by_path($post_slug[0], OBJECT, 'post');

            if (isset($post)) {
                wp_redirect(get_permalink($post->ID), 301);
                die();
            }
        }
    }
}
add_action('dw_redirect', 'dw_old_blog_redirect');
