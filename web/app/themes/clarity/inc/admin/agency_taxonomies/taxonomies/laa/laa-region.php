<?php

namespace MOJ_Intranet\Taxonomies;

use Agency_Context;

class LAA_Region extends Agency_Taxonomy
{
    protected string $name = 'laa_region';

    protected ?string $agency = 'laa';

    protected array $object_types = array(
        'event',
    );

    protected array $args = array(
        'labels' => array(
            'name' => 'LAA Regions',
            'singular_name' => 'Region',
            'menu_name' => 'LAA Regions',
            'all_items' => 'All Regions',
            'parent_item' => 'Parent Region',
            'parent_item_colon' => 'Parent Region:',
            'new_item_name' => 'New Region Name',
            'add_new_item' => 'Add New Region',
            'edit_item' => 'Edit Region',
            'update_item' => 'Update Region',
            'separate_items_with_commas' => 'Separate Regions with commas',
            'search_items' => 'Search Regions',
            'add_or_remove_items' => 'Add or remove Regions',
            'choose_from_most_used' => 'Choose from the most used Regions',
            'not_found' => 'Not Found',
        ),
        'hierarchical' => true,
        'public' => false,
        'show_ui' => true,
        'show_admin_column' => false,
        'show_in_nav_menus' => false,
        'show_tagcloud' => false,
        'rewrite' => false,
    );
}
