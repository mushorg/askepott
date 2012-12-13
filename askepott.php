<?php
/*
Plugin Name: askepott
Plugin URI: https://github.com/glastopf/askepott
Description: Wordpress WAF plug-in with some magic
Version: 0.1
Author: Askepott Team
Author URI: https://github.com/glastopf/askepott

Updated: December 13, 2012

    Copyright 2012  Askepott Team (email: glaslos@gmail.com)
	This source file is subject to version 3.0 of the PHP license,
	that is bundled with this package in the file LICENSE, and is
	available at through the world-wide-web at http://www.php.net/license/3_0.txt.
	If you did not receive a copy of the PHP license and are unable
	to obtain it through the world-wide-web, please send a note to
	license@php.net so we can mail you a copy immediately.

Inspired by: http://wordpress.org/extend/plugins/wordpress-firewall-2/
    
*/

// Prevent direct file access to the firewall
if(preg_match("#^askepott.php#", basename($_SERVER['PHP_SELF']))) {
	exit();
}

function askepott_recursive_flatten($array, &$newArray, $prefix='', $delimiter='][', $level=0) {
    foreach($array as $key => $child) {
        if (is_array($child)) {
            $newPrefix = $prefix . $key . $delimiter;
            if($level == 0) {
                $newPrefix = $key . '[';
            }
            $newArray =& askepott_recursive_flatten($child, $newArray, $newPrefix, $delimiter, $level+1);
        } else {
            (!$level) ? $post='' : $post=']';
            $newArray[$prefix . $key . $post] = $child;
        }
    }
    return $newArray;
}

function askepott_check_default_whitelist($page_name, $new_arr) {
    foreach(unserialize(get_option('WP_firewall_default_whitelisted_page')) as $whitelisted_page) {
        if(!is_array($whitelisted_page)) {
            if(preg_match('#^' . $whitelisted_page . '$#', $page_name)) {
                $new_arr = false;
            }
        } else {
            if(preg_match('#^' . $whitelisted_page[0] . '$#', $page_name)) {
                foreach($whitelisted_page[1] as $whitelisted_variable) {
                    foreach(array_keys($new_arr) as $var) {
                        if(preg_match('#^' . $whitelisted_variable . '$#', $var)) {
                            $new_arr = array_diff_key($new_arr,array($var=>''));
                        }
                    }
                }
            }
        }
    }
    return $new_arr;
}

function askepott_check_whitelist($new_arr) {
    $pages = unserialize(get_option('WP_firewall_whitelisted_page'));
    $variables = unserialize(get_option('WP_firewall_whitelisted_variable'));
    $count = 0;
    while($count < sizeof($pages)) {
        $page_regex = preg_quote($pages[$count], '#');
        $page_regex = str_replace('\*', '.*', $page_regex);
        $var_regex = preg_quote($variables[$count], '#');
        $var_regex = str_replace('\*', '.*', $var_regex);
        
        if( $variables[$count] != '') {
            if(($pages[$count] == '') || (preg_match('#^' . $page_regex . '$#', $page_name))) {
                $temp_arr = $new_arr;
                foreach(array_keys($new_arr) as $var) {
                    if(preg_match('#^' . $var_regex . '$#', $var)) {
                        $new_arr = array_diff_key($new_arr, array($var=>''));
                    }
                }
            }
        } elseif($pages[$count] != '') {
            if(preg_match('#^' . $page_regex . '$#', $page_name)) {
                return false;
            }
        }
        $count++;
    }
    return $new_arr;
}

function askepott_get_request() {
        preg_match('#([^?]+)?.*$#', $_SERVER['REQUEST_URI'], $url);
        $page_name = $url[1];
        $_a = array();
        $new_arr = askepott_recursive_flatten($_REQUEST, $_a);
        $new_arr = askepott_check_default_whitelist($page_name, $new_arr);
        if ($new_arr) {
            $new_arr = askepott_check_whitelist($new_arr);
        }
        
}
        
function askepott_check_attack_types() {
    $request_string = askepott_get_request();
    if($request_string == false) {
        // Nothing to do, all white listed
    } else {
        // Directory traversal - check directories
        if(get_option('WP_firewall_exclude_directory') == 'allow') {
            $exclude_terms = array('#etc/passwd#', '#proc/self/environ#', '#\.\./#');
            foreach($exclude_terms as $preg) {
                foreach($request_string as $key=>$value) {
                    if(preg_match($preg, $value)) {
                        if(!WP_firewall_check_ip_whitelist()) {
                            WP_firewall_send_log_message($key, $value, 'directory-traversal-attack', 'Directory Traversal');
                            WP_firewall_send_redirect();
                        }
                    }
                }
            }
        }
    }
}

askepott_check_attack_types();    

?>