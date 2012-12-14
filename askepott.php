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

add_option('askepott_redirect_page', 'homepage');
add_option('askepott_exclude_directory', 'allow');
add_option('askepott_exclude_queries', 'allow');
add_option('askepott_exclude_terms', 'allow');
add_option('askepott_exclude_spaces', 'allow');
add_option('askepott_exclude_file', 'allow');
add_option('askepott_exclude_http', 'disallow');
add_option('askepott_email_enable', 'enable');
add_option('askepott_email_type', 'html');
add_option('askepott_email_address', get_option('admin_email'));
add_option('askepott_whitelisted_ip', 
			serialize(array('0' => $_SERVER['REMOTE_ADDR']))
);
add_option('askepott_whitelisted_page', '');
add_option('askepott_whitelisted_variable', '');
add_option('askepott_plugin_url', get_option('siteurl') . '/wp-admin/options-general.php?page=' . basename(__FILE__));
add_option('askepott_default_whitelisted_page', 
	serialize(
		array(
			array(
				'.*/wp-comments-post\.php',
				array('url', 'comment')
			),
			array(
				'.*/wp-admin/.*',
				array(
					'_wp_original_http_referer',
					'_wp_http_referer'
				)
			),
			array(
				'.*wp-login.php',
				array('redirect_to')
			),
			array(
				'.*',
				array(
					'comment_author_url_.*',
					'__utmz'
				)
			),
			'.*/wp-admin/options-general\.php',
			'.*/wp-admin/post-new\.php',
			'.*/wp-admin/page-new\.php',
			'.*/wp-admin/link-add\.php',
			'.*/wp-admin/post\.php',
			'.*/wp-admin/page\.php',
			'.*/wp-admin/admin-ajax.php'
		)
	)
);
add_option('askepott_previous_attack_var', '');
add_option('askepott_previous_attack_ip', '');
add_option('askepott_email_limit', 'off');

if (!function_exists('array_diff_key')) {
    function array_diff_key()
    {
        $args = func_get_args();
        if (count($args) < 2) {
            user_error('Wrong parameter count for array_diff_key()', E_USER_WARNING);
            return;
        }
        $array_count = count($args);
        for ($i = 0; $i !== $array_count; $i++) {
            if (!is_array($args[$i])) {
                user_error('array_diff_key() Argument #' .
                    ($i + 1) . ' is not an array', E_USER_WARNING);
                return;
            }
        }
        $result = $args[0];
        foreach ($args[0] as $key1 => $value1) {
            for ($i = 1; $i !== $array_count; $i++) {
                foreach ($args[$i] as $key2 => $value2) {
                    if ((string) $key1 === (string) $key2) {
                        unset($result[$key2]);
                        break 2;
                    }
                }
            }
        }
        return $result;
    }
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
    foreach(unserialize(get_option('askepott_default_whitelisted_page')) as $whitelisted_page) {
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
    $pages = unserialize(get_option('askepott_whitelisted_page'));
    $variables = unserialize(get_option('askepott_whitelisted_variable'));
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
	return $new_arr;
        
}

function askepott_check_ip_whitelist() {
	$current_ip = $_SERVER['REMOTE_ADDR'];
	$ips = unserialize(get_option('askepott_whitelisted_ip'));
	if(is_array($ips)) {
		foreach($ips as $ip) {
			if(($current_ip == $ip) || ($current_ip == gethostbyname($ip))) {
				return true;
			}
		}
	}
	return false;
}

function askepottl_send_log_message($bad_variable = '', $bad_value = '', $attack_type = '', $attack_category = '') {
	$bad_variable = htmlentities($bad_variable);
	$bad_value = htmlentities($bad_value);
	$offender_ip = $_SERVER['REMOTE_ADDR'];
	// Missing Stuff
}

function askepott_send_redirect() {
	$home_url = get_option('siteurl');
	if(get_option('askepott_redirect_page') == '404page') {
		// Not clear if just including the 404 template is safe.
		// Not sure why it wouldn't be safe, but better safe than sorry...?
		// 404 could contain errors relaying info which could be useful to attacker...?
		header ("Location: $home_url/404/");
		exit();
	} else {
		header ("Location: $home_url");
		exit();
	}
}

function askepott_check_attack_types() {
    $request_string = askepott_get_request();
    if($request_string == false) {
        // Nothing to do, all white listed
    } else {
        // Directory traversal - check directories
        if(get_option('askepott_exclude_directory') == 'allow') {
            $exclude_terms = array('#etc/passwd#', '#proc/self/environ#', '#\.\./#');
            foreach($exclude_terms as $preg) {
                foreach($request_string as $key=>$value) {
                    if(preg_match($preg, $value)) {
                        if(!askepott_check_ip_whitelist()) {
                            askepottl_send_log_message($key, $value, 'directory-traversal-attack', 'Directory Traversal');
                            askepott_send_redirect();
                        }
                    }
                }
            }
        }
		// SQL injection - check queries
		if(get_option('askepott_exclude_queries') == 'allow') {
			$exclude_terms = array('#concat\s*\(#i', '#group_concat#i', '#union.*select#i');
			foreach($exclude_terms as $preg) {
				foreach($request_string as $key=>$value) {
					if(preg_match($preg, $value)) {
						if(!askepott_check_ip_whitelist()) {
							askepottl_send_log_message($key, $value, 'sql-injection-attack', 'SQL Injection');
							askepott_send_redirect();
						}
					}
				}
			}
		}
		// WP SQL injection - check wp terms
		if(get_option('askepott_exclude_terms') == 'allow') {
			$exclude_terms = array('#wp_#i', '#user_login#i', '#user_pass#i', '#0x[0-9a-f][0-9a-f]#i', '#/\*\*/#');
			foreach($exclude_terms as $preg) {
				foreach($request_string as $key=>$value) {
					if(preg_match($preg, $value)) {
						if(!askepott_check_ip_whitelist()) {
							askepottl_send_log_message($key, $value, 'wp-specific-sql-injection-attack', 'WordPress-Specific SQL Injection');
							askepott_send_redirect();
						}
					}
				}
			}
		}
		// Field truncation - check ... not sure yet
		if(get_option('askepott_exclude_spaces') == 'allow') {
			$exclude_terms = array('#\s{49,}#i','#\x00#');
			foreach($exclude_terms as $preg) {
				foreach($request_string as $key=>$value) {
					if(preg_match('#\s{49,}#i', $value)) {
						if(!askepott_check_ip_whitelist()) {
							askepottl_send_log_message($key, $value, 'field-truncation-attack', 'Field Truncation');
							askepott_send_redirect();
						}
					}
				}
			}
		}
		// Block executable file upload - check exluded file types
		if(get_option('askepott_exclude_file') == 'allow') {
			foreach ($_FILES as $file) {
				$file_extensions = 
					array(
						'#\.dll$#i', '#\.rb$#i', '#\.py$#i', '#\.exe$#i', '#\.php[3-6]?$#i', '#\.pl$#i', 
						'#\.perl$#i', '#\.ph[34]$#i', '#\.phl$#i', '#\.phtml$#i', '#\.phtm$#i'
					);
				 foreach($file_extensions as $regex) {
					if(preg_match($regex, $file['name'])) {
						// no ip check, should there be one?
				 		askepottl_send_log_message('$_FILE', $file['name'], 'executable-file-upload-attack', 'Executable File Upload');
						askepott_send_redirect();	
					}
				 }
			}
		}
		// Block remote file execution - check for leading http/https
		// This can be problematic with many plugins, as it'll break requests
		// starting with http/https, however, may be still be useful
		if(get_option('askepott_exclude_http') == 'allow') {
			$exclude_terms = array('#^http#i', '#\.shtml#i');
			foreach($exclude_terms as $preg) {
				foreach($request_string as $key=>$value) {
					if(preg_match($preg, $value)) {
						if(!askepott_check_ip_whitelist()) {
							askepottl_send_log_message($key, $value, 'remote-file-execution-attack', 'Remote File Execution');
							askepott_send_redirect();
						}
					}
				}
			}
		}
    }
}

askepott_check_attack_types();    

function askepott_assert_first() {
	$active_plugs = (get_option('active_plugins'));
	$active_plugs = array_diff($active_plugs, array("askepott.php"));
	array_unshift($active_plugs, "askepott.php");
}

function askepott_admin_menu() {
	add_submenu_page('options-general.php', 'Askepott', 'Askepott', 10, __FILE__, 'askepott_submenu');
}

add_action('admin_menu', 'askepott_admin_menu');

function add_settings_link($links, $file) {
	static $this_plugin;
	if(!$this_plugin) {
		$this_plugin = plugin_basename(__FILE__);
	}

	if($file == $this_plugin) {
		$settings_link = '<a href="options-general.php?page=' . $this_plugin . '">' . __("Settings", "askeputt") . '</a>';
		array_unshift($links, $settings_link);
	}
	return $links;
}

add_filter('plugin_action_links', 'add_settings_link', 10, 2);

function askepott_submenu() {
	askepott_assert_first();
	
	$action_url = $_SERVER['REQUEST_URI'];
	if ($_REQUEST['set_exclusions']) {
		update_option('askepott_redirect_page', $_REQUEST['redirect_type']);
		update_option('askepott_exclude_directory', $_REQUEST['block_directory']);
		update_option('askepott_exclude_queries', $_REQUEST['block_queries']);
		update_option('askepott_exclude_terms', $_REQUEST['block_terms']);
		update_option('askepott_exclude_spaces', $_REQUEST['block_spaces']);
		update_option('askepott_exclude_file', $_REQUEST['block_file']);
		update_option('askepott_exclude_http', $_REQUEST['block_http']);
		echo '<div class="updated fade"><p>Security Filters and Redirect page updated.</p></div>';
		
	} elseif($_REQUEST['turn_off_email']) {
		update_option('askepott_email_address', '');
		$action_url = str_replace('&turn_off_email=1', '', $_SERVER['REQUEST_URI']);
		echo '<div class="updated fade"><p>Emails are now turned off.</p></div>';
		
	} elseif($_REQUEST['set_whitelist_variable']) {
		echo '<div class="updated fade"><p>Whitelisted ' . $_REQUEST['set_whitelist_variable'] . '</p></div>';
		$pages = unserialize(get_option('askepott_whitelisted_page'));
		$variables = unserialize(get_option('askepott_whitelisted_variable'));
		$pages[] = '';
		$variables[] = $_REQUEST['set_whitelist_variable'];
		update_option('askepott_whitelisted_page', serialize($pages));
		update_option('askepott_whitelisted_variable', serialize($variables));
		$action_url = str_replace(('&set_whitelist_variable=' . $_REQUEST['set_whitelist_variable']), '', $_SERVER['REQUEST_URI']);
		echo '<div class="updated fade"><p>Whitelisted Variable set.</p></div>';
		
	} elseif($_REQUEST['set_email']) {
		update_option('askepott_email_address', $_REQUEST['email_address']);
		update_option('askepott_email_limit', $_REQUEST['email_limit']);
		update_option('askepott_email_type', $_REQUEST['email_type']);
		echo '<div class="updated fade"><p>Email settings updated.</p></div>';
		
	} elseif($_REQUEST['set_whitelist_ip']) {
		update_option('askepott_whitelisted_ip', serialize($_REQUEST['whitelisted_ip']));
		echo '<div class="updated fade"><p>Whitelisted IP set.</p></div>';
		
	} elseif($_REQUEST['set_whitelist_page']) {
		update_option('askepott_whitelisted_page', serialize($_REQUEST['whitelist_page']));
		update_option('askepott_whitelisted_variable', serialize($_REQUEST['whitelist_variable']));
		echo '<div class="updated fade"><p>Whitelisted Page set.</p></div>';
		
	} elseif($_REQUEST['suppress'] === '0') {
		update_option('askepott_email_limit', 'off');
		echo '<div class="updated fade"><p>Email limit set.</p></div>';
		$action_url = str_replace('&suppress=0', '', $_SERVER['REQUEST_URI']);
	}
	?>
	<div class="wrap">
		<div id="icon-tools" class="icon32"></div>
		<h2>Firewall Options:</h2>
			<form name="set-exclusion-options" action="<?php echo $action_url; ?>" method="post" class="widefat" style="padding:0 0 20px; margin:20px 0 0;">
			<div style="padding:0 20px;">
				<h3>Apply Security Filters:</h3>
				<p><input type="checkbox" value="allow" name="block_directory" <?php echo (get_option('askepott_exclude_directory') == 'allow') ? 'checked="checked"' : '' ?> /> Block directory traversals (../, ../../etc/passwd, etc.) in application parameters.</p>
				<p><input type="checkbox" value="allow" name="block_queries" <?php echo (get_option('askepott_exclude_queries') == 'allow') ? 'checked="checked"' : '' ?> /> Block SQL queries (union select, concat(, /**/, etc.) in application parameters.</p>
				<p><input type="checkbox" value="allow" name="block_terms" <?php echo (get_option('askepott_exclude_terms') == 'allow') ? 'checked="checked"' : ''?> /> Block WordPress specific terms (wp_, user_login, etc.) in application parameters.</p>
				<p><input type="checkbox" value="allow" name="block_spaces" <?php echo (get_option('askepott_exclude_spaces') == 'allow') ? 'checked="checked"' : '' ?> /> Block field truncation attacks in application parameters.</p>
				<p><input type="checkbox" value="allow" name="block_file" <?php echo (get_option('askepott_exclude_file') == 'allow') ? 'checked="checked"' : '' ?> /> Block executable file uploads (.php, .exe, etc.)</p>
				<p><input type="checkbox" value="allow" name="block_http" <?php echo (get_option('askepott_exclude_http') == 'allow') ? 'checked="checked"' : '' ?> /> Block leading http:// and https:// in application parameters (<em>off</em> by default; may cause problems with many plugins).</p>
				
				<h4>Upon Detecting Attack:</h4>
				<table border="0" cellpadding="0" cellspacing="0" style="width:260px; margin-top:0; padding:0;">
					<tr>
						<td><strong>Show 404 Error Page:</strong></td>
						<td><input type="radio" name="redirect_type" value="404page" <?php echo (get_option('askepott_redirect_page') == '404page') ? 'checked="checked"' : '' ?> /></td>
					</tr>
					<tr>
						<td><strong>Redirect To Homepage:</strong></td>
						<td><input type="radio" name="redirect_type" value="homepage" <?php echo (get_option('askepott_redirect_page') == 'homepage') ? 'checked="checked"' : '' ?> /></td>
					</tr>
				</table>
				<p style="margin-top:5px;"><small><em>Note: All filters are subject to "Whitelisted IPs" and "Whitelisted Pages" below.</em></small></p>
				<input type="submit" name="set_exclusions" value="Set Security Filters" class="button-secondary" />
			</div>
			</form>
			
			
			<form name="email_address" action="<?php echo $action_url; ?>" method="post" class="widefat" style="padding:0 0 20px; margin:20px 0 0;">
			<div style="padding:0 20px;">
				<h3>Email:</h3>
				<p><strong>Enter an email address for attack reports:</strong></p>
				<input type="text" value="<?php echo get_option('askepott_email_address') ?>" name="email_address" />
				<p style="margin-top:5px;"><small><em>Note: Leave this setting blank to disable emails.</em></small></p>
				<p><strong>Email type:</strong> <input type="radio" name="email_type" value="html"<?php echo (get_option('askepott_email_type') == 'html') ? 'checked="checked"' : '' ?> />html <input type="radio" name="email_type" value="text" <?php echo (get_option('askepott_email_type') == 'text') ? 'checked="checked"' : '' ?> />text</p>
				<p><strong>Suppress similar attack warning emails:</strong> <input type="radio" name="email_limit" value="on"<?php echo (get_option('askepott_email_limit') == 'on') ? 'checked="checked"' : '' ?> />On <input type="radio" name="email_limit" value="off" <?php echo (get_option('askepott_email_limit') == 'off') ? 'checked="checked"' : '' ?> />Off</p>
				<input type="submit" name="set_email" value="Set Email"  class="button-secondary" />
			</div>
			</form>
			
			<form name="whitelist_ip" action="<?php echo $action_url; ?>" method="post" class="widefat" style="padding:0 0 20px; margin:20px 0 0;">
			<div style="padding:0 20px;">
				<h3>Whitelisted IPs:</h3>
				<p>Enter IP(s) that are whitelisted &mdash; and not subject to security rules.</p>
				<?php
					if( !get_option('askepott_whitelisted_ip')) {
						echo '<input type="text" value="" name="whitelisted_ip[]" /><br />';
					} else {
						//$ips = array_unique( unserialize(get_option('askepott_whitelisted_ip')) );
						$ips_options = get_option('askepott_whitelisted_ip');
						$ips_options_unserialized = unserialize($ips_options);
						
						// Check to see if data needs to be unserialzed or not
						if($ips_options_unserialized !== FALSE) {
							$ips = array_unique($ips_options_unserialized);
							foreach($ips as $ip){
								if($ip != '') {
									echo '<input type="text" value="' . $ip . '" name="whitelisted_ip[]" /><br />';
								}
							}
						} else {
							$ips = array_unique($ips_options);
							foreach($ips as $ip) {
								if($ip != '') {
									echo '<input type="text" value="' . $ip . '" name="whitelisted_ip[]" /><br />';
								}
							}
						}
						echo  '<input type="text" value="" name="whitelisted_ip[]" /><br />';
					}
				?>
				<p style="margin-top:5px;"><small><em>Note: Set field(s) to blank to disable IP whitelist. Your current IP is: <strong><?php echo $_SERVER['REMOTE_ADDR']?></strong>.</em></small></p>
				<input type="submit" name="set_whitelist_ip" value="Set Whitelisted IPs" class="button-secondary" />
			</div>
			</form>
			
			<form name="whitelist_page_or_variable" action="<?php echo $action_url; ?>" method="post" class="widefat" style="padding:0 0 20px; margin:20px 0 0;">
			<div style="padding:0 20px;">
				<h3>Whitelisted Pages:</h3>
				<p>Enter page and/or form variables that are whitelisted &mdash; and not subject to security rules:</p>
				<table cellspacing="0" cellpadding="0" border="0">
					<tr>
						<td><strong>Page:</strong></td>
						<td><strong>Form Variable:</strong></td>
					</tr>
					<?php
					//!unserialize(get_option('askepott_whitelisted_page')) && !unserialize(get_option('askepott_whitelisted_variable'))
					$whitelist_pages = get_option('askepott_whitelisted_page');
					$whitelist_variables = get_option('askepott_whitelisted_variable');
					$whitelist_pages_unserialized = unserialize($whitelist_pages);
					$whitelist_variables_unserialized = unserialize($whitelist_variables);
					
					if(($whitelist_pages == '') && ($whitelist_variables == '')) {
						echo '<tr><td><input type="text" name="whitelist_page[]" /></td>';
						echo '<td><input type="text" name="whitelist_variable[]" /></td></tr>';
					} else {
						//$pages = unserialize(get_option('askepott_whitelisted_page'));
						//$variables = unserialize(get_option('askepott_whitelisted_variable'));
						if(($whitelist_pages_unserialized !== FALSE) && ($whitelist_pages_unserialized !== FALSE)) {
							$pages = $whitelist_pages_unserialized;
							$variables = $whitelist_variables_unserialized;
							$count = 0;
							while($count < sizeof($pages)) {
								if(($pages[$count] != '') || ($variables[$count] != '')) {
									echo '<tr><td><input type="text" value="'. $pages[$count] . '" name="whitelist_page[]" /></td>';
									echo '<td><input type="text" value="' . $variables[$count] . '" name="whitelist_variable[]" /></td></tr>';
								}
								$count++;
							}
						} else {
							$pages = $whitelist_pages;
							$variables = $whitelist_variables;
							$count = 0;
							while($count < sizeof($pages)) {
								if(($pages[$count] != '') || ($variables[$count] != '')) {
									echo '<tr><td><input type="text" value="'. $pages[$count] . '" name="whitelist_page[]" /></td>';
									echo '<td><input type="text" value="' . $variables[$count] . '" name="whitelist_variable[]" /></td></tr>';
								}
								$count++;
							}
						}
						echo '<tr><td><input type="text" name="whitelist_page[]" /></td>';
						echo '<td><input type="text" name="whitelist_variable[]" /></td></tr>';
					}
					?>
				</table>
				<p style="margin-top:5px;"><small><em>Note: Set field(s) to blank to disable page whitelist.<br />Note: Use *'s for wildcard characters.</em></small></p>
				<input type="submit" name="set_whitelist_page" value="Set Whitelisted Pages" class="button-secondary" />
			</div>
			</form>
				
		<?php askepott_show_plugin_link(); ?>
	</div>
<?php
}

function askepott_show_plugin_link() { ?>
	<div style="margin:30px 0 20px; text-align:right;">
		<small>Modifications to this plugin by <a href="http://matthewpavkov.com" target="_blank">Matthew Pavkov</a>.<br />Please use the <a href="http://wordpress.org/tags/wordpress-firewall-2?forum_id=10" target="_blank">Wordpress Plugin Forum</a> to report bugs, suggestions, etc.</small>
		<br /><br />
		<small>Original plugin by <a href="http://www.seoegghead.com/software/" target="_blank">SEO Egghead</a>.</small>
		<!--
		<a href="http://www.seoegghead.com/software/wordpress-firewall.seo" style="text-decoration:none;" target="_blank">
		<?php if(preg_match('#MSIE#', $_SERVER['HTTP_USER_AGENT']) == 0) { ?>
			<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAUCAMAAA
			BxjAnBAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAADBQTFRFz6Ol
			opmRs21w48/P+Pb218bF9Orr6OTit7CpqVpdqaGZrmJlvYCD0ry769vc////wFM5SwAAAB
			B0Uk5T////////////////////AOAjXRkAAAJLSURBVHjatFXtDiMhCERF3Q/R93/bGxDX
			Xu5Pr2lJNk7pVHQYujS+FImov09Ng75VmM4zvU+V7xVu583vU7sVZo/CG7+kDRcL27qs4J
			VWfJ+N/+GMzdi7cAQVhfm4PEJlcXjUkVf64CHxtogySnN8N64Ppn6erc10Gd3zERQn3DGN
			ZIQGKq5LQ8ITnB+Y6073dK5oTBtDsxWUH3gmXGlF33nytFIFhfkKV68avSpOQDhLwhmk9t
			6vECoKUEpJtHA8bwFWg5T7jHlifZSSsXnBORtwArWWZIEdREUBvYAK/1MJ4bC6aAhumRkQ
			ResRLusW1oKmDJxBj1pMJ3OmCiET36Wdkadxon1XwNcc6+G76tTFfT+ptCWVkVAwGb7qFQ
			5lQYRDm1JdRhTPy8Tz6EPNUvVsaqpoHbh5dqEVW+e5QC9KuY1KnK+nxTKfoCLg8rqTrmkW
			xAZ/FfOjDxWhuxC2RuuI0oXcGTNldKfSGhuVVh8PXNz+iHS1Yj4Ubf+a/ZaquLgQKqd1w8
			cIxSrGFHqR33Q4lbIHJIWsQeYn9fqBVWA3lauRBWNcb6ymOAootnO5jNregu/ipCfQDWIH
			1c2wWk6Ze2oSP/CApx78Mh3McxXzj7cdLa0uo8qpV/KQsoes7Jk0Kh0rEvR98CjiMDMG3w
			MKioFqhqWJo3qoWYtt9TyiD1mw8U7Psfjoj5m9X2Ob5b9fKp+9A1+KiU/zbwvn6ZqozpQH
			958X3j6Ly2c2pj8vXB5/VLyCFi7j9zeWGQSvF/IP6ZMLjz8CDACmemOuUH7ZzQAAAABJRU
			5ErkJggg==" alt="" />
		<?php } ?>
		<br />
		<small>Click here for plugin documentation.</small>
		</a><br />
		<small>Got Questions or Feedback? <a style="text-decoration:none;" href="http://www.seoegghead.com/about/contact-us.seo?subject=WP+Firewall+Feedback" target="_blank">Click here.</a></small>
		<br />
		<small>By using this plugin you agree to <a style="text-decoration:none;" href="http://www.seoegghead.com/software/free-software-disclaimer.seo" target="_blank">this simple disclaimer</a>.</small>
		-->
	</div>
<?php } ?>