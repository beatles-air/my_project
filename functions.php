<?php

function mtException($exception){
	$msg = 'Exception:' . $exception->getMessage();
	$log_data = "date:" . date("Y-m-d H:i:s") . "||";
	$log_data .= $msg;
	//writeLog($log_data, '500_error');
	echo 'Ooops,system error,Come back later.';
	die();
}

function getCurrentTime() {
	if (!$_SERVER['REQUEST_TIME']) {
		$time = time();
	} else {
		$time = $_SERVER['REQUEST_TIME'];
	}
	return $time;
}

/**
 * Class registry
 *
 * This function acts as a singleton.  If the requested class does not
 * exist it is instantiated and set to a static variable.  If it has
 * previously been instantiated the variable is returned.
 *
 * @access	public
 * @param	string	the class name being requested
 * @param	bool	optional flag that lets classes get loaded but not instantiated
 * @return	object
 */
function &loadClass($class ,$data = null ,$instantiate = TRUE){
	static $objects = array();
	if($data){
		$class_key = md5($class . '_' . md5(serialize($data)));
	}else{
		$class_key = $class;
	}
	// Does the class exist?  If so, we're done...
	if(isset($objects[$class_key])){
		return $objects[$class_key];
	}
	require_once ROOT_PATH . '/libraries/' . $class . '.php';
	
	if($instantiate == FALSE){
		$objects[$class_key] = TRUE;
		return $objects[$class_key];
	}
	
	$name = 'VIP_' . $class;
	if($data){
		$objects[$class_key] = & instantiate_class(new $name($data));
	}else{
		$objects[$class_key] = & instantiate_class(new $name());
	}
	return $objects[$class_key];
}

function &loadModel($class ,$instantiate = TRUE){
	static $models = array();
	
	// Does the class exist?  If so, we're done...
	if(isset($models[$class])){
		return $models[$class];
	}
	require_once ROOT_PATH . '/models/' . $class . '.php';
	if($instantiate == FALSE){
		$models[$class] = TRUE;
		return $models[$class];
	}
	
	$name = $class . '_model';
	$models[$class] = & instantiate_class(new $name());
	return $models[$class];
}

/**
 * Instantiate Class
 *
 * Returns a new class object by reference, used by loadClass() and the DB class.
 * Required to retain PHP 4 compatibility and also not make PHP 5.3 cry.
 *
 * Use: $obj =& instantiate_class(new Foo());
 * 
 * @access	public
 * @param	object
 * @return	object
 */
function &instantiate_class(&$class_object){
	return $class_object;
}

function getCookies($cypher){
	if(!$cypher){
		return array();
	}
	$td = mcrypt_module_open('tripledes', '', 'ecb', '');
	$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
	mcrypt_generic_init($td, SESSION_ENCRYPTION_KEY, $iv);
	$plain_text = rtrim(mdecrypt_generic($td, base64_decode($cypher)), "\0");
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);
	$session_data = unserialize($plain_text);
	return $session_data;
}

function writeCookies($session_data ,$life_time_limit = 1209600){
	if($session_data){
		$arg_str_session_data = serialize($session_data);
		$td = mcrypt_module_open('tripledes', '', 'ecb', '');
		$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		mcrypt_generic_init($td, SESSION_ENCRYPTION_KEY, $iv);
		$cypher = base64_encode(mcrypt_generic($td, $arg_str_session_data));
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
	}else{
		$cypher = '';
	}
	if($life_time_limit){
		$life_time_limit = time() + $life_time_limit;
	}
	
	setcookie(COOKIE_NAME, $cypher, $life_time_limit, "/", COOKIE_DOMAIN);
	return true;
}

function getSession($name=''){//session值存入memcache
	session_start();
	if(!$name){
		return $_SESSION;
	}
	return $_SESSION[$name];
}

function writeLog($msg ,$name = null ,$log_dir = null){
	/* $log_switch = system_switch(LOG_SWITCH);
	  if(!$log_switch){
	  return true;
	  } */
	if(!$name){
		$name = date('Y-m-d_H');
	}else{
		if($log_dir === null){
			$name .= '_' . date('H');
		}
	}
	if($_SERVER['SERVER_ADDR']){
		$name .= '_' . $_SERVER['SERVER_ADDR'];
	}else{
		if(!$GLOBALS['local_ip']){
			$get_local_ip_cmd = "/sbin/ifconfig|grep 'inet addr'|awk '{print $2}'|awk -F':' '{print $2}'|awk '$1 !~ /127.0.0.1/{print}'|tail -n 1";
			$local_ip = exec($get_local_ip_cmd);
			$GLOBALS['local_ip'] = $local_ip;
		}
		$name .= '_' . $GLOBALS['local_ip'];
	}
	if($log_dir === null){
		$log_dir = '/' . date('Ym') . '/' . date('d');
		_mkdirs($log_dir, LOG_DIR);
	}
	$log_path = LOG_DIR . $log_dir;
	_mkdirs($log_dir, LOG_DIR);
	$log_file = $log_path . "/" . $name . ".log";
	$fd = fopen($log_file, "a");
	if(is_array($msg)){
		fwrite($fd, json_encode($msg) . "\n");
	}else{
		fwrite($fd, $msg . "\n");
	}
	fclose($fd);
}

/**
 * HTTP Protocol defined status codes
 * @param int $num
 */
function HTTPStatus($num){
	static $http = array(100 => "HTTP/1.1 100 Continue",101 => "HTTP/1.1 101 Switching Protocols",200 => "HTTP/1.1 200 OK",201 => "HTTP/1.1 201 Created",202 => "HTTP/1.1 202 Accepted",203 => "HTTP/1.1 203 Non-Authoritative Information",204 => "HTTP/1.1 204 No Content",205 => "HTTP/1.1 205 Reset Content",206 => "HTTP/1.1 206 Partial Content",300 => "HTTP/1.1 300 Multiple Choices",301 => "HTTP/1.1 301 Moved Permanently",302 => "HTTP/1.1 302 Found",303 => "HTTP/1.1 303 See Other",304 => "HTTP/1.1 304 Not Modified",305 => "HTTP/1.1 305 Use Proxy",307 => "HTTP/1.1 307 Temporary Redirect",400 => "HTTP/1.1 400 Bad Request",401 => "HTTP/1.1 401 Unauthorized",402 => "HTTP/1.1 402 Payment Required",403 => "HTTP/1.1 403 Forbidden",404 => "HTTP/1.1 404 Not Found",405 => "HTTP/1.1 405 Method Not Allowed",406 => "HTTP/1.1 406 Not Acceptable",407 => "HTTP/1.1 407 Proxy Authentication Required",408 => "HTTP/1.1 408 Request Time-out",409 => "HTTP/1.1 409 Conflict",410 => "HTTP/1.1 410 Gone",411 => "HTTP/1.1 411 Length Required",412 => "HTTP/1.1 412 Precondition Failed",413 => "HTTP/1.1 413 Request Entity Too Large",414 => "HTTP/1.1 414 Request-URI Too Large",415 => "HTTP/1.1 415 Unsupported Media Type",416 => "HTTP/1.1 416 Requested range not satisfiable",417 => "HTTP/1.1 417 Expectation Failed",500 => "HTTP/1.1 500 Internal Server Error",501 => "HTTP/1.1 501 Not Implemented",502 => "HTTP/1.1 502 Bad Gateway",503 => "HTTP/1.1 503 Service Unavailable",504 => "HTTP/1.1 504 Gateway Time-out");
	header($http[$num]);
}

function _json_encode($data){
	header("Content-type: application/json; charset=utf-8");
	return json_encode($data);
}

function encry_password($password,$salt){
	return md5($password.$salt);
}

function ajax_return_error($error_code ,$error = null){
	header("Content-type: application/json; charset=utf-8");
	$data['error_code'] = $error_code;
	if($error){
		$data['error'] = $error;
	}
	return json_encode($data);
}

function return_error_data($error_code ,$error){
	$data['error_code'] = $error_code;
	$data['error'] = urlencode($error);
	$urldecode_flag = true;
	return api_return_output($data, $urldecode_flag);
}

function api_return_error($error_code ,$error){
	header('HTTP/1.1 400 Bad Request');
	$data['error'] = urlencode($error);
	$data['error_code'] = intval($error_code);
	$data['request'] = $GLOBALS['request_uri_info'];
	$urldecode_flag = true;
	return api_return_output($data, $urldecode_flag);
}

function api_return_output($data ,$urldecode_flag = false){
	$return_data = _json_encode($data);
	if($urldecode_flag){
		$return_data = urldecode($return_data);
	}
	
	return $return_data;
}

function bigintval($value){
	$value = trim($value);
	if(ctype_digit($value)){
		return $value;
	}
	$value = preg_replace("/[^0-9](.*)$/", '', $value);
	if(ctype_digit($value)){
		return $value;
	}
	return 0;
}

function random_string(){
	$character_set_array = array();
	$character_set_array[] = array('count' => 7,'characters' => 'abcdefghijklmnopqrstuvwxyz');
	$character_set_array[] = array('count' => 1,'characters' => '0123456789');
	$temp_array = array();
	foreach($character_set_array as $character_set){
		for($i = 0; $i < $character_set['count']; $i++){
			$temp_array[] = $character_set['characters'][rand(0, strlen($character_set['characters']) - 1)];
		}
	}
	shuffle($temp_array);
	return implode('', $temp_array);
}

/**
 * 将当前字符串从 BeginString 向右截取
 *
 * @param string $BeginString
 * @param boolean $self
 * @return String
 */
function rightString($String ,$BeginString ,$self = false){
	$Start = strpos($String, $BeginString);
	if($Start === false)
		return null;
	if(!$self)
		$Start += strlen($BeginString);
	$newString = substr($String, $Start);
	return $newString;
}

/**
 * 将当前字符串从 BeginString 向左截取
 *
 * @param string $BeginString
 * @param boolean $self
 * @return String
 */
function leftString($BeginString ,$String ,$self = false){
	$Start = strpos($String, $BeginString);
	if($Start === false)
		return null;
	if($self)
		$Start += strlen($BeginString);
	$newString = substr($String, 0, $Start);
	return $newString;
}

function model_return_error($error_code ,$error){
	$data['error_code'] = 'VIP' . $error_code;
	$data['error'] = $error;
	return $data;
}

function _addslashes($str){
	if(get_magic_quotes_gpc()){
		return $str;
	}
	return addslashes($str);
}

function return_output($file ,$data = null ,$single = true){
	if($single){
		$line = $data;
	}else{
		foreach($data as $data_key => $data_value){
			$$data_key = $data_value;
		}
		unset($data);
	}
	
	ob_start();
	include $file;
	return ob_get_clean();
}

function getDepKey($options){
	if(!$options || !is_array($options)){
		return null;
	}
	$defaults = array('target_id' => 0,'type' => 0,'subtype' => 0);
	foreach($defaults as $k => $v){
		$options[$k] = array_key_exists($k, $options) ? $options[$k] : $v;
	}
	$rendered_key = KEY_PREFIX . 'dep_' . $options['target_id'] . '_' . $options['type'] . '_' . $options['subtype'];
	return md5($rendered_key);
}

// 去除首尾全角及半角空格,多个空格合并为一个
function _trim($str){
	$str = preg_replace('/( |　|\r\n|\r|\n)+/', ' ', $str);
	return trim(preg_replace("/^　+|　+$/ ", " ", $str));
}

/**
 * friendlyDate()
 *
 * @param mixed $sTime
 * @param string $type,当full时,返回全部时间日期
 * @return 友好的时间日期
 */
function friendlyDate($sTime ,$type = 'normal' ,$strtotime = false){
	if($strtotime){
		$sTime = strtotime($sTime);
	}
	//sTime=源时间，cTime=当前时间，dTime=时间差
	$cTime = time();
	
	$dTime = $cTime - $sTime;
	
	$dDay = intval(date("Ymd", $cTime)) - intval(date("Ymd", $sTime));
	$dYear = intval(date("Y", $cTime)) - intval(date("Y", $sTime));
	//normal：n秒前，n分钟前，n小时前，日期
	if($type == 'normal'){
		if($dTime < 60){
			if($dTime < 10){
				$dTime = 10;
			}
			return $dTime . "秒前";
		}elseif($dTime < 3600){
			return intval($dTime / 60) . "分钟前";
		}elseif($dTime >= 3600 && $dDay == 0){
			return "今天" . date(" H:i", $sTime);
		}elseif($dYear == 0){
			return date("n月d日  H:i", $sTime);
		}else{
			return date("Y年n月d日 H:i", $sTime);
		}
	
		//full: Y-m-d , H:i:s
	}elseif($type == 'full'){
		return date("Y年n月d日  H:i:s", $sTime);
	}elseif($type == 'date'){
		return date("Y-n-d", $sTime);
	}else{
		if($dTime < 60){
			if($dTime < 10){
				$dTime = 10;
			}
			return $dTime . "秒前";
		}elseif($dTime < 3600){
			return intval($dTime / 60) . "分钟前";
		}elseif($dTime >= 3600 && $dDay == 0){
			return "今天" . date(" H:i", $sTime);
		}elseif($dYear == 0){
			return date("n月d日 ,H:i", $sTime);
		}else{
			return date("Y年n月d日 H:i", $sTime);
		}
	}
}

function strlen_weibo($string ,$charset = 'utf-8'){
	$n = $count = 0;
	$length = strlen($string);
	if(strtolower($charset) == 'utf-8'){
		while($n < $length){
			$currentByte = ord($string[$n]);
			if($currentByte == 9 || $currentByte == 10 || (32 <= $currentByte && $currentByte <= 126)){
				$n++;
				$count++;
			}elseif(194 <= $currentByte && $currentByte <= 223){
				$n += 2;
				$count += 2;
			}elseif(224 <= $currentByte && $currentByte <= 239){
				$n += 3;
				$count += 2;
			}elseif(240 <= $currentByte && $currentByte <= 247){
				$n += 4;
				$count += 2;
			}elseif(248 <= $currentByte && $currentByte <= 251){
				$n += 5;
				$count += 2;
			}elseif($currentByte == 252 || $currentByte == 253){
				$n += 6;
				$count += 2;
			}else{
				$n++;
				$count++;
			}
			if($count >= $length){
				break;
			}
		}
		return ceil($count / 2);
	}else{
		for($i = 0; $i < $length; $i++){
			if(ord($string[$i]) > 127){
				$i++;
				$count++;
			}
			$count++;
		}
		return ceil($count / 2);
	}
}

function cutstr($string ,$length = 20 ,$dot = '...' ,$htmlencode = true ,$charset = 'utf-8'){
	if(strlen($string) <= $length){
		if($htmlencode){
			return htmlspecialchars($string);
		}else{
			return $string;
		}
	}
	/* if ($htmlencode) {
	  $string = htmlspecialchars_decode ( $string );
	  } */
	$strcut = '';
	if(strtolower($charset) == 'utf-8'){
		$n = $tn = $noc = 0;
		while($n < strlen($string)){
			$t = ord($string[$n]);
			if($t == 9 || $t == 10 || (32 <= $t && $t <= 126)){
				$tn = 1;
				$n++;
				$noc++;
			}elseif(194 <= $t && $t <= 223){
				$tn = 2;
				$n += 2;
				$noc += 2;
			}elseif(224 <= $t && $t < 239){
				$tn = 3;
				$n += 3;
				$noc += 2;
			}elseif(240 <= $t && $t <= 247){
				$tn = 4;
				$n += 4;
				$noc += 2;
			}elseif(248 <= $t && $t <= 251){
				$tn = 5;
				$n += 5;
				$noc += 2;
			}elseif($t == 252 || $t == 253){
				$tn = 6;
				$n += 6;
				$noc += 2;
			}else{
				$n++;
			}
			if($noc >= $length){
				break;
			}
		}
		if($noc > $length){
			$n -= $tn;
		}
		$strcut = substr($string, 0, $n);
	}else{
		for($i = 0; $i < $length; $i++){
			$strcut .= ord($string[$i]) > 127 ? $string[$i] . $string[++$i] : $string[$i];
		}
	}
	$original_strlen = strlen($string);
	$new_strlen = strlen($strcut);
	if($htmlencode){
		$strcut = htmlspecialchars($strcut);
	}
	return $strcut . ($original_strlen > $new_strlen ? $dot : '');
}

function _mkdir($dir){
	if(file_exists($dir))
		return true;
	$u = umask(0);
	$r = @mkdir($dir, 0777);
	umask($u);
	return $r;
}

function _mkdirs($dir ,$rootpath = '.'){
	if(!$rootpath)
		return false;
	if($rootpath == '.')
		$rootpath = realpath($rootpath);
	$forlder = explode('/', $dir);
	$path = '';
	for($i = 0; $i < count($forlder); $i++){
		if($current_dir = trim($forlder[$i])){
			if($current_dir == '.')
				continue;
			$path .= '/' . $current_dir;
			if($current_dir == '..'){
				continue;
			}
			if(file_exists($rootpath . $path)){
				@chmod($rootpath . $path, 0777);
			}else{
				if(!_mkdir($rootpath . $path)){
					return false;
				}
			}
		}
	}
	return true;
}

function isEmail($email){
	return preg_match('/^[_\-\.\w]+@\w+\.([_-\w]+\.)*\w{1,4}$/', $email);
}

function isMobile($phone){
	return preg_match("/13[0-9]{9}$|15[0|1|2|3|5|6|7|8|9]\d{8}$|18[0|5|6|7|8|9]\d{8}$/", $phone);
}

function isRealname($realname){
    return preg_match('/^[a-zA-Z\x{4e00}-\x{9fa5}]{1,12}$/u', $realname);
}

function isDateValid($str){
	if(!preg_match("/^\d{4}-\d{2}-\d{2}$/", $str))
		return FALSE;
	$stamp = strtotime($str);
	if(!is_numeric($stamp))
		return FALSE;
	
		//checkdate(month, day, year)
	if(checkdate(date('m', $stamp), date('d', $stamp), date('Y', $stamp))){
		return TRUE;
	}
	return FALSE;
}

function is_intval($mixed) {
	return ( preg_match('/^\d*$/', $mixed) == 1 );
}

function getUrl($controller ,$action = 'index' ,$parameters = null){
	$url = '/' . $controller . '/' . $action;
	if($parameters && is_array($parameters)){
		foreach($parameters as $key => $value){
			$url = $url . '/' . $key . '/' . $value;
		}
	}
	
	return $url;
}

function write_ini_file($path ,$assoc_array){
	foreach($assoc_array as $key => $item){
		if(is_array($item)){
			$content .= "\n[{$key}]\n";
			foreach($item as $key2 => $item2){
				if(is_numeric($item2) || is_bool($item2))
					$content .= "{$key2} = {$item2}\n";
				else
					$content .= "{$key2} = \"{$item2}\"\n";
			}
		}else{
			if(is_numeric($item) || is_bool($item))
				$content .= "{$key} = {$item}\n";
			else
				$content .= "{$key} = \"{$item}\"\n";
		}
	}
	if(!$handle = fopen($path, 'w')){
		return false;
	}
	
	if(!fwrite($handle, $content)){
		return false;
	}
	
	fclose($handle);
	return true;
}

function substring($String ,$BeginString ,$EndString = null){
	$Start = strpos($String, $BeginString);
	if($Start === false)
		return null;
	$Start += strlen($BeginString);
	$String = substr($String, $Start);
	if(!$EndString)
		return $String;
	$End = strpos($String, $EndString);
	if($End == false)
		return null;
	return substr($String, 0, $End);
}

function get_client_ip(){
	if(getenv('HTTP_CLIENT_IP')) {
		$ip = getenv('HTTP_CLIENT_IP');
	} elseif(getenv('HTTP_X_FORWARDED_FOR')) {
		$ip = getenv('HTTP_X_FORWARDED_FOR');
	} elseif(getenv('REMOTE_ADDR')) {
		$ip = getenv('REMOTE_ADDR');
	} else {
		$ip = $HTTP_SERVER_VARS['REMOTE_ADDR'];
	}
	return $ip;
}

function curl_get_contents($url ,$timeout = 15){
	$curlHandle = curl_init();
	curl_setopt($curlHandle, CURLOPT_URL, $url);
	curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($curlHandle, CURLOPT_TIMEOUT, $timeout);
	$result = curl_exec($curlHandle);
	curl_close($curlHandle);
	return $result;
}

/*
 * POST 请求
 */
function curl_post_contents($sUrl ,$aPOSTParam){
	$oCurl = curl_init();
	if(stripos($sUrl, "https://") !== FALSE){
		curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, false);
	}
	$aPOST = array();
	foreach($aPOSTParam as $key => $val){
		$aPOST[] = $key . "=" . urlencode($val);
	}
	curl_setopt($oCurl, CURLOPT_URL, $sUrl);
	curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($oCurl, CURLOPT_POST, true);
	curl_setopt($oCurl, CURLOPT_POSTFIELDS, join("&", $aPOST));
	$sContent = curl_exec($oCurl);
	$aStatus = curl_getinfo($oCurl);
	curl_close($oCurl);
	if(intval($aStatus["http_code"]) == 200){
		return $sContent;
	}else{
		return FALSE;
	}
}

/**
 * 
 * 通过socket的方式来提交参数到目标地址，可以用于实现PHP的异步处理等
 * @param string $url,array $post_data,array $cookie,string $referer
 */
function SocketRequest($url ,$post_data = array() ,$cookie = array() ,$referer){
	$method = "GET"; //可以通过POST或者GET传递一些参数给要触发的脚本
	$url_array = parse_url($url);
	$port = isset($url_array['port']) ? $url_array['port'] : 80;
	
	$fp = fsockopen($url_array['host'], $port, $errno, $errstr, 30);
	if(!$fp){
		return FALSE;
	}
	$getPath = $url_array['path'] . "?" . $url_array['query'];
	if(!empty($post_data)){
		$method = "POST";
	}
	$header = $method . " " . $getPath;
	$header .= " HTTP/1.1\r\n";
	$header .= "Host: " . $url_array['host'] . "\r\n"; //HTTP 1.1 Host域不能省略
	if($referer){
		$header .= "Referer: $referer\r\n";
	}
	
	if(!empty($cookie)){
		$_cookie = strval(NULL);
		foreach($cookie as $k => $v){
			$_cookie .= $k . "=" . $v . "; ";
		}
		$cookie_str = "Cookie: " . base64_encode($_cookie) . " \r\n"; //传递Cookie
		$header .= $cookie_str;
	}
	if(!empty($post_data)){
		$_post = http_build_query($post_data);
		$post_str = "Content-Type: application/x-www-form-urlencoded\r\n"; //POST数据
		$post_str .= "Content-Length: " . strlen($_post) . " \r\n"; //POST数据的长度
		$post_str .= "Connection:Close\r\n\r\n";
		$post_str .= $_post . "\r\n\r\n "; //传递POST数据
		$header .= $post_str;
	}else{
		$header .= "Connection:Close\r\n\r\n";
	}
	fwrite($fp, $header);
	fclose($fp);
	return true;
}
function getMailDomain($email){
	$mail_config = array('126.com' => 'http://126.com/','163.com' => 'http://mail.163.com/','sina.com' => 'http://mail.sina.com/','sina.cn' => 'http://mail.sina.com/','yahoo.cn' => 'http://cn.mail.yahoo.com/','21cn.com' => 'http://mail.21cn.com/','tom.com' => 'http://mail.tom.com/','gmail.com' => 'http://mail.google.com/gmail ','hotmail.com' => 'http://www.Hotmail.com/','msn.com' => 'http://www.msn.com/','qq.com' => 'http://mail.qq.com/','sohu.com' => 'http://mail.sohu.com/','139.com' => 'http://mail.139.com/','189.cn' => 'http://mail.189.cn/webmail/','wo.com.cn' => 'http://mail.wo.com.cn/','meitu.com' => 'http://mail.meitu.com/');
	if(preg_match("/@(.+)/i", $email, $data)){
		$u = strtolower($data[1]);
		if(array_key_exists($u, $mail_config)){
			$url = $mail_config[$u];
		}else
			$url = "http://www." . $u;
	}else{
		$url = "";
	}
	return $url;
}

//分页
function MultiPage(&$multipages){
	if($multipages['page'] - 1 > 0){
		$multipages['firstpage'] = 1;
		$multipages['backpage'] = $multipages['page'] - 1;
	}
	if($multipages['page'] < $multipages['pagecount']){
		$multipages['nextpage'] = ($multipages['page'] + 1);
		$multipages['lastpage'] = $multipages['pagecount'];
	}
	if($multipages['pagecount'] > 1){
		if($multipages['pagecount'] <= 5){
			$min = 1;
			$max = $multipages['pagecount'];
			for($i = $min; $i <= $max; $i++){
				$multipages['pagenums'][$i] = $i;
			}
		}else{
			$max = ($multipages['page'] + 2) < $multipages['pagecount'] ? $multipages['page'] + 2 : $multipages['pagecount'];
			if($multipages['pagecount'] > 1){
				$min = ($max - 3) > 0 ? $max - 3 : 1;
				for($i = $min; $i <= $max; $i++){
					$multipages['pagenums'][$i] = $i;
				}
			}
			if($multipages['page'] > 2){
				$multipages['frontsign'] = true;
			}
			if($multipages['page'] + 2 < $multipages['pagecount']){
				$multipages['backsign'] = true;
			}
		}
	}
}
function compu_timediff($begin_time,$end_time){
	if($begin_time < $end_time){
		$starttime = $begin_time;
		$endtime = $end_time;
	}else{
		return array("day" => '0',"hour" => '00',"min" => '00',"sec" => '00');
	}
	$timediff = $endtime-$starttime;
	$days = intval($timediff/86400);
	$remain = $timediff%86400;
	$hours = intval($remain/3600);
	$remain = $remain%3600;
	$mins = intval($remain/60);
	$secs = $remain%60;
	$hours = str_pad($hours,2,'0',STR_PAD_LEFT);
	$mins = str_pad($mins,2,'0',STR_PAD_LEFT);
	$secs = str_pad($secs,2,'0',STR_PAD_LEFT);
	$res = array("day" => $days,"hour" => $hours,"min" => $mins,"sec" => $secs);
	return $res;
}

function CheckCharLength($String ,$MinLength ,$MaxLength ,$Encode = 'UTF-8'){
	if(!$Encode || $MaxLength < 1){
		return false;
	}
	$Length = (strlen($String) + mb_strlen($String, $Encode)) / 2;
	if($Length >= $MinLength && $Length <= $MaxLength){
		return true;
	}else{
		return false;
	}
}

function getCurrentUrl(){
	return 'http://'.$_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
}