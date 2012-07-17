<?php
/*
 * This file is part of XenAPI <http://www.contex.me/>.
 *
 * XenAPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * XenAPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
$xf = new XenAPI("/home/contex/www/"); 
$xf->setAPIKey("b8e7ae12510bdfb110bd");

if ($xf->getRest()->hasRequest('action')) {
	if (!$xf->getRest()->getAction()) {
		$xf->getRest()->throwErrorF(1, "action");
	} else if (!$xf->getRest()->isSupportedAction()) {
		$xf->getRest()->throwErrorF(2, $xf->getRest()->getAction());
	} else if (!$xf->getRest()->hasRequest("hash") && !$xf->getRest()->isIgnoredAction()) {
		$xf->getRest()->throwErrorF(1, "hash");
	} else if (!$xf->getRest()->isAuthenticated() && !$xf->getRest()->isIgnoredAction()) {
		$xf->getRest()->throwErrorF(6, $xf->getRest()->getHash());
	} else {
		$xf->getRest()->processRequest();
	}
} else {
	$xf->getRest()->throwErrorF(3, "action");
}

class RestAPI {
	private $xenAPI, $actions = array("getuser", "authenticate");
	private $ignoredActions = array("authenticate");
	private $method, $data = array(), $hash = false;
	private $errors = array(0 => "Unknown error", 
							1 => "Parameter: {ERROR}, is empty/missing a value",
							2 => "{ERROR}, is not a supported action",
							3 => "Missing parameter: {ERROR}",
							4 => "No user found with the parameter: {ERROR}",
							5 => "Authentication error: {ERROR}",
							6 => "{ERROR} is not a valid hash");
	
	public function __construct($xenAPI) {
		$this->xenAPI = $xenAPI;
		$request_method = strtolower($_SERVER['REQUEST_METHOD']);  
		$this->method = $request_method;
		switch ($request_method) {  
			case 'get':  
				$this->data = $_GET;  
				break;  
			case 'post':  
				$this->data = $_POST;  
				break;  
			case 'put':  
				parse_str(file_get_contents('php://input'), $put_vars);  
				$this->data = $put_vars;  
				break;  
		} 
		if ($this->hasRequest("hash")) {
			$this->hash = $this->getRequest("hash");
		}
	}
	
	public function getHash() {
		return $this->hash;
	}
	
	public function isAuthenticated() {
		if ($this->getHash()) {
			if ($this->getHash() == $this->xenAPI->getAPIKey()) {
				return true;
			}
			if (strpos($this->getHash(), ":") !== false) {
				$array = explode(":", $this->getHash());
				$user = $this->xenAPI->getUser($array[0]);
				if ($user->isRegistered()) {
					$record = $user->getAuthenticationRecord();
					$ddata = unserialize($record['data']);
					if ($ddata['hash'] == $array[1]) {
						return true;
					}
				}
			}
		}
		return false;
	}
	
	public function getMethod() {
		return $this->method;
	}
	
	public function getAction() {
		return $this->getRequest('action');
	}
	
	public function hasRequest($key) {
		return isset($this->data[$key]);
	}
	
	public function getRequest($key) {
		if ($this->hasRequest($key)) {
			return $this->data[$key];
		} else {
			return false;
		}
	}
	
	public function getData() {
		return $this->data;
	}
	
	public function isSupportedAction() {
		return in_array(strtolower($this->data['action']), $this->actions);
	}
	
	public function isIgnoredAction() {
		return in_array(strtolower($this->data['action']), $this->ignoredActions);
	}
	
	public function getError($error) {
		$this->getErrorF($error, null);
	}

	public function getErrorF($error, $extra) {
		if (array_key_exists($error, $this->errors)) {
			if ($extra != null) {
				return str_replace("{ERROR}", $extra, $this->errors[$error]);
			} else {
				return $this->errors[$error];
			}
		} else {
			return $this->errors[0];
		}
	}
	
	public function throwError($error) {
		$this->throwErrorF($error, null);
	}
	
	public function throwErrorF($error, $extra) {
		if ($extra != null) {
			$this->sendResponse(array("error" => $error, "message" => $this->getErrorF($error, $extra)));
		} else {
			$this->sendResponse(array("error" => $error, "message" => $this->getError($error)));
		}
	}
	
	public function processRequest() {
		switch (strtolower($this->getAction())) {
			case "getuser": 
				if (!$this->hasRequest('value')) {
					$this->throwErrorF(3, "value");
					break;
				} else if (!$this->getRequest('value')) {
					$this->throwErrorF(1, "value");
					break;
				}
				$user = $this->xenAPI->getUser($this->getRequest('value'));
				if (!$user->isRegistered()) {
					$this->throwErrorF(4, $this->getRequest('value'));
					break;
				} else {
					$this->sendResponse($user->getData());
				}
				break;
			case "authenticate": 
				if (!$this->hasRequest('username')) {
					$this->throwErrorF(3, "username");
					break;
				} else if (!$this->getRequest('username')) {
					$this->throwErrorF(1, "username");
					break;
				} else if (!$this->hasRequest('password')) {
					$this->throwErrorF(3, "password");
					break;
				} else if (!$this->getRequest('password')) {
					$this->throwErrorF(1, "password");
					break;
				}
				$user = $this->xenAPI->getUser($this->getRequest('username'));
				if (!$user->isRegistered()) {
					$this->throwErrorF(4, $this->getRequest('username'));
				} else {
					if ($user->validateAuthentication($this->getRequest('password'))) {
						$record = $user->getAuthenticationRecord();
						$ddata = unserialize($record['data']);
						$this->sendResponse(array('hash' => $ddata['hash']));
					} else {
						$this->throwErrorF(5, 'Invalid username or password!');
					}
				}
				break;
		}
	}
	
	public function sendResponse($data) {
		echo json_encode($data);
	}
}

class XenAPI {
	private $xfDir, $startTime, $models, $rest, $visitor, $apikey = false;
	
	public function __construct($directory) {
		$this->xfDir = $directory;
		$this->startTime = microtime(true);
		require($this->xfDir . '/library/XenForo/Autoloader.php');
		XenForo_Autoloader::getInstance()->setupAutoloader($this->xfDir. '/library');
		XenForo_Application::initialize($this->xfDir . '/library', $this->xfDir);
		XenForo_Application::set('page_start_time', $this->startTime);
		$this->models = new Models();
		$this->models->setUserModel(XenForo_Model::create('XenForo_Model_User'));
		$this->models->setUserFieldModel(XenForo_Model::create('XenForo_Model_UserField'));
		$this->rest = new RestAPI($this);
		$this->visitor = new Visitor();
	}
	
	public function getRest() {
		return $this->rest;
	}
	
	public function getVisitor() {
		return $this->visitor;
	}
	
	public function getAPIKey() {
		return $this->apikey;
	}
	
	public function setAPIKey($apikey) {
		$this->apikey = $apikey;
	}
	
	public function getModels() {
		return $this->models;
	}
	
	public function getLatestUser() {
		return new User($this->models, $this->models->getUserModel()->getLatestUser());
	}
	
	public function getTotalUsersCount() {
		return $this->models->getUserModel()->countTotalUsers();
	}
	
	public function getUser($input) {
		if (is_numeric($input)) {
			$user = new User($this->models, $this->models->getUserModel()->getUserById($input));
			if (!$user->isRegistered()) {
				return new User($this->models, $this->models->getUserModel()->getUserByName($input));
			}
			return $user;
		} else if($this->models->getUserModel()->couldBeEmail($input)) {
			return new User($this->models, $this->models->getUserModel()->getUserByEmail($input));
		} else {
			return new User($this->models, $this->models->getUserModel()->getUserByName($input));
		}
	}
}

class Models {
	private $userModel, $userFieldModel;
	
	public function setUserModel($userModel) {
		$this->userModel = $userModel;
	}
	
	public function getUserModel() {
		return $this->userModel;
	}
	
	public function setUserFieldModel($userFieldModel) {
		$this->userFieldModel = $userFieldModel;
	}
	
	public function getUserFieldModel() {
		return $this->userFieldModel;
	}
}

class User {
	private $models, $data, $registered = false;
	
	public function __construct($models, $data) {
		$this->models = $models;
		$this->data = $data;
		if (!empty($data)) {
			$this->registered = true;
		}
	}
	
	public function isRegistered() {
		return $this->registered;
	}
	
	public function getData() {
		return $this->data;
	}
	
	public function getAuthenticationRecord() {
		return $this->models->getUserModel()->getUserAuthenticationRecordByUserId($this->data['user_id']); 
	}
	
	public function validateAuthentication($password) {
		if (strlen($password) == 64) {
			$record = $this->getAuthenticationRecord();
			$ddata = unserialize($record['data']);
			return $ddata['hash'] == $password;
		} else {
			return $this->models->getUserModel()->validateAuthentication($this->data['username'], $password); 
		}
	}
	
	public function getUnreadAlertsCount() {
		return $this->models->getUserModel()->getUnreadAlertsCount($this->getID()); 
	}
}

class Visitor {
	private $ip, $useragent, $referer;

	public function __construct() {
		if (isset($_SERVER['HTTP_CLIENT_IP'])) {
			$this->ip = $_SERVER['HTTP_CLIENT_IP'];
		} else if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$this->ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else if(isset($_SERVER['REMOTE_ADDR'])) {
			$this->ip = $_SERVER['REMOTE_ADDR'];
		}
		if (isset($_SERVER['HTTP_USER_AGENT'])) { 
			$this->useragent = $_SERVER['HTTP_USER_AGENT']; 
		}
		if (isset($_SERVER['HTTP_REFERER'])) { 
			$this->referer = $_SERVER['HTTP_REFERER']; 
		}
	}

	/*
	* Returns the IP of the visitor.
	*/
	public function getIP() {
		return $this->ip;
	}

	/*
	* Returns the User Agent of the visitor.
	*/
	public function getUserAgent() {
		return $this->useragent;
	}

	/*
	* Returns the referer of the visitor.
	*/
	public function getReferer() {
		return $this->referer;
	}
}
?>
