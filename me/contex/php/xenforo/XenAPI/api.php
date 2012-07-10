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
echo $xf->getLatestUser()->getID() . "<br>";
if (!$xf->getUser(1)->validateAuthentication("test")) {
	echo "Failed login!<br>";
} else {
	echo "Passed login!<br>";
}
echo $xf->getTotalUsersCount() . "<br>";
echo $xf->getLatestUser()->getID();

class XenAPI {
	private $xfDir, $startTime;
	private $models;
	
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
	}
	
	public function getModels() {
		return $this->models;
	}
	
	public function getUserModel() {
		return $this->models->getUserModel();
	}
	
	public function getUserFieldModel() {
		return $this->models->getUserFieldModel();
	}
	
	public function getLatestUser() {
		return new User($this->models, $this->models->getUserModel()->getLatestUser());
	}
	
	public function getTotalUsersCount() {
		return $this->models->getUserModel()->countTotalUsers();
	}
	
	public function getUser($userInput) {
		if (is_int($userInput)) {
			return new User($this->models, $this->models->getUserModel()->getUserById($userInput));
		} else if($this->models->getUserModel()->couldBeEmail($userInput)) {
			return new User($this->models, $this->models->getUserModel()->getUserByEmail($userInput));
		} else {
			return new User($this->models, $this->models->getUserModel()->getUserByName($userInput));
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
	private $models, $data;
	
	public function __construct($models, $data) {
		$this->models = $models;
		$this->data = $data;
	}
	
	public function getData() {
		return $this->data;
	}
	
	public function getAuthenticationRecord() {
		return $this->models->getUserModel()->getUserAuthenticationRecordByUserId($this->getID()); 
	}
	
	public function validateAuthentication($password) {
		return $this->models->getUserModel()->validateAuthentication($this->getUsername(), $password); 
	}
	
	public function getUnreadAlertsCount() {
		return $this->models->getUserModel()->getUnreadAlertsCount($this->getID()); 
	}

	public function getID() {
		return $this->data['user_id'];
	}
	
	public function getUsername() {
		return $this->data['username'];
	}
	
	public function getEmail() {
		return $this->data['email'];
	}
	
	public function getGender() {
		return $this->data['gender'];
	}
	
	public function getCustomTitle() {
		return $this->data['custom_title'];
	}
	
	public function getLanguageID() {
		return $this->data['language_id'];
	}
	
	public function getStyleID() {
		return $this->data['style_id'];
	}
	
	public function getTimezone() {
		return $this->data['timezone'];
	}
	
	public function isVisible() {
		return $this->data['visible'];
	}
	
	public function getGroupID() {
		return $this->data['user_group_id'];
	}
	
	public function getSecondaryGroupIDs() {
		return $this->data['secondary_group_ids'];
	}
}
?>