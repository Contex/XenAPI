<?php
/*
 * This file is part of XenAPI <http://www.xenapi.net/>.
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
$time_start = microtime(true);
$restAPI = new RestAPI(); 
$restAPI->setAPIKey('b8e7ae12510bdfb110bd');

if (!$restAPI->getAPIKey != NULL && !$restAPI->hasRequest('hash')) {
    // Hash argument is required and was not found, throw error.
    $restAPI->throwErrorF(3, 'hash');
} else if (!$restAPI->hasRequest('action')) {
    // Action argument was not found, throw error.
    $restAPI->throwErrorF(3, 'action');
}
if (!$restAPI->getAction()) {
    // Action argument is empty or not set, throw error. 
    $restAPI->throwErrorF(1, 'action');
} else if (!$restAPI->isSupportedAction()) {
    // Action is not supported, throw error.
    $restAPI->throwErrorF(2, $restAPI->getAction());
} else if (!$restAPI->hasRequest('hash') && !$restAPI->isPublicAction()) {
    // Action is not public and requires a hash but the hash argument is not set, throw error.
    $restAPI->throwErrorF(1, 'hash');
} else if (!$restAPI->isAuthenticated() && !$restAPI->isPublicAction()) {
    // Hash is not valid and action is not public, throw error.
    $restAPI->throwErrorF(6, $restAPI->getHash());
} else if (!$restAPI->isPermitted()) {
    // User does not have permission to use this action, throw error.
    if ($restAPI->hasRequest('value') && $restAPI->isUserAction()) {
        $restAPI->throwErrorF(9, $restAPI->getAction());
    } else {
        $restAPI->throwErrorF(10, $restAPI->getAction());
    }
}
// Process the request.
$restAPI->processRequest();

class RestAPI {
    const version = '1.2';
    /**
    * Contains all the actions in an array, each action is 'action' => 'permission_name'
    * 'action' is the name of the action in lowercase.
    * 'permission_name' is the permission requirement of the action, see description under.
    *
    * Permission names and meaning:
    *   - public:        A hash is not required to use this action, it can be used without
    *                    without being 'authenticated'.
    *   - authenticated: The action requires the user to be authenticated to use the action
    *                    with a 'value' argument.
    *   - moderator:     The action requires the user to be a moderator to use the action 
    *                    with a 'value' argument.
    *   - administrator: The action requires the user to be an administrator to use the action
    *                    with a 'value' argument.
    *   - private:       User is only allowed to use the action on himself/herself. 
    *                    Example: If user tries to use 'getAlerts' with a 'value' argument, 
    *                              an error will be thrown.
    *
    * NOTE: Permissions are ignored when the API key is used as a hash, permissions are only
    *       used when the user is using the 'username:hash' format for the 'hash' argument.
    */
    private $actions = array(
                             'getactions'         => 'public', 
                             'getalerts'          => 'private', 
                             'getuser'            => 'authenticated', 
                             'getavatar'          => 'public', 
                             'getusers'           => 'public', 
                             'getgroup'           => 'public', 
                             'authenticate'       => 'public');
    
    // Array of actions that are user specific and require an username, ID or email for the 'value' parameter.
    private $user_actions = array('getalerts', 'getuser', 'getavatar');
    
    // List of errors, this is where the 'throwErrorF' function gets the messages from.
    private $errors = array(
                            0  => 'Unknown error', 
                            1  => 'Argument: "{ERROR}", is empty/missing a value',
                            2  => '"{ERROR}", is not a supported action',
                            3  => 'Missing argument: "{ERROR}"',
                            4  => 'No user found with the argument: "{ERROR}"',
                            5  => 'Authentication error: "{ERROR}"',
                            6  => '"{ERROR}" is not a valid hash',
                            7  => 'No group found with the argument: "{ERROR}"',
                            8  => 'You do not have permissions to use the "{ERROR}" action',
                            9  => 'You are not permitted to use the "{ERROR}" action on others (remove the value argument)',
                            10 => 'You do not have permission to use the "{ERROR}" action',
                            11 => '"{ERROR}" is a supported action but there is no code for it yet',
                            12 => '"{ERROR}" is a unknown request method.');

    private $xenAPI, $method, $data = array(), $hash = FALSE, $apikey = FALSE;

    /**
    * Default constructor for the RestAPI class.
    * The data gets set here depending on what kind of request method is being used.
    */
    public function __construct() {
        $this->method = strtolower($_SERVER['REQUEST_METHOD']);  
        switch ($this->method) {  
            case 'get':  
                $this->data = $_GET;  
                break;  
            case 'post':  
                $this->data = $_POST;  
                break;  
            case 'put':  
            case 'delete':
                parse_str(file_get_contents('php://input'), $put_vars);  
                $this->data = $put_vars;  
                break;  
            default:
                $this->throwErrorF(12, $this->method);
                break;
        } 
        $this->xenAPI = new XenAPI();

        // Lowercase the key data, ignores the case of the arguments.
        $this->data = array_change_key_case($this->data);
        if ($this->hasRequest('hash')) {
            // Sets the hash variable if the hash argument is set.
            $this->hash = $this->getRequest('hash');
        }
    }

    /**
    * Returns the API key, returns false if an API key was not set.
    */
    public function getAPIKey() {
        return $this->apikey;
    }
    
    /**
    * Sets the API key.
    */
    public function setAPIKey($apikey) {
        $this->apikey = $apikey;
    }
    
    /**
    * Return the hash, returns false if the hash was not set.
    */
    public function getHash() {
        return $this->hash;
    }
    
    /**
    * Checks if the request is authenticated.
    * Returns true if the hash equals the API key.
    * Returns true if the hash equals the user hash.
    * Returns false if none of the above are true.
    */
    public function isAuthenticated() {
        if ($this->getHash()) {
            // Hash argument is set, continue.
            if ($this->getHash() == $this->getAPIKey()) {
                // The hash equals the API key, return true.
                return true;
            }
            if (strpos($this->getHash(), ':') !== false) {
                // The hash contains : (username:hash), split it into an array.
                $array = explode(':', $this->getHash());
                // Get the user and check if the user is valid (registered).
                $user = $this->xenAPI->getUser($array[0]);
                if ($user->isRegistered()) {
                    // User is registered, get the hash from the authentication record.
                    $record = $user->getAuthenticationRecord();
                    $ddata = unserialize($record['data']);
                    if ($ddata['hash'] == $array[1]) {
                        // The hash in the authentication record equals the hash in the 'hash' argument.
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
    * Checks if the request is permitted.
    * Returns true if API key is set and valid or the action's permission is public.
    */
    public function isPermitted() {
        $permission = $this->getActionPermission();
        // Check if the request is authenticated and it's an user hash (and not an API key).
        if ($this->isAuthenticated() && $this->getUser()) {
            switch ($permission) {
                case 'public':
                    return true;
                case 'authenticated':
                    return true;
                case 'moderator':
                    return $this->getUser()->isModerator();
                case 'administrator':
                    return $this->getUser()->isAdmin();
                case 'private':
                    // Check if the 'value' argument is set.
                    if ($this->hasRequest('value') && $this->getRequest('value')) {
                        /**
                        * Returns true if the 'value' argument equals the username of the user hash.
                        * In other words, the request is not permitted if 'value' != username.
                        */
                        return $this->getUser()->getUsername() == $this->getRequest('value');
                    }
                    // The value argument is not, request is permitted, return true.
                    return true;
            }
        }
        // Returns true if permission of the action is public or the request has a valid API key.
        return $permission == 'public' || $this->hasAPIKey();
    }
    
    /**
    * Returns true if the request has an API key that is valid, returns false if not.
    */
    public function hasAPIKey() {
        if ($this->getHash()) {
            return $this->getHash() == $this->getAPIKey();
        }
        return false;
    }
    
    /**
    * Returns the User class of the username if the hash is set and is an userhash.
    * Returns false if the hash is not an userhash.
    */
    public function getUser() {
        if (strpos($this->getHash(), ':') !== false) {
            $array = explode(':', $this->getHash());
            return $this->xenAPI->getUser($array[0]);
        }    
        return false;
    }
    
    /**
    * Returns the method (get, post, put, delete).
    */
    public function getMethod() {
        return $this->method;
    }
    
    /**
    * Returns the action name.
    */
    public function getAction() {
        return $this->getRequest('action');
    }
    
    /**
    * Returns the permission name of the action.
    */
    public function getActionPermission() {
        return strtolower($this->actions[strtolower($this->getAction())]);
    }
    
    /**
    * Returns true if the '$key' is set a argument, returns false if not.
    */
    public function hasRequest($key) {
        return isset($this->data[strtolower($key)]);
    }
    
    /**
    * Gets the data of the '$key', returns false if the '$key' argument was not set.
    */
    public function getRequest($key) {
        if ($this->hasRequest($key)) {
            return $this->data[strtolower($key)];
        } else {
            return false;
        }
    }
    
    /**
    * Returns the array of all the arguments in the request.
    */
    public function getData() {
        return $this->data;
    }
    
    /**
    * Returns true if the action is supported, false if not.
    */
    public function isSupportedAction() {
        return array_key_exists(strtolower($this->data['action']), $this->actions);
    }
    
    /**
    * Returns true if the action is a public action (does not require a hash), false if not.
    */
    public function isPublicAction() {
        return strtolower($this->actions[strtolower($this->data['action'])]) == 'public';
    }
    
    /**
    * Returns true if the action is a user action (the 'value' parameter has to be an username/id/email), false if not.
    */
    public function isUserAction() {
        return in_array(strtolower($this->data['action']), $this->user_actions);
    }
    
    /**
    * Gets the error message without any parameter.
    */
    public function getError($error) {
        $this->getErrorF($error, null);
    }

    /**
    * Gets the error message and replaces {ERROR} with the $extra parameter.
    */
    public function getErrorF($error, $extra) {
        if (array_key_exists($error, $this->errors)) {
            if ($extra != null) {
                return str_replace('{ERROR}', $extra, $this->errors[$error]);
            } else {
                return $this->errors[$error];
            }
        } else {
            return $this->errors[0];
        }
    }
    
    /**
    * Throw the error message.
    */
    public function throwError($error) {
        $this->throwErrorF($error, null);
    }
    
    /**
    * Throw the error message.
    */
    public function throwErrorF($error, $extra) {
        if ($extra != null) {
            $this->sendResponse(array('error' => $error, 'message' => $this->getErrorF($error, $extra)));
        } else {
            $this->sendResponse(array('error' => $error, 'message' => $this->getError($error)));
        }
    }
    
    /**
    * Processes the REST request.
    */
    public function processRequest() {
        // Check if the action is an user action.
        if ($this->isUserAction()) {
            if ($this->hasRequest('value')) {
                if (!$this->getRequest('value')) {
                    // Throw error if the 'value' arguement is set but empty.
                    $this->throwErrorF(1, 'value');
                    break;
                }
                // Create a user variable with the 'value' arguement.
                $user = $this->xenAPI->getUser($this->getRequest('value'));
                if (!$user->isRegistered()) {
                    // Throw error if the 'value' user is not registered.
                    $this->throwErrorF(4, $this->getRequest('value'));
                    break;
                }
            } else if ($this->hasRequest('hash')) {
                // The 'value' arguement was not set, check if hash is an API key.
                if ($this->hasAPIKey()) {
                    /**
                    * The 'hash' arguement is an API key, and the 'value' arguement
                    * is required but not set, throw error.
                    */
                    $this->throwErrorF(3, 'value');
                }
                // Get the user from the hash.
                $user = $this->getUser();
            } else {
                // Nor the 'value' arguement or the 'hash' arguement has been set, throw error.
                $this->throwErrorF(3, 'value');
                break;
            }
        }
    
        switch (strtolower($this->getAction())) {
            case 'getalerts':
                /**
                * Grabs the alerts from the specified user, if type is not specified, 
                * default (recent alerts) is used instead.
                * 
                * NOTE: The 'value' arguement will only work for the user itself and
                *       not on others users unless the permission arguement for the 
                *       'getalerts' action is changed (default permission: private).
                *
                * Options for the 'type' arguement are:
                *     - fetchPopupItems: Fetch alerts viewed in the last options:alertsPopupExpiryHours hours.
                *   - fetchRecent:     Fetch alerts viewed in the last options:alertExpiryDays days.
                *   - fetchAll:        Fetch alerts regardless of their view_date.
                *
                * For more information, see /library/XenForo/Model/Alert.php.
                *
                * EXAMPLES: 
                *   - api.php?action=getAlerts&hash=USERNAME:HASH
                *   - api.php?action=getAlerts&type=fetchAll&hash=USERNAME:HASH
                *   - api.php?action=getAlerts&value=USERNAME&hash=USERNAME:HASH
                *   - api.php?action=getAlerts&value=USERNAME&type=fetchAll&hash=USERNAME:HASH
                *   - api.php?action=getAlerts&value=USERNAME&hash=API_KEY
                *   - api.php?action=getAlerts&value=USERNAME&type=fetchAll&hash=API_KEY
                */
                /* 
                * Check if the request has the 'type' arguement set, 
                * if it doesn't it uses the default (fetchRecent).
                */
                if ($this->hasRequest('type')) {
                    if (!$this->getRequest('type')) {
                        // Throw error if the 'type' arguement is set but empty.
                        $this->throwErrorF(1, 'type');
                        break;
                    }
                    // Use the value from the 'type' arguement to get the alerts.
                    $data = $user->getAlerts($this->getRequest('type'));
                } else {
                    // Use the default type to get the alerts.
                    $data = $user->getAlerts();
                }
                // Send the response.
                $this->sendResponse($data);
                break;
            case 'getuser': 
                /**
                * Grabs and returns an user object.
                * 
                * EXAMPLES: 
                *   - api.php?action=getUser&hash=USERNAME:HASH
                *   - api.php?action=getUser&value=USERNAME&hash=USERNAME:HASH
                *   - api.php?action=getUser&value=USERNAME&hash=API_KEY
                */
                $data = $user->getData();
                
                /*
                * Run through an additional permission check if the request is
                * not using an API key, unset some variables depending on the 
                * user level.
                */
                if (!$this->hasAPIKey()) {
                    // Unset variables since the API key isn't used.
                    if (isset($data['style_id'])) {
                        unset($data['style_id']);
                    }
                    if (isset($data['display_style_group_id'])) {
                        unset($data['display_style_group_id']);
                    }
                    if (isset($data['permission_combination_id'])) {
                        unset($data['permission_combination_id']);
                    }
                    if (!$this->getUser()->isAdmin()) {
                        // Unset variables if user is not an admin.
                        if (isset($data['is_banned'])) {
                            unset($data['is_banned']);
                        }
                    }
                    if (!$this->getUser()->isModerator()) {
                        // Unset variables if user is not a moderator.
                        if (isset($data['user_state'])) {
                            unset($data['user_state']);
                        }
                        if (isset($data['visible'])) {
                            unset($data['visible']);
                        }
                        if (isset($data['email'])) {
                            unset($data['email']);
                        }
                    } 
                    if ($this->getUser()->getID() != $user->getID()) {
                        // Unset variables if user does not equal the requested user by the 'value' arguement.
                        if (isset($data['language_id'])) {
                            unset($data['language_id']);
                        }
                        if (isset($data['message_count'])) {
                            unset($data['message_count']);
                        }
                        if (isset($data['conversations_unread'])) {
                            unset($data['conversations_unread']);
                        }
                        if (isset($data['alerts_unread'])) {
                            unset($data['alerts_unread']);
                        }
                    }
                }
                // Send the response.
                $this->sendResponse($data);
                break;
            case 'getavatar': 
                /**
                * Returns the avatar of the requested user.
                *
                * Options for the 'size' arguement are:
                *   - s (Small)
                *   - m (Medium)
                *   - l (Large)
                *
                * NOTE: The default avatar size is 'Medium'.
                * 
                * EXAMPLES: 
                *   - api.php?action=getAvatar&hash=USERNAME:HASH
                *   - api.php?action=getAvatar&size=M&hash=USERNAME:HASH
                *   - api.php?action=getAvatar&value=USERNAME&hash=USERNAME:HASH
                *   - api.php?action=getAvatar&value=USERNAME&size=M&hash=USERNAME:HASH
                *   - api.php?action=getAvatar&value=USERNAME&hash=API_KEY
                *   - api.php?action=getAvatar&value=USERNAME&size=M&hash=API_KEY
                */
                if ($this->hasRequest('size')) {
                    if (!$this->getRequest('size')) {
                        // Throw error if the 'size' arguement is set but empty.
                        $this->throwErrorF(1, 'size');
                        break;
                    }
                    // Use the value from the 'size' arguement.
                    $size = strtolower($this->getRequest('size'));
                    if (!in_array($size, array('s', 'm', 'l'))) {
                        /**
                        * The value from the 'size' arguement was not valid,
                        * use default size (medium) instead.
                        */
                        $size = 'm';
                    }
                } else {
                    // No specific size was requested, use default size (medium):
                    $size = 'm';
                }
                // Send the response.
                $this->sendResponse(array('avatar' => $user->getAvatar($size)));
                break;
            case 'getactions':
                /**
                * Returns the actions and their permission levels.
                *
                * EXAMPLE:
                *   - api.php?action=getActions
                */
                /*
                
                // TODO: Only show actions depending on what permission level the user is.
                $temp = array();
                foreach ($this->actions as $action => $permission) {
                    $temp[$action] = $permission;
                }
                */
                // Send the response.
                $this->sendResponse($this->actions);
                break;
            case 'getusers': 
                /**
                * Searches through the usernames depending on the input.
                *
                * NOTE: Asterisk (*) can be used as a wildcard.
                *
                * EXAMPLE:
                *   - api.php?action=getUsers&value=Contex
                *   - api.php?action=getUsers&value=Cont*
                *   - api.php?action=getUsers&value=C*
                */
                if (!$this->hasRequest('value')) {
                    // The 'value' arguement has not been set, throw error.
                    $this->throwErrorF(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' arguement is set but empty.
                    $this->throwErrorF(1, 'value');
                    break;
                }
                
                // Replace the wildcard with '%' for the SQL query.
                $string = str_replace('*', '%', $this->getRequest('value'));
                
                // Perform the SQL query and grab all the usernames.
                $results = $this->xenAPI->getDatabase()->fetchAll("SELECT `username` FROM `xf_user` WHERE `username` LIKE '$string'");
                
                // Send the response.
                $this->sendResponse($results);
                break;
            case 'getgroup': 
                /**
                * Returns the group information depending on the 'value' arguement.
                *
                * NOTE: Only group titles, user titles and group ID's can be used for the 'value' parameter.
                *
                * EXAMPLE:
                *   - api.php?action=getGroup&value=1
                *   - api.php?action=getGroup&value=Guest
                */
                if (!$this->hasRequest('value')) {
                    // The 'value' arguement has not been set, throw error.
                    $this->throwErrorF(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' arguement is set but empty.
                    $this->throwErrorF(1, 'value');
                    break;
                }
                $string = $this->getRequest('value');
                
                // Check if the 'value' arguement is a number (ID).
                if (is_numeric($string)) {
                    // The 'value' arguement was a number, search by the group ID.
                    $group = $this->xenAPI->getDatabase()->fetchRow("SELECT * FROM `xf_user_group` WHERE `user_group_id` = $string");
                } else {
                    // The 'value' arguement was not a number, search by the group title and user title instead.
                    $group = $this->xenAPI->getDatabase()->fetchRow("SELECT * FROM `xf_user_group` WHERE `title` = '$string' OR `user_title` = '$string'");
                }
                if (!$group) {
                    // Could not find any groups, throw error.
                    $this->throwErrorF(7, $string);
                } else {
                    // Group was found, send response.
                    $this->sendResponse($group);
                }
                break;
            case 'authenticate': 
                /**
                * Authenticates the user and returns the hash that the user has to use for future requests.
                *
                * EXAMPLE:
                *   - api.php?action=authenticate&username=USERNAME&password=PASSWORD
                */
                if (!$this->hasRequest('username')) {
                    // The 'username' arguement has not been set, throw error.
                    $this->throwErrorF(3, 'username');
                    break;
                } else if (!$this->getRequest('username')) {
                    // Throw error if the 'username' arguement is set but empty.
                    $this->throwErrorF(1, 'username');
                    break;
                } else if (!$this->hasRequest('password')) {
                    // The 'password' arguement has not been set, throw error.
                    $this->throwErrorF(3, 'password');
                    break;
                } else if (!$this->getRequest('password')) {
                    // Throw error if the 'password' arguement is set but empty.
                    $this->throwErrorF(1, 'password');
                    break;
                }
                // Get the user object.
                $user = $this->xenAPI->getUser($this->getRequest('username'));
                if (!$user->isRegistered()) {
                    // Requested user was not registered, throw error.
                    $this->throwErrorF(4, $this->getRequest('username'));
                } else {
                    // Requested user was registered, check authentication.
                    if ($user->validateAuthentication($this->getRequest('password'))) {
                        // Authentication was valid, grab the user's authentication record.
                        $record = $user->getAuthenticationRecord();
                        $ddata = unserialize($record['data']);
                        // Send the hash in responsel.
                        $this->sendResponse(array('hash' => $ddata['hash']));
                    } else {
                        // The username or password was wrong, throw error.
                        $this->throwErrorF(5, 'Invalid username or password!');
                    }
                }
                break;
            default:
                // Action was supported but has not yet been added to the switch statement, throw error.
                $this->throwErrorF(11, $this->getAction());
        }
    }
    
    /**
    * Send the response array in JSON.
    */
    public function sendResponse($data) {
        if ($this->hasRequest('performance')) {
    		global $time_start;
			$time_end = microtime(true);
			$data['execution_time'] = $time_end - $time_start;
		}
        die(json_encode($data));
    }
}

/**
* The XenAPI class provides all the functions and variables 
* that are needed to use XenForo's classes and functions.
*/
class XenAPI {
    private $xfDir, $models;
    
    /**
    * Default consturctor, instalizes XenForo classes and models.
    */
    public function __construct() {
        $this->xfDir = dirname(__FILE__);
        require($this->xfDir . '/library/XenForo/Autoloader.php');
        XenForo_Autoloader::getInstance()->setupAutoloader($this->xfDir. '/library');
        XenForo_Application::initialize($this->xfDir . '/library', $this->xfDir);
        XenForo_Application::set('page_start_time', microtime(true));
        $this->models = new Models();
        $this->models->setUserModel(XenForo_Model::create('XenForo_Model_User'));
        $this->models->setAlertModel(XenForo_Model::create('XenForo_Model_Alert'));
        $this->models->setUserFieldModel(XenForo_Model::create('XenForo_Model_UserField'));
        $this->models->setAvatarModel(XenForo_Model::create('XenForo_Model_Avatar'));
        $this->models->setModel('database', XenForo_Application::get('db'));
    }
    
    /**
    * Returns the Database model.
    */
    public function getDatabase() {
        return $this->models->getModel('database');
    }
    
    /**
    * Returns the array of all the models.
    */
    public function getModels() {
        return $this->models;
    }
    
    /**
    * Grabs the User class of the last registered user.
    */
    public function getLatestUser() {
        return new User($this->models, $this->models->getUserModel()->getLatestUser());
    }
    
    /**
    * Returns the total count of registered users on XenForo.
    */
    public function getTotalUsersCount() {
        return $this->models->getUserModel()->countTotalUsers();
    }
    
    /**
    * Returns the User class of the $input parameter.
    *
    * The $input parameter can be an user ID, username or e-mail.
    * Returns false if $input is null.
    */
    public function getUser($input) {
        if ($input == false || $input == null) {
            return false;
        } else if (is_numeric($input)) {
            // $input is a number, grab the user by an ID.
            $user = new User($this->models, $this->models->getUserModel()->getUserById($input));
            if (!$user->isRegistered()) {
                // The user ID was not found, grabbing the user by the username instead.
                return new User($this->models, $this->models->getUserModel()->getUserByName($input));
            }
            return $user;
        } else if($this->models->getUserModel()->couldBeEmail($input)) {
            // $input is an e-mail, return the user of the e-mail.
            return new User($this->models, $this->models->getUserModel()->getUserByEmail($input));
        } else {
            // $input is an username, return the user of the username.
            return new User($this->models, $this->models->getUserModel()->getUserByName($input));
        }
    }
}

/**
* This class contains all the required models of XenForo.
*/
class Models {
    private $models = array();
    
    /**
    * Returns the array of all the models. 
    */
    public function getModels() {
        return $this->models;
    }
    
    /**
    * Returns the model defined by the parameter $model.
    */
    public function getModel($model) {
        return $this->models[$model];
    }
    
    /**
    * Sets the model of the parameter $model.
    */
    public function setModel($name, $model) {
        $this->models[$name] = $model;
    }
    
    /**
    * Sets the user model.
    */
    public function setUserModel($userModel) {
        $this->models['userModel'] = $userModel;
    }
    
    /**
    * Returns the user model.
    */
    public function getUserModel() {
        return $this->models['userModel'];
    }
    
    /**
    * Sets the alert model.
    */
    public function setAlertModel($alertModel) {
        $this->models['alertModel'] = $alertModel;
    }
    
    /**
    * Returns the alert model.
    */
    public function getAlertModel() {
        return $this->models['alertModel'];
    }
    
    /**
    * Sets the userfield model.
    */
    public function setUserFieldModel($userFieldModel) {
        $this->models['userFieldModel'] = $userFieldModel;
    }
    
    /**
    * Returns the userfield model.
    */
    public function getUserFieldModel() {
        return $this->models['userFieldModel'];
    }
    
    /**
    * Sets the avatar model.
    */
    public function setAvatarModel($avatarModel) {
        $this->models['avatarModel'] = $avatarModel;
    }
    
    /**
    * Returns the avatar model.
    */
    public function getAvatarModel() {
        return $this->models['avatarModel'];
    }
    
    /**
    * Returns the database model.
    */
    public function getDatabase() {
        return $this->getModel('database');
    }
}    

/**
* This class contains all the functions and all the relevant data of a XenForo user.
*/
class User {
    private $models, $data, $registered = false;
    
    /**
    * Default constructor.
    */
    public function __construct($models, $data) {
        $this->models = $models;
        $this->data = $data;
        if (!empty($data)) {
            $this->registered = true;
        }
    }
    
    /**
    * Returns an array which contains all the data of the user.
    */
    public function getData() {
        return $this->data;
    }
    
    /**
    * Returns all the alerts and relevant information regarding the alerts.
    */
    public function getAlerts($type = 'fetchRecent') {
        /* 
        * Options are:
        *   - fetchPopupItems: Fetch alerts viewed in the last options:alertsPopupExpiryHours hours.
        *   - fetchRecent:     Fetch alerts viewed in the last options:alertExpiryDays days.
        *   - fetchAll:        Fetch alerts regardless of their view_date.
        *
        * For more information, see /library/XenForo/Model/Alert.php.
        */
        $types = array('fetchPopupItems', 'fetchRecent', 'fetchAll');
        if (!in_array($type, $types)) {
            $type = 'fetchRecent';
        }
        return $this->models->getAlertModel()->getAlertsForUser($this->getID(), $type);
    }
    
    /**
    * Returns the ID of the user.
    */
    public function getID() {
        return $this->data['user_id'];
    }
    
    /**
    * Returns the username of the user.
    */
    public function getUsername() {
        return $this->data['username'];
    }
    
    /**
    * Returns the email of the user.
    */
    public function getEmail() {
        return $this->data['email'];
    }
    
    /**
    * Returns the avatar URL of the user.
    */
    public function getAvatar($size) {
        if ($this->data['gravatar']) {
            return XenForo_Template_Helper_Core::getAvatarUrl($this->data, $size);
        } else if (!empty($this->data['avatar_date'])) {
            return 'http://' . $_SERVER['HTTP_HOST'] . '/' . XenForo_Template_Helper_Core::getAvatarUrl($this->data, $size, 'custom');
        } else {
            return 'http://' . $_SERVER['HTTP_HOST'] . '/' . XenForo_Template_Helper_Core::getAvatarUrl($this->data, $size, 'default');
        }
    }
    
    /**
    * Returns if the user is registered or not.
    */
    public function isRegistered() {
        return $this->registered;
    }
    
    /**
    * Returns true if the user is a global moderator.
    */
    public function isModerator() {
        return $this->data['is_moderator'] == 1;
    }
    
    /**
    * Returns true if the user an administrator.
    */
    public function isAdmin() {
        return $this->data['is_admin'] == 1;
    }
    
    /**
    * Returns true if the user is banned.
    */
    public function isBanned() {
        return $this->data['is_banned'] == 1;
    }
    
    /**
    * Returns the authentication record of the user.
    */
    public function getAuthenticationRecord() {
        return $this->models->getUserModel()->getUserAuthenticationRecordByUserId($this->data['user_id']); 
    }
    
    /**
    * Verifies the password of the user. 
    */
    public function validateAuthentication($password) {
        if (strlen($password) == 64) {
            $record = $this->getAuthenticationRecord();
            $ddata = unserialize($record['data']);
            return $ddata['hash'] == $password;
        } else {
            return $this->models->getUserModel()->validateAuthentication($this->data['username'], $password); 
        }
    }
    
    /**
    * Returns the amount of unread alerts.
    */
    public function getUnreadAlertsCount() {
        return $this->models->getUserModel()->getUnreadAlertsCount($this->getID()); 
    }
}

/**
* This class contains all the relevant information about the visitor that performed the request.
*/
class Visitor {
    /*
    * Returns the IP of the visitor.
    */
    public static function getIP() {
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } else if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else if(isset($_SERVER['REMOTE_ADDR'])) {
            return $_SERVER['REMOTE_ADDR'];
        }
        return NULL;
    }

    /*
    * Returns the User Agent of the visitor.
    */
    public static function getUserAgent() {
        if (isset($_SERVER['HTTP_USER_AGENT'])) { 
            return $_SERVER['HTTP_USER_AGENT']; 
        }
        return NULL;
    }

    /*
    * Returns the referer of the visitor.
    */
    public static function getReferer() {
        if (isset($_SERVER['HTTP_REFERER'])) { 
            return $_SERVER['HTTP_REFERER']; 
        }
        return NULL;
    }
}
?>
