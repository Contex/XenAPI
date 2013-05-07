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
$time_start = microtime(TRUE);
$options = array('api_key' => 'API_KEY');
$restAPI = new RestAPI($options); 

if ($restAPI->getAPIKey() != NULL && $restAPI->getAPIKey() == 'API_KEY') { 
    // API is set but not changed from the default API key.
    $restAPI->throwError(17);
} else if ($restAPI->getAPIKey() != NULL && !$restAPI->hasRequest('hash') && !$restAPI->isPublicAction()) {
    // Hash argument is required and was not found, throw error.
    $restAPI->throwError(3, 'hash');
} else if (!$restAPI->getHash() && !$restAPI->isPublicAction()) {
    // Hash argument is empty or not set, throw error. 
    $restAPI->throwError(1, 'hash');
} else if (!$restAPI->isAuthenticated() && !$restAPI->isPublicAction()) {
    // Hash is not valid and action is not public, throw error.
    $restAPI->throwError(6, $restAPI->getHash(), 'hash');
} else if (!$restAPI->hasRequest('action')) {
    // Action argument was not found, throw error.
    $restAPI->throwError(3, 'action');
} else if (!$restAPI->getAction()) {
    // Action argument is empty or not set, throw error. 
    $restAPI->throwError(1, 'action');
} else if (!$restAPI->isSupportedAction()) {
    // Action is not supported, throw error.
    $restAPI->throwError(2, $restAPI->getAction());
} else if (!$restAPI->isPermitted()) {
    // User does not have permission to use this action, throw error.
    if ($restAPI->hasRequest('value') && $restAPI->isUserAction()) {
        $restAPI->throwError(9, $restAPI->getAction());
    } else {
        $restAPI->throwError(10, $restAPI->getAction());
    }
}
// Process the request.
$restAPI->processRequest();

class RestAPI {
    const version = '1.3.dev';
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
                             'authenticate' => 'public',
                             'getactions'   => 'public', 
                             'getaddon'     => 'administrator',
                             'getaddons'    => 'administrator',
                             'getalerts'    => 'private', 
                             'getavatar'    => 'public', 
                             'getgroup'     => 'public', 
                             'getresource'  => 'administrator',
                             'getresources' => 'administrator',
                             'getstats'     => 'public',
                             'getthread'    => 'public',
                             'getthreads'   => 'public',
                             'getuser'      => 'authenticated', 
                             'getusers'     => 'public');
    
    // Array of actions that are user specific and require an username, ID or email for the 'value' parameter.
    private $user_actions = array('getalerts', 'getuser', 'getavatar');
    
    // List of errors, this is where the 'throwErrorF' function gets the messages from.
    private $errors = array(
                            0  => 'Unknown error', 
                            1  => 'Argument: "{ERROR}", is empty/missing a value',
                            2  => '"{ERROR}", is not a supported action',
                            3  => 'Missing argument: "{ERROR}"',
                            4  => 'No {ERROR} found with the argument: "{ERROR2}"',
                            5  => 'Authentication error: "{ERROR}"',
                            6  => '"{ERROR}" is not a valid {ERROR2}',
                            7  => 'PLACEHOLDER',
                            8  => 'PLACEHOLDER',
                            9  => 'You are not permitted to use the "{ERROR}" action on others (remove the value argument)',
                            10 => 'You do not have permission to use the "{ERROR}" action',
                            11 => '"{ERROR}" is a supported action but there is no code for it yet',
                            12 => '"{ERROR}" is a unknown request method.',
                            13 => '"{ERROR}" is not an installed addon.',
                            14 => '"{ERROR}" is not an author of any resources.',
                            15 => 'Could not find a resource with ID "{ERROR}".',
                            16 => 'Could not find a required model to perform this request: "{ERROR}".',
                            17 => 'The API key has not been changed, make sure you use another API key before using this API.',
                            18 => '"{ERROR} is a unknown permission name, the request was terminated.',
                            19 => 'Could not find a thread with ID "{ERROR}".',
                            20 => '{ERROR} not have permissions to view {ERROR2}.',
                            21 => 'The "{ERROR}" argument has to be a number.',
                            22 => 'The argument for "order_by", "{ERROR}", was not found in the list available order by list: "({ERROR2})".');

    private $xenAPI, $method, $data = array(), $hash = FALSE, $apikey = FALSE;

    /**
    * Default constructor for the RestAPI class.
    * The data gets set here depending on what kind of request method is being used.
    */
    public function __construct($options = array()) {
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
                $this->throwError(12, $this->method);
                break;
        }
        $this->xenAPI = new XenAPI();

        // Check if there are any options.
        if (is_array($options) && count($options) > 0) {
            if (isset($options['api_key']) && !empty($options['api_key'])) {
                // Set the API key.
                $this->apikey = $options['api_key'];
            }
        }

        // Lowercase the key data, ignores the case of the arguments.
        $this->data = array_change_key_case($this->data);
        if ($this->hasRequest('hash')) {
            // Sets the hash variable if the hash argument is set.
            $this->hash = $this->getRequest('hash');
        }
        // Check if grab_as by argument is set.
        if ($this->hasRequest('grab_as') && $this->hasAPIKey()) {
            if (!$this->getRequest('grab_as')) {
                // Throw error if the 'grab_as' argument is set but empty.
                $this->throwError(1, 'grab_as');
            }
            // Create a user object with the 'grab_as' argument.
            $this->grab_as = $this->xenAPI->getUser($this->getRequest('grab_as'));
            if (!$this->grab_as->isRegistered()) {
                // Throw error if the 'grab_as' user is not registered.
                $this->throwError(4, 'user', $this->getRequest('grab_as'));
                break;
            }
        }
        // Check if order by argument is set.
        if ($this->hasRequest('order_by')) {
            if (!$this->getRequest('order_by')) {
                // Throw error if the 'order_by' argument is set but empty.
                $this->throwError(1, 'order_by');
            }
            $this->order_by = $this->getRequest('order_by');
        }
        // Check if order argument is set.
        if ($this->hasRequest('order')) {
            if (!$this->getRequest('order')) {
                // Throw error if the 'order' argument is set but empty.
                $this->throwError(1, 'order');
            }
            $this->order = strtolower($this->getRequest('order'));
            if ($this->order == 'd' || $this->order == 'desc' || $this->order == 'descending') {
                // Order is descending (10-0).
                $this->order = 'desc';
            } else if ($this->order == 'a' || $this->order == 'asc' || $this->order == 'ascending') {
                // Order is ascending (0-10).
                $this->order = 'asc';
            } else {
                // Order is unknown, default to descending (10-0).
                $this->order = 'desc';
            }
        } else {
            // Order is not set, default to descending (10-0).
            $this->order = 'desc';
        }
        // Check if limit argument is set.
        if ($this->hasRequest('limit')) {
            if (!$this->getRequest('limit') && (is_numeric($this->getRequest('limit')) && $this->getRequest('limit') != 0)) {
                // Throw error if the 'limit' argument is set but empty.
                $this->throwError(1, 'limit');
            } else if (!is_numeric($this->getRequest('limit'))) {
                // Throw error if the 'limit' argument is set but not a number.
                $this->throwError(21, 'limit');
            }
            $this->limit = $this->getRequest('limit');
        } else {
            // Limit is not set, default to 100.
            $this->limit = 100;
        }
    }

    /**
    * Returns the XenAPI, returns NULL if the XenAPI was not set.
    */
    public function getXenAPI() {
        return $this->xenAPI;
    }

    /**
    * Returns the API key, returns FALSE if an API key was not set.
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
    * Return the hash, returns FALSE if the hash was not set.
    */
    public function getHash() {
        return $this->hash;
    }
    
    /**
    * Checks if the request is authenticated.
    * Returns TRUE if the hash equals the API key.
    * Returns TRUE if the hash equals the user hash.
    * Returns FALSE if none of the above are TRUE.
    */
    public function isAuthenticated() {
        if ($this->getHash()) {
            // Hash argument is set, continue.
            if ($this->getHash() == $this->getAPIKey()) {
                // The hash equals the API key, return TRUE.
                return TRUE;
            }
            if (strpos($this->getHash(), ':') !== FALSE) {
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
                        return TRUE;
                    }
                }
            }
        }
        return FALSE;
    }
    
    /**
    * Checks if the request is permitted.
    * Returns TRUE if API key is set and valid or the action's permission is public.
    */
    public function isPermitted() {
        $permission = $this->getActionPermission();
        // Check if the request is authenticated and it's an user hash (and not an API key).
        if ($this->isAuthenticated() && $this->getUser()) {
            switch ($permission) {
                case 'public':
                    return TRUE;
                case 'authenticated':
                    return TRUE;
                case 'moderator':
                    return $this->getUser()->isModerator();
                case 'administrator':
                    return $this->getUser()->isAdmin();
                case 'private':
                    // Check if the 'value' argument is set.
                    if ($this->hasRequest('value') && $this->getRequest('value')) {
                        /**
                        * Returns TRUE if the 'value' argument equals the username of the user hash.
                        * In other words, the request is not permitted if 'value' != username.
                        */
                        return $this->getUser()->getUsername() == $this->getRequest('value');
                    }
                    // The value argument is not, request is permitted, return TRUE.
                    return TRUE;
                default:
                    $this->throwError(17, $permission);
                    return FALSE;
            }
        }
        // Returns TRUE if permission of the action is public or the request has a valid API key.
        return $permission == 'public' || $this->hasAPIKey();
    }
    
    /**
    * Returns TRUE if the request has an API key that is valid, returns FALSE if not.
    */
    public function hasAPIKey() {
        if ($this->getHash()) {
            return $this->getHash() == $this->getAPIKey();
        }
        return FALSE;
    }
    
    /**
    * Returns the User class of the username if the hash is set and is an userhash.
    * Returns FALSE if the hash is not an userhash.
    */
    public function getUser() {
        if (isset($this->user) && $this->user != NULL) {
            return $this->user;
        } else if (isset($this->grab_as) && $this->grab_as != NULL) {
            return $this->grab_as;
        } else if (strpos($this->getHash(), ':') !== FALSE) {
            $array = explode(':', $this->getHash());
            $this->user = $this->xenAPI->getUser($array[0]);
            return $this->user;
        }    
        return FALSE;
    }

    /**
    *
    */
    public function checkOrderBy($order_by_array) {
        if ($this->hasRequest('order_by')) {
            if (!$this->getRequest('order_by')) {
                // Throw error if the 'order_by' argument is set but empty.
                $this->throwError(1, 'order_by');
                break;
            } 
            if (!in_array(strtolower($this->getRequest('order_by')), $order_by_array)) {
                // Throw error if the 'order_by' argument is set but could not be found in list of allowed order_by.
                $this->throwError(22, $this->getRequest('order_by'), implode(', ', $order_by_array));
                break;
            }
            return strtolower($this->getRequest('order_by'));
        }
        return FALSE;
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
        return (isset($this->data['action']) && isset($this->actions[strtolower($this->getAction())])) 
                ? strtolower($this->actions[strtolower($this->getAction())]) 
                : NULL;
    }
    
    /**
    * Returns TRUE if the '$key' is set a argument, returns FALSE if not.
    */
    public function hasRequest($key) {
        return isset($this->data[strtolower($key)]);
    }
    
    /**
    * Gets the data of the '$key', returns FALSE if the '$key' argument was not set.
    */
    public function getRequest($key) {
        if ($this->hasRequest($key)) {
            return $this->data[strtolower($key)];
        } else {
            return FALSE;
        }
    }
    
    /**
    * Returns the array of all the arguments in the request.
    */
    public function getData() {
        return $this->data;
    }
    
    /**
    * Returns TRUE if the action is supported, FALSE if not.
    */
    public function isSupportedAction() {
        return isset($this->data['action']) && array_key_exists(strtolower($this->data['action']), $this->actions);
    }
    
    /**
    * Returns TRUE if the action is a public action (does not require a hash), FALSE if not.
    */
    public function isPublicAction() {
        return isset($this->data['action']) && isset($this->actions[strtolower($this->data['action'])]) && strtolower($this->actions[strtolower($this->data['action'])]) == 'public';
    }
    
    /**
    * Returns TRUE if the action is a user action (the 'value' parameter has to be an username/id/email), FALSE if not.
    */
    public function isUserAction() {
        return isset($this->data['action']) && in_array(strtolower($this->data['action']), $this->user_actions);
    }

    /**
    * Gets the error message and replaces {ERROR} with the $extra parameter.
    */
    public function getError($error, $extra = NULL, $extra2 = NULL) {
        if (array_key_exists($error, $this->errors)) {
            $error_string = $this->errors[$error];
            if ($extra != NULL) {
                $error_string = str_replace('{ERROR}', $extra, $error_string);
            } 
            if ($extra2 != NULL) {
                $error_string = str_replace('{ERROR2}', $extra2, $error_string);
            }
            return $error_string;
        } else {
            return $this->errors[0];
        }
    }
    
    /**
    * Throw the error message.
    */
    public function throwError($error, $extra = NULL, $extra2 = NULL) {
        $this->sendResponse(array('error' => $error, 'message' => $this->getError($error, $extra, $extra2)));
    }
    
    /**
    * Processes the REST request.
    */
    public function processRequest() {
        // Check if the action is an user action.
        if ($this->isUserAction()) {
            if ($this->hasRequest('value')) {
                if (!$this->getRequest('value')) {
                    // Throw error if the 'value' argument is set but empty.
                    $this->throwError(1, 'value');
                    break;
                }
                // Create a user variable with the 'value' argument.
                $user = $this->xenAPI->getUser($this->getRequest('value'));
                if (!$user->isRegistered()) {
                    // Throw error if the 'value' user is not registered.
                    $this->throwError(4, 'user', $this->getRequest('value'));
                    break;
                }
            } else if ($this->hasRequest('hash')) {
                // The 'value' argument was not set, check if hash is an API key.
                if ($this->hasAPIKey() && !isset($this->grab_as)) {
                    /**
                    * The 'hash' argument is an API key, and the 'value' argument
                    * is required but not set, throw error.
                    */
                    $this->throwError(3, 'value');
                }
                // Get the user from the hash.
                $user = $this->getUser();
            } else {
                // Nor the 'value' argument or the 'hash' argument has been set, throw error.
                $this->throwError(3, 'value');
                break;
            }
        }
    
        switch (strtolower($this->getAction())) {
            case 'authenticate': 
                /**
                * Authenticates the user and returns the hash that the user has to use for future requests.
                *
                * EXAMPLE:
                *   - api.php?action=authenticate&username=USERNAME&password=PASSWORD
                */
                if (!$this->hasRequest('username')) {
                    // The 'username' argument has not been set, throw error.
                    $this->throwError(3, 'username');
                    break;
                } else if (!$this->getRequest('username')) {
                    // Throw error if the 'username' argument is set but empty.
                    $this->throwError(1, 'username');
                    break;
                } else if (!$this->hasRequest('password')) {
                    // The 'password' argument has not been set, throw error.
                    $this->throwError(3, 'password');
                    break;
                } else if (!$this->getRequest('password')) {
                    // Throw error if the 'password' argument is set but empty.
                    $this->throwError(1, 'password');
                    break;
                }
                // Get the user object.
                $user = $this->xenAPI->getUser($this->getRequest('username'));
                if (!$user->isRegistered()) {
                    // Requested user was not registered, throw error.
                    $this->throwError(4, 'user', $this->getRequest('username'));
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
                        $this->throwError(5, 'Invalid username or password!');
                    }
                }
                break;
            case 'getalerts':
                /**
                * Grabs the alerts from the specified user, if type is not specified, 
                * default (recent alerts) is used instead.
                * 
                * NOTE: The 'value' argument will only work for the user itself and
                *       not on others users unless the permission argument for the 
                *       'getalerts' action is changed (default permission: private).
                *
                * Options for the 'type' argument are:
                *     - fetchPopupItems: Fetch alerts viewed in the last options:alertsPopupExpiryHours hours.
                *     - fetchRecent:     Fetch alerts viewed in the last options:alertExpiryDays days.
                *     - fetchAll:        Fetch alerts regardless of their view_date.
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
                * Check if the request has the 'type' argument set, 
                * if it doesn't it uses the default (fetchRecent).
                */
                if ($this->hasRequest('type')) {
                    if (!$this->getRequest('type')) {
                        // Throw error if the 'type' argument is set but empty.
                        $this->throwError(1, 'type');
                        break;
                    }
                    // Use the value from the 'type' argument to get the alerts.
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
                        // Unset variables if user does not equal the requested user by the 'value' argument.
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
                * Options for the 'size' argument are:
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
                        // Throw error if the 'size' argument is set but empty.
                        $this->throwError(1, 'size');
                        break;
                    }
                    // Use the value from the 'size' argument.
                    $size = strtolower($this->getRequest('size'));
                    if (!in_array($size, array('s', 'm', 'l'))) {
                        /**
                        * The value from the 'size' argument was not valid,
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
                if ($this->hasRequest('value')) {
                    // Request has value.
                    if (!$this->getRequest('value')) {
                        // Throw error if the 'value' argument is set but empty.
                        $this->throwError(1, 'value');
                        break;
                    }
                    // Replace the wildcard with '%' for the SQL query.
                    $string = str_replace('*', '%', $this->getRequest('value'));
                } else if (!$this->hasRequest('order_by')) {
                    // Nor the 'value' argument or the 'order_by' argument has been set, throw error.
                    $this->throwError(3, 'value');
                    break;
                }

                // Check if the order by argument is set.
                $order_by_field = $this->checkOrderBy(array('user_id', 'message_count', 'conversations_unread', 'register_date', 'last_activity', 'trophy_points', 'alerts_unread', 'like_count'));
                
                // Perform the SQL query and grab all the usernames and user id's.
                $results = $this->xenAPI->getDatabase()->fetchAll("SELECT `user_id`, `username`" . ($this->hasRequest('order_by') ? ", `$order_by_field`" : '') . " FROM `xf_user`" . ($this->hasRequest('value') ? " WHERE `username` LIKE '$string'" : '') . ($this->hasRequest('order_by') ? " ORDER BY `$order_by_field` " . $this->order : '') . (($this->limit > 0) ? ' LIMIT ' . $this->limit : ''));
                
                // Send the response.
                $this->sendResponse($results);
                break;
            case 'getgroup': 
                /**
                * Returns the group information depending on the 'value' argument.
                *
                * NOTE: Only group titles, user titles and group ID's can be used for the 'value' parameter.
                *
                * EXAMPLE:
                *   - api.php?action=getGroup&value=1
                *   - api.php?action=getGroup&value=Guest
                */
                if (!$this->hasRequest('value')) {
                    // The 'value' argument has not been set, throw error.
                    $this->throwError(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' argument is set but empty.
                    $this->throwError(1, 'value');
                    break;
                }
                $string = $this->getRequest('value');
                
                // Check if the 'value' argument is a number (ID).
                if (is_numeric($string)) {
                    // The 'value' argument was a number, search by the group ID.
                    $group = $this->xenAPI->getDatabase()->fetchRow("SELECT * FROM `xf_user_group` WHERE `user_group_id` = $string");
                } else {
                    // The 'value' argument was not a number, search by the group title and user title instead.
                    $group = $this->xenAPI->getDatabase()->fetchRow("SELECT * FROM `xf_user_group` WHERE `title` = '$string' OR `user_title` = '$string'");
                }
                if (!$group) {
                    // Could not find any groups, throw error.
                    $this->throwError(4, 'group', $string);
                } else {
                    // Group was found, send response.
                    $this->sendResponse($group);
                }
                break;
            case 'getaddons':
                /**
                * Returns a list of addons, if a type is not specified or not supported, 
                * default (all) is used instead.
                *
                * Options for the 'type' argument are:
                *   - all:      This is default, and will return all the addons, ignoring if they are installed or not.
                *   - enabled:  Fetches all the addons that are enabled, ignoring the disabled ones.
                *   - disabled: Fetches all the addons that are disabled, ignoring the enabled ones.
                *
                * For more information, see /library/XenForo/Model/Alert.php.
                *
                * EXAMPLES: 
                *   - api.php?action=getAddons&hash=USERNAME:HASH
                *   - api.php?action=getAddons&hash=API_KEY
                *   - api.php?action=getAddons&type=enabled&hash=USERNAME:HASH
                *   - api.php?action=getAddons&type=enabled&hash=API_KEY
                */
                /* 
                * Check if the request has the 'type' argument set, 
                * if it doesn't it uses the default (all).
                */
                if ($this->hasRequest('type')) {
                    if (!$this->getRequest('type')) {
                        // Throw error if the 'type' argument is set but empty.
                        $this->throwError(1, 'type');
                        break;
                    }
                    // Use the value from the 'type' argument to get the alerts.
                    $installed_addons = $this->xenAPI->getAddons($this->getRequest('type'));
                } else {
                    // Use the default type to get the alerts.
                    $installed_addons = $this->xenAPI->getAddons();
                }
                // Create an array for the addons.
                $addons = array();
                // Loop through all the addons and strip out any information that we don't need.
                foreach ($installed_addons as $addon) {
                    $addons[] = Addon::getLimitedData($addon);
                }
                // Send the response.
                $this->sendResponse(array('count' => count($addons), 'addons' => $addons));
                break;
            case 'getaddon': 
                /**
                * Returns the addon information depending on the 'value' argument.
                *
                * NOTE: Only addon ID's can be used for the 'value' parameter.
                *       Addon ID's can be found by using the 'getAlerts' action.
                *
                * EXAMPLE:
                *   - api.php?action=getAddon&value=PostRating&hash=USERNAME:HASH
                *   - api.php?action=getAddon&value=PostRating&hash=API_KEY
                */
                if (!$this->hasRequest('value')) {
                    // The 'value' argument has not been set, throw error.
                    $this->throwError(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' argument is set but empty.
                    $this->throwError(1, 'value');
                    break;
                }
                $string = $this->getRequest('value');
                // Try to grab the addon from XenForo.
                $addon = $this->getXenAPI()->getAddon($string);
                if (!$addon->isInstalled()) {
                    // Could not find the addon, throw error.
                    $this->throwError(13, $string);
                } else {
                    // Addon was found, send response.
                    $this->sendResponse(Addon::getLimitedData($addon));
                }
                break;
            case 'getresources':
                /**
                * Returns a list of resources, either all the resources, 
                * or just the resources created by an author.
                *
                * NOTE: Only usernames and user ID's can be used for the 'author' parameter.
                *
                * EXAMPLES: 
                *   - api.php?action=getResources&hash=USERNAME:HASH
                *   - api.php?action=getResources&hash=API_KEY
                *   - api.php?action=getResources&author=Contex&hash=USERNAME:HASH
                *   - api.php?action=getResources&author=1&hash=API_KEY
                */
                /* 
                * Check if the request has the 'author' argument set, 
                * if it doesn't it uses the default (all).
                */
                if (!$this->getXenAPI()->getModels()->hasModel('resource')) {
                    $this->throwError(16, 'resource');
                    break;
                }
                if ($this->hasRequest('author')) {
                    if (!$this->getRequest('author')) {
                        // Throw error if the 'author' argument is set but empty.
                        $this->throwError(1, 'author');
                        break;
                    }
                    // Use the value from the 'author' argument to get the alerts.
                    $resources_list = $this->xenAPI->getResources($this->getRequest('author'));
                    if (count($resources_list) == 0) {
                       // Throw error if the 'author' is not the author of any resources.
                        $this->throwError(14, $this->getRequest('author'));
                        break;
                    }
                } else {
                    // Use the default type to get the alerts.
                    $resources_list = $this->getXenAPI()->getResources();
                }

                // Create an array for the resources.
                $resources = array();
                // Loop through all the resources and strip out any information that we don't need.
                foreach ($resources_list as $resource) {
                    $resources[] = Resource::getLimitedData($resource);
                }
                // Send the response.
                $this->sendResponse(array('count' => count($resources), 'resources' => $resources));
            case 'getresource': 
                /**
                * Returns the resource information depending on the 'value' argument.
                *
                * NOTE: Only resource ID's can be used for the 'value' parameter.
                *       Resource ID's can be found by using the 'getResources' action.
                *
                * EXAMPLE:
                *   - api.php?action=getResource&value=1&hash=USERNAME:HASH
                *   - api.php?action=getResource&value=1&hash=API_KEY
                */
                if (!$this->getXenAPI()->getModels()->hasModel('resource')) {
                    $this->throwError(16, 'resource');
                    break;
                }
                if (!$this->hasRequest('value')) {
                    // The 'value' argument has not been set, throw error.
                    $this->throwError(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' argument is set but empty.
                    $this->throwError(1, 'value');
                    break;
                }
                $string = $this->getRequest('value');
                // Try to grab the addon from XenForo.
                $resource = $this->getXenAPI()->getResource($string);
                if (!$resource->isValid()) {
                    // Could not find the resource, throw error.
                    $this->throwError(15, $string);
                } else {
                    // Resource was found, send response.
                    $this->sendResponse(Resource::getLimitedData($resource));
                }
                break;
            case 'getstats':
                /**
                * Returns a summary of stats.
                *
                * EXAMPLE:
                *   - api.php?action=getStats
                */
                $latest_user = $this->xenAPI->getLatestUser();
                $this->sendResponse(array(
                    'threads'             => $this->xenAPI->getStatsItem('threads'),
                    'posts'               => $this->xenAPI->getStatsItem('posts'),
                    'members'             => $this->xenAPI->getStatsItem('users'),
                    'latest_member'       => array('user_id' => $latest_user->getID(), 'username' => $latest_user->getUsername()),
                    'registrations_today' => $this->xenAPI->getStatsItem('registrations_today'),
                    'threads_today'       => $this->xenAPI->getStatsItem('threads_today'),
                    'posts_today'         => $this->xenAPI->getStatsItem('posts_today'),
                    'users_online'        => $this->xenAPI->getUsersOnlineCount($this->getUser())
                ));
                break;
            case 'getthread':
                /**
                * Returns the thread information depending on the 'value' argument.
                *
                * NOTE: Only thread ID's can be used for the 'value' parameter.
                *       Thread ID's can be found by using the 'getThreads' action.
                *
                *       The user needs permission to see the thread if the request is
                *       using a user hash and not an API key.
                *
                * EXAMPLE:
                *   - api.php?action=getThread&value=820&hash=USERNAME:HASH
                *   - api.php?action=getThread&value=820&hash=API_KEY
                */
                if (!$this->hasRequest('value')) {
                    // The 'value' argument has not been set, throw error.
                    $this->throwError(3, 'value');
                    break;
                } else if (!$this->getRequest('value')) {
                    // Throw error if the 'value' argument is set but empty.
                    $this->throwError(1, 'value');
                    break;
                }
                $string = $this->getRequest('value');
                // Try to grab the thread from XenForo.
                $thread = $this->getXenAPI()->getThread($string);
                if ($thread == NULL) {
                     // Could not find the thread, throw error.
                    $this->throwError(19, $string);
                } else if (!$this->getXenAPI()->canViewThread($this->getUser(), $thread)) {
                    if (!$this->hasAPIKey()) {
                        // Thread was found but the user is not permitted to view the thread.
                        $this->throwError(20, 'you do', 'this thread');
                    } else if ($this->hasAPIKey() && isset($this->grab_as)) {
                        // Thread was found but the 'grab_as' user is not permitted to view the thread.
                        $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this thread');
                    }
                } else {
                     // Thread was found, and the request was permitted.
                    $this->sendResponse($thread);
                }
                break;
            case 'getthreads':
                /**
                * Returns a list of threads.
                *
                * NOTE: Only usernames and user ID's can be used for the 'author' parameter.
                *
                * EXAMPLES: 
                *   - api.php?action=getThreads&hash=USERNAME:HASH
                *   - api.php?action=getThreads&hash=API_KEY
                *   - api.php?action=getThreads&author=Contex&hash=USERNAME:HASH
                *   - api.php?action=getThreads&author=1&hash=API_KEY
                */
                // Init variables.
                $conditions = array();
                $fetch_options = array('limit' => $this->limit);

                // Check if request has author.
                if ($this->hasRequest('author')) {
                    if (!$this->getRequest('author')) {
                        // Throw error if the 'author' argument is set but empty.
                        $this->throwError(1, 'author');
                        break;
                    }
                    // Grab the user object of the author.
                    $user = $this->xenAPI->getUser($this->getRequest('author'));
                    if (!$user->isRegistered()) {
                        // Throw error if the 'author' user is not registered.
                        $this->throwError(4, 'user', $this->getRequest('author'));
                        break;
                    }
                    // Add the user ID to the query conditions.
                    $conditions['user_id'] = $user->getID();
                }

                // Check if request has author.
                if ($this->hasRequest('node_id')) {
                    if (!$this->getRequest('node_id') && (is_numeric($this->getRequest('node_id')) && $this->getRequest('node_id') != 0)) {
                        // Throw error if the 'node_id' argument is set but empty.
                        $this->throwError(1, 'node_id');
                    } else if (!is_numeric($this->getRequest('node_id'))) {
                        // Throw error if the 'limit' argument is set but not a number.
                        $this->throwError(21, 'node_id');
                    }
                    if (!$this->xenAPI->getNode($this->getRequest('node_id'))) {
                        // Could not find any nodes, throw error.
                        $this->throwError(4, 'node', $this->getRequest('node_id'));
                    }
                    // Add the node ID to the query conditions.
                    $conditions['node_id'] = $this->getRequest('node_id');
                }

                // Check if the order by argument is set.
                $order_by_field = $this->checkOrderBy(array('title', 'post_date', 'view_count', 'reply_count', 'first_post_likes', 'last_post_date'));

                // Add the order by options to the fetch options.
                if ($this->hasRequest('order_by')) {
                    $fetch_options['order']          = $order_by_field;
                    $fetch_options['orderDirection'] = $this->order;
                }

                // Get the threads.
                $threads = $this->getXenAPI()->getThreads($conditions, $fetch_options, $this->getUser());

                // Send the response.
                $this->sendResponse(array('count' => count($threads), 'threads' => $threads));
        }
    }
    
    /**
    * Send the response array in JSON.
    */
    public function sendResponse($data) {
        if ($this->hasRequest('performance')) {
    		global $time_start;
			$time_end = microtime(TRUE);
			$data['execution_time'] = $time_end - $time_start;
		}
        header('Content-type: application/json');
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
        XenForo_Application::set('page_start_time', microtime(TRUE));
        $this->models = new Models();
        // TODO: Don't create models on init, only create them if they're being used (see Models::checkModel($model_name, $model)).
        $this->getModels()->setUserModel(XenForo_Model::create('XenForo_Model_User'));
        $this->getModels()->setAlertModel(XenForo_Model::create('XenForo_Model_Alert'));
        $this->getModels()->setUserFieldModel(XenForo_Model::create('XenForo_Model_UserField'));
        $this->getModels()->setAvatarModel(XenForo_Model::create('XenForo_Model_Avatar'));
        $this->getModels()->setModel('addon', XenForo_Model::create('XenForo_Model_AddOn'));
        $this->getModels()->setModel('database', XenForo_Application::get('db'));
        try {
            $this->getModels()->setModel('resource', XenForo_Model::create('XenResource_Model_Resource'));
        } catch (Exception $ignore) {
            // The resource model is missing, ignore the exceiption.
        }
    }
    
    /**
    * Returns the Database model.
    */
    public function getDatabase() {
        return $this->getModels()->getModel('database');
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
        return new User($this->getModels(), $this->getModels()->getUserModel()->getLatestUser());
    }
    
    /**
    * Returns the total count of registered users on XenForo.
    */
    public function getUserCount() {
        return $this->getModels()->getUserModel()->countTotalUsers();
    }

    /**
    * Returns a list of addons in the Addon class.
    */
    public function getAddons($type = 'all') {
        // TODO: add support to grab addon options.
        $type = strtolower($type);
        $allowed_types = array('all', 'enabled', 'disabled');
        if (!in_array($type, $allowed_types)) {
            $type = 'all';
        }
        $installed_addons = $this->getModels()->getModel('addon')->getAllAddOns();
        $addons = array();
        foreach ($installed_addons as $addon) {
            $temp_addon = new Addon($addon);
            if (($type == 'enabled' && $temp_addon->isEnabled()) || ($type == 'disabled' && !$temp_addon->isEnabled()) || $type == 'all') {
                $addons[] = $temp_addon;
            }
        }
        return $addons;
    }

    /**
    * Returns the Addon class of the $addon parameter.
    */
    public function getAddon($addon) {
        return new Addon($this->getModels()->getModel('addon')->getAddOnById($addon));
    }

    /**
    * Returns a list of resources.
    */
    public function getResources($author = NULL) {
        $resources_list = $this->getModels()->getModel('resource')->getResources();
        $resources = array();
        foreach ($resources_list as $resource) {
            $temp_resource = new Resource($resource);
            if ($author != NULL 
                && (((is_numeric($author) && $temp_resource->getAuthorUserID() != $author) 
                    || strtolower($temp_resource->getAuthorUsername()) != strtolower($author)))) {
                // The author input is not NULL and the resource is not owned by the author, skip the resource.
                continue;
            }
            $resources[] = $temp_resource;
        }
        return $resources;
    }

    /**
    * Returns the Resource class of the $resource parameter.
    */
    public function getResource($resource) {
        return new Resource($this->getModels()->getModel('resource')->getResourceById($resource));
    }

    /**
    * TODO
    */
    public function getStats($start = NULL, $end = NULL, $types = NULL) {
        $this->getModels()->checkModel('stats', XenForo_Model::create('XenForo_Model_Stats'));
        // TODO
        return $this->getModels()->getModel('stats')->getStatsData(time() - 5000, time());
    }

    public function getStatsItem($item) {
        $this->getModels()->checkModel('database', XenForo_Application::get('db'));
        switch ($item) {
            case 'users':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_user');
            case 'posts':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_post');
            case 'threads':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_thread');
            case 'registrations_today':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_user WHERE register_date > UNIX_TIMESTAMP(CURDATE())');
            case 'posts_today':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_post WHERE post_date > UNIX_TIMESTAMP(CURDATE()) AND position != 0');
            case 'threads_today':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_thread WHERE post_date > UNIX_TIMESTAMP(CURDATE())');
            default:
                return NULL;
        }
    }

    /**
    * TODO
    */
    public function getUsersOnlineCount($user = NULL) {
        $this->getModels()->checkModel('session', XenForo_Model::create('XenForo_Model_Session'));
        if ($user != NULL) {
            // USer parameter is not null, make sure to follow privacy of the users.
            $this->getModels()->checkModel('user', XenForo_Model::create('XenForo_Model_User'));
            // Check if the user can bypass user privacy.
            $bypass = $this->getModels()->getModel('user')->canBypassUserPrivacy($null, $user);
            $conditions = array(
                'cutOff' => array('>', $this->getModels()->getModel('session')->getOnlineStatusTimeout()),
                'getInvisible' => $bypass,
                'getUnconfirmed' => $bypass,
                'forceInclude' => ($bypass ? FALSE : $user->getID())
            );
        } else {
            // User parameter is null, ignore privacy and grab all the users.
            $conditions = array(
                'cutOff' => array('>', $this->getModels()->getModel('session')->getOnlineStatusTimeout())
            );
        }
        // Return the count of online visitors (users + guests).
        return $this->getModels()->getModel('session')->countSessionActivityRecords($conditions);
    }

    /**
    * Returns the Forum array of the $forum_id parameter.
    */
    public function getForum($forum_id) {
        $this->getModels()->checkModel('forum', XenForo_Model::create('XenForo_Model_Forum'));
        return $this->getModels()->getModel('forum')->getForumByID($forum_id);
    }

    /**
    * Returns the Node array of the $node_id parameter.
    */
    public function getNode($node_id) {
        $this->getModels()->checkModel('node', XenForo_Model::create('XenForo_Model_Node'));
        return $this->getModels()->getModel('node')->getNodeByID($node_id);
    }

    /**
    * Returns the Thread array of the $thread_id parameter.
    */
    public function getThread($thread_id, $fetch_options = array()) {
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        return $this->getModels()->getModel('thread')->getThreadById($thread_id, $fetch_options);
    }

    /**
    * Returns a list of threads.
    */
    public function getThreads($conditions = array(), $fetchOptions = array('limit' => 10), $user = NULL) {
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        if ($user == NULL) {
            $thread_list = $this->getModels()->getModel('thread')->getThreads($conditions, $fetchOptions);
            return $thread_list;
        }
        $thread_list = $this->getModels()->getModel('thread')->getThreads($conditions, array_merge($fetchOptions, array('permissionCombinationId' => $user->data['permission_combination_id'])));
        // Loop through the threads to check if the user has permissions to view the thread.
        foreach ($thread_list as $key => $thread) {
            $permissions = XenForo_Permission::unserializePermissions($thread['node_permission_cache']);
            if (!$this->getModels()->getModel('thread')->canViewThread($thread, array(), $null, $permissions, $user->getData())) {
                // User does not have permission to view this thread, unset it and continue the loop.
                unset($thread_list[$key]);
            }
            unset($thread_list[$key]['node_permission_cache']);
        }
        return $thread_list;
    }


    /**
    * Returns the Thread array of the $thread_id parameter.
    */
    public function canViewThread($user, $thread, $permissions = NULL) {
        // Check if the thread model has initialized.
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        if ($permissions == NULL) {
            // Let's grab the permissions.
            $thread = $this->getThread($thread['thread_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));

            // Unserialize the permissions.
            $permissions = XenForo_Permission::unserializePermissions($thread['node_permission_cache']);
        }
        return ($this->getModels()->getModel('thread')->canViewThread($thread, array(), $null, $permissions, $user->getData()));
    }
    
    /**
    * Returns the User class of the $input parameter.
    *
    * The $input parameter can be an user ID, username or e-mail.
    * Returns FALSE if $input is NULL.
    */
    public function getUser($input, $grab_permission = FALSE) {
        if ($input == FALSE || $input == NULL) {
            return FALSE;
        } else if (is_numeric($input)) {
            // $input is a number, grab the user by an ID.
            $user = new User($this->models, $this->models->getUserModel()->getUserById($input));
            if (!$user->isRegistered()) {
                // The user ID was not found, grabbing the user by the username instead.
                return new User($this->models, $this->models->getUserModel()->getUserByName($input));
            }
            return $user;
        } else if ($this->models->getUserModel()->couldBeEmail($input)) {
            // $input is an e-mail, return the user of the e-mail.
            return new User($this->models, $this->models->getUserModel()->getUserByEmail($input));
        } else {
            // $input is an username, return the user of the username.
            return new User($this->models, $this->models->getUserModel()->getUserByName($input, ($grab_permission) ? array('join' => XenForo_Model_User::FETCH_USER_PERMISSIONS) : array()));
        }
    }
}

/**
* This class contains all the required models of XenForo.
*/
class Models {
    private $models = array();

    /**
    * Returns TRUE if the model exists, FALSE if not.
    */
    public function hasModel($model_name) {
        return isset($this->models[$model_name]) && $this->models[$model_name] != NULL;
    }

    /**
    * Checks if the model exists, adds it to the array if not.
    */
    public function checkModel($model_name, $model) {
        if (!$this->hasModel($model_name)) {
            $this->setModel($model_name, $model);
        }
    }

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
* This class contains all the functions and all the relevant data of a XenForo resource.
*/
class Resource {
    private $data;
    
    /**
    * Default constructor.
    */
    public function __construct($data) {
        $this->data = $data;
    }

    /**
    * Returns an array with that conists of limited data.
    */
    public static function getLimitedData($resource) {
       return array('id'               => $resource->getID(),
                    'title'            => $resource->getTitle(),
                    'author_id'        => $resource->getAuthorUserID(),
                    'author_username'  => $resource->getAuthorUsername(),
                    'state'            => $resource->getState(),
                    'creation_date'    => $resource->getCreationDate(),
                    'category_id'      => $resource->getCategoryID(),
                    'version_id'       => $resource->getCurrentVersionID(),
                    'description_id'   => $resource->getDescriptionUpdateID(),
                    'thread_id'        => $resource->getDiscussionThreadID(),
                    'external_url'     => $resource->getExternalURL(),
                    'price'            => $resource->getPrice(),
                    'currency'         => $resource->getCurrency(),
                    'times_downloaded' => $resource->getTimesDownloaded(),
                    'times_rated'      => $resource->getTimesRated(),
                    'rating_sum'       => $resource->getRatingSum(),
                    'rating_avg'       => $resource->getAverageRating(),
                    'rating_weighted'  => $resource->getWeightedRating(),
                    'times_updated'    => $resource->getTimesUpdated(),
                    'times_reviewed'   => $resource->getTimesReviewed(),
                    'last_update'      => $resource->getLastUpdateDate());
    }

    /**
    * Returns an array which contains all the data of the resource.
    */
    public function getData() {
        return $this->data;
    }

    /**
    * Returns TRUE if the resource is valid, returns FALSE if not.
    */
    public function isValid() {
        return $this->data != NULL && is_array($this->data) && isset($this->data['resource_id']) && $this->data['resource_id'] != NULL;
    }

    /**
    * Returns the ID of the resource.
    */
    public function getID() {
        return $this->data['resource_id'];
    }

    /**
    * Returns the title of the resource.
    */
    public function getTitle() {
        return $this->data['title'];
    }

    /**
    * Returns the tag line of the resource.
    */
    public function getTagLine() {
        return $this->data['tag_line'];
    }

    /**
    * Returns the ID of the author.
    */
    public function getAuthorUserID() {
        return $this->data['user_id'];
    }

    /**
    * Returns the username of the author.
    */
    public function getAuthorUsername() {
        return $this->data['username'];
    }


    /**
    * Returns the state of the resource.
    * TODO
    */
    public function getState() {
        return $this->data['resource_state'];
    }

    /**
    * Returns the creation date of the resource.
    */
    public function getCreationDate() {
        return $this->data['resource_date'];
    }

    /**
    * Returns the category ID of the resource.
    */
    public function getCategoryID() {
        return $this->data['resource_category_id'];
    }

    /**
    * Returns the current version ID of the resource.
    */
    public function getCurrentVersionID() {
        return $this->data['current_version_id'];
    }

    /**
    * Returns the current description update ID of the resource.
    */
    public function getDescriptionUpdateID() {
        return $this->data['description_update_id'];
    }

    /**
    * Returns the discussion thread ID of the resource.
    */
    public function getDiscussionThreadID() {
        return $this->data['discussion_thread_id'];
    }

    /**
    * Returns the external URL of the resource.
    */
    public function getExternalURL() {
        return $this->data['external_url'];
    }

    /**
    * Returns TRUE if the resource is fileless, FALSE if not.
    */
    public function isFileless() {
        return $this->data['is_fileless'] == 1;
    }

    /**
    * Returns the external purchase URL of the resource if it has any.
    */
    public function getExternalPurchaseURL() {
        return $this->data['external_purchase_url'];
    }

    /**
    * Returns the price of the resource.
    */
    public function getPrice() {
        return $this->data['price'];
    }

    /**
    * Returns the currency of the price of the resource.
    */
    public function getCurrency() {
        return $this->data['currency'];
    }

    /**
    * Returns the amount of times the resource has been downloaded.
    */
    public function getTimesDownloaded() {
        return $this->data['download_count'];
    }

    /**
    * Returns the amount of times the resource has been rated.
    */
    public function getTimesRated() {
        return $this->data['rating_count'];
    }

    /**
    * Returns the sum of the ratings.
    */
    public function getRatingSum() {
        return $this->data['rating_sum'];
    }

    /**
    * Returns the average rating of the resource.
    */
    public function getAverageRating() {
        return $this->data['rating_avg'];
    }

    /**
    * Returns the weighted rating of the resource.
    */
    public function getWeightedRating() {
        return $this->data['rating_weighted'];
    }

    /**
    * Returns the amount of times the resource has been updated.
    */
    public function getTimesUpdated() {
        return $this->data['update_count'];
    }

    /**
    * Returns the amount of times the resource has been reviewed.
    */
    public function getTimesReviewed() {
        return $this->data['review_count'];
    }

    /**
    * Returns the last update date of the resource.
    */
    public function getLastUpdateDate() {
        return $this->data['last_update'];
    }

    /**
    * Returns the alternative support URL of the resource.
    */
    public function getAlternativeSupportURL() {
        return $this->data['alt_support_url'];
    }

    /**
    * Returns TRUE if the resource had first visible.
    */
    public function hadFirstVisible() {
        return $this->data['had_first_visible'] == 1;
    }
}   

/**
* This class contains all the functions and all the relevant data of a XenForo addon.
*/
class Addon {
    private $data;
    
    /**
    * Default constructor.
    */
    public function __construct($data) {
        $this->data = $data;
    }

    /**
    * Returns an array with that conists of limited data.
    */
    public static function getLimitedData($addon) {
       return array('id'      => $addon->getID(),
                    'title'   => $addon->getTitle(),
                    'version' => $addon->getVersionString(),
                    'enabled' => $addon->isEnabled(),
                    'url'     => $addon->getURL());
    }

    /**
    * Returns an array which contains all the data of the addon.
    */
    public function getData() {
        return $this->data;
    }

    /**
    * Returns TRUE if the addon is installed, returns FALSE if not.
    */
    public function isInstalled() {
        return $this->data != NULL && is_array($this->data) && isset($this->data['addon_id']) && $this->data['addon_id'] != NULL;
    }

    /**
    * Returns TRUE if the addon is enabled, returns FALSE if not.
    */
    public function isEnabled() {
        return $this->data['active'] == 1;
    }

    /**
    * Returns the ID of the addon.
    */
    public function getID() {
        return $this->data['addon_id'];
    }

    /**
    * Returns the title of the addon.
    */
    public function getTitle() {
        return $this->data['title'];
    }

    /**
    * Returns the version string of the addon.
    */
    public function getVersionString() {
        return $this->data['version_string'];
    }

    /**
    * Returns the version ID of the addon.
    */
    public function getVersionID() {
        return $this->data['version_id'];
    }

    /**
    * Returns the URL of the addon.
    */
    public function getURL() {
        return $this->data['url'];
    }

    /**
    * Returns the install callback class of the addon.
    */
    public function getInstallCallbackClass() {
        return $this->data['install_callback_class'];
    }

    /**
    * Returns the install callback method of the addon.
    */
    public function getInstallCallbackMethod() {
        return $this->data['install_callback_method'];
    }

    /**
    * Returns the uninstall callback class of the addon.
    */
    public function getUninstallCallbackClass() {
        return $this->data['uninstall_callback_class'];
    }

    /**
    * Returns the uninstall callback method of the addon.
    */
    public function getUninstallCallbackMethod() {
        return $this->data['uninstall_callback_class'];
    }
}

/**
* This class contains all the functions and all the relevant data of a XenForo user.
*/
class User {
    public $data;
    private $models, $registered = FALSE;
    
    /**
    * Default constructor.
    */
    public function __construct($models, $data) {
        $this->models = $models;
        $this->data = $data;
        if (!empty($data)) {
            $this->registered = TRUE;
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
    * Returns TRUE if the user is a global moderator.
    */
    public function isModerator() {
        return $this->data['is_moderator'] == 1;
    }
    
    /**
    * Returns TRUE if the user an administrator.
    */
    public function isAdmin() {
        return $this->data['is_admin'] == 1;
    }
    
    /**
    * Returns TRUE if the user is banned.
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

    /**
    * Returns the permission cache, if any.
    */
    public function getPermissionCache() {
        return $this->data['global_permission_cache'];
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
