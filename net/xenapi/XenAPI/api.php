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
require_once('xen_api.php');

// To change the API key, replace the API_KEY with your desired API key.
$restAPI = new RestAPI('API_KEY');

# DO NOT CHANGE ANYTHING BELOW THIS LINE UNLESS
# YOU REALLY KNOW WHAT ARE YOU DOING

// Process the request
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
    const VERSION = '1.4.dev';
    const GENERAL_ERROR = 0x201;
    const USER_ERROR = 0x202;
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
    *   - api_key:       An API key is required to perform this action.
    *
    * NOTE: Permissions are ignored when the API key is used as a hash, permissions are only
    *       used when the user is using the 'username:hash' format for the 'hash' argument.
    */
    private $actions = array(
        'authenticate'             => 'public',
        'createconversation'       => 'authenticated',
        'createconversationreply'  => 'authenticated',
        'createpost'               => 'authenticated',
        'createprofilepost'        => 'authenticated',
        'createprofilepostcomment' => 'authenticated',
        'createthread'             => 'authenticated',
        'deletepost'               => 'authenticated',
        'edituser'                 => 'api_key',
        'getactions'               => 'public', 
        'getaddon'                 => 'administrator',
        'getaddons'                => 'administrator',
        'getalerts'                => 'private', 
        'getavatar'                => 'public',
        'getconversation'          => 'private',
        'getconversations'         => 'private',
        'getgroup'                 => 'public', 
        'getnode'                  => 'public',
        'getnodes'                 => 'public',
        'getpost'                  => 'public',
        'getposts'                 => 'public',
        'getprofilepost'           => 'authenticated',
        'getprofileposts'          => 'authenticated',
        'getresource'              => 'administrator',
        'getresources'             => 'administrator',
        'getstats'                 => 'public',
        'getthread'                => 'public',
        'getthreads'               => 'public',
        'getuser'                  => 'authenticated', 
        'getusers'                 => 'public',
        'register'                 => 'api_key'
    );
    
    // Array of actions that are user specific and require an username, ID or email for the 'value' parameter.
    private $user_actions = array('getalerts', 'getavatar', 'getconversation', 'getconversations', 'createprofilepost', 'getuser');
    
    // List of general errors, this is where the 'throwError' function gets the messages from.
    private $general_errors = array(
        0  => 'Unknown error', 
        1  => 'Argument: "{ERROR}", is empty/missing a value',
        2  => '"{ERROR}", is not a supported action',
        3  => 'Missing argument: "{ERROR}"',
        4  => 'No {ERROR} found with the argument: "{ERROR2}"',
        5  => 'Authentication error: "{ERROR}"',
        6  => '"{ERROR}" is not a valid {ERROR2}',
        7  => 'Something went wrong when "{ERROR}": "{ERROR2}"',
        8  => 'The request had no values set, available fields are: "({ERROR})"',
        9  => 'You are not permitted to use the "{ERROR}" action on others (remove the value argument)',
        10 => 'You do not have permission to use the "{ERROR}" action',
        11 => '"{ERROR}" is a supported action but there is no code for it yet',
        12 => '"{ERROR}" is a unknown request method',
        13 => '"{ERROR}" is not an installed addon',
        14 => '"{ERROR}" is not an author of any resources',
        15 => 'Could not find a resource with ID "{ERROR}"',
        16 => 'Could not find a required model to perform this request: "{ERROR}"',
        17 => 'The API key has not been changed, make sure you use another API key before using this API',
        18 => '"{ERROR} is a unknown permission name, the request was terminated.',
        19 => 'Could not find a {ERROR} with ID "{ERROR2}"',
        20 => '{ERROR} not have permissions to view {ERROR2}',
        21 => 'The "{ERROR}" argument has to be a number',
        22 => 'The argument for "order_by", "{ERROR}", was not found in the list available order by list: "({ERROR2})"',
        23 => 'The argument for "node_type", "{ERROR}", was not found in the list available node type list: "({ERROR2})"'
    );

    // Specific errors related to user actions.
    private $user_errors = array(
        0  => 'Unknown user error',
        1  => 'Field was not recognised',
        2  => 'Group not found',
        3  => 'User data array was missing',
        4  => 'The specified user is not registered',
        5  => 'Invalid custom field array',
        6  => 'Editing super admins is disabled',
        7  => 'The add_groups parameter needs to be an array and have at least 1 item',
        8  => 'The user is already a member of the group(s)',
        9  => 'No values were changed',
        10 => 'Missing required a required parameter',
        11 => 'The remove_groups parameter needs to be an array and have at least 1 item',
        12 => 'The user is not a member of the group(s)',
        13 => 'An user is required to create a post/thread',
        14 => 'The user does not have permissions to post in this thread',
        30 => 'Missing required registration fields',
        31 => 'Password invalid',
        32 => 'Name length is too short',
        33 => 'Name length is too long',
        34 => 'Name contains disallowed words',
        35 => 'Name does not follow the required format',
        36 => 'Name contains censored words',
        37 => 'Name contains CTRL characters',
        38 => 'Name contains comma',
        39 => 'Name resembles an email',
        40 => 'User already exists',
        41 => 'Invalid email',
        42 => 'Email already used',
        43 => 'Email banned by administrator',
        44 => 'Invalid timezone',
        45 => 'Custom title contains censored words',
        46 => 'Custom title contains disallowed words',
        47 => 'Invalid date of birth',
        48 => 'Cannot delete your own account',
        49 => 'Field contained an invalid value'
    );

    private $xenAPI, $method, $data = array(), $hash = FALSE, $apikey = FALSE;

    /**
    * Default constructor for the RestAPI class.
    * The data gets set here depending on what kind of request method is being used.
    */
    public function __construct($api_key = NULL) {
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

        // Set the API key.
        $this->apikey = $api_key;

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
        // Set the limit.
        $this->setLimit(100);
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
    * TODO
    */
    public function setLimit($default) {
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
            // Limit is not set, default to $default variable.
            $this->limit = $default;
        }
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
                case 'api_key':
                    return $this->hasAPIKey();
                default:
                    $this->throwError(10, $this->getAction());
                    return FALSE;
            }
        }
        // Returns TRUE if permission of the action is public or the request has a valid API key.
        return $permission == 'public' || $this->hasAPIKey();
    }

    public function getCustomArray($input_data) {
        // Custom fields are set.
        $custom_array_data = array();

        // Check if there are more than one custom array.
        if (strpos($input_data, ',') !== FALSE) {
            // There are more than one custom array set.
            $custom_arrays = explode(',', $input_data);

            // Loop through the custom fields.
            foreach ($custom_arrays as $custom_array) {
                // Check if custom array string contains = symbol, ignore if not.
                if (strpos($custom_array, '=') !== FALSE) {
                    // Custom array string contains = symbol, explode it.
                    $custom_array_list = explode('=', $custom_array);

                    // Add the custom item data to the array.
                    $custom_array_data[$custom_array_list[0]] = $custom_array_list[1];
                }
            }
        } else if (strpos($input_data, '=') !== FALSE) {
            // Custom array string contains = symbol, explode it.
            $custom_array_list = explode('=', $input_data);

            // Add the custom item data to the array.
            $custom_array_data[$custom_array_list[0]] = $custom_array_list[1];
        }

        // Return the array(s).
        return $custom_array_data;
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
    * TODO
    */
    public function checkRequestParameter($parameter, $required = TRUE) {
        if ($required && !$this->hasRequest($parameter)) {
            // The '$parameter' argument has not been set, throw error.
            $this->throwError(3, $parameter);
        } else if ($this->hasRequest($parameter) && !$this->getRequest($parameter)) {
            // Throw error if the '$parameter' argument is set but empty.
            $this->throwError(1, $parameter);
        }
        return TRUE;
    }

    /**
    * TODO
    */
    public function checkRequestParameters(array $parameters, $required = TRUE) {
        foreach ($parameters as $parameter) {
            $this->checkRequestParameter($parameter, $required);
        }
        return TRUE;
    }

    /**
    * TODO
    */
    public function getUserErrorID($phrase_name) {
        switch ($phrase_name) {
            case 'please_enter_value_for_all_required_fields':
                return 30;
            case 'please_enter_valid_password':
                return 31;
            case 'please_enter_name_that_is_at_least_x_characters_long':
                return 32;
            case 'please_enter_name_that_is_at_most_x_characters_long':
                return 33;
            case 'please_enter_another_name_disallowed_words':
                return 34;
            case 'please_enter_another_name_required_format':
                return 35;
            case 'please_enter_name_that_does_not_contain_any_censored_words':
                return 36;
            case 'please_enter_name_without_using_control_characters':
                return 37;
            case 'please_enter_name_that_does_not_contain_comma':
                return 38;
            case 'please_enter_name_that_does_not_resemble_an_email_address':
                return 39;
            case 'usernames_must_be_unique':
                return 40;
            case 'please_enter_valid_email':
                return 41;
            case 'email_addresses_must_be_unique':
                return 42;
            case 'email_address_you_entered_has_been_banned_by_administrator':
                return 43;
            case 'please_select_valid_time_zone':
                return 44;
            case 'please_enter_custom_title_that_does_not_contain_any_censored_words':
                return 45;
            case 'please_enter_another_custom_title_disallowed_words':
                return 46;
            case 'please_enter_valid_date_of_birth':
                return 47;
            case 'you_cannot_delete_your_own_account':
                return 48;
            case 'please_enter_valid_value':
                return 49;
            default:
                return 0;
        }
    }

    /**
    * Gets the error message and replaces {ERROR} with the $extra parameter.
    */
    public function getError($error, $extra = NULL, $extra2 = NULL, $error_type = self::GENERAL_ERROR) {
        if ($error_type == NULL) {
            $error_type = self::GENERAL_ERROR;
        }
        if ($error_type == self::GENERAL_ERROR) {
            if (!array_key_exists($error, $this->general_errors)) {
                $error = 0;
            }
            $error_string = $this->general_errors[$error];
        } else if ($error_type == self::USER_ERROR) {
            if (!array_key_exists($error, $this->user_errors)) {
                $error = 0;
            }
            $error_string = $this->user_errors[$error];
        }
        if ($extra != NULL) {
            $error_string = str_replace('{ERROR}', $extra, $error_string);
        } 
        if ($extra2 != NULL) {
            $error_string = str_replace('{ERROR2}', $extra2, $error_string);
        }
        return array('id' => $error, 'message' => $error_string);
    }
    
    /**
    * Throw the error message.
    */
    public function throwError($error, $extra = NULL, $extra2 = NULL) {
        if ($error == self::USER_ERROR) {
            if ($extra2 == NULL) {
                $extra2 = 'performing a user action';
            }
            $user_error = $this->getError($extra['error_id'], NULL, NULL, self::USER_ERROR);
            $general_error = $this->getError(7, $extra2, $user_error['message']);
            $error_response = array(
                'error' => $general_error['id'], 
                'message' => $general_error['message'], 
                'user_error_id' => $user_error['id'],
                'user_error_field' => $extra['error_field'],
                'user_error_key' => $extra['error_key'],
                'user_error_phrase' => $extra['error_phrase']
            );
        } else {
            if (is_array($extra)) {
                $extra = implode(', ', $extra);
            }
            if (is_array($extra2)) {
                $extra2 = implode(', ', $extra2);
            }
            $error = $this->getError($error, $extra, $extra2, $error_type);
            $error_response = array('error' => $error['id'], 'message' => $error['message']);
        }
        // Throw a 400 error.
        header('HTTP/ 400 API error');

        // Send error.
        $this->sendResponse($error_response);
    }

    private function handleUserError($user_results, $error_key, $error_message) {
        if (!empty($user_results['error'])) {
            // Contains errors, process errors.
            if (is_array($user_results['errors'])) {
                // The error message was an array, loop through the messages.
                $error_keys = array();
                foreach ($user_results['errors'] as $error_field => $error) {
                    if (!($error instanceof XenForo_Phrase)) {
                        $post_error = array(
                            'error_id' => 1,
                            'error_key' => 'field_not_recognised', 
                            'error_field' => $error_field, 
                            'error_phrase' => $error
                        );
                        $this->throwError(self::USER_ERROR, $post_error, $error_message);
                    }

                    // Let's init the error array.
                    $post_error = array(
                        'error_id' => $this->getUserErrorID($error->getPhraseName()),
                        'error_key' => $error->getPhraseName(), 
                        'error_field' => $error_field, 
                        'error_phrase' => $error->render()
                    );

                    $this->throwError(self::USER_ERROR, $post_error, $error_message);
                }
            } else {
                $post_error = array(
                    'error_id' => $user_results['error'],
                    'error_key' => 'general_user_' . $error_key, 
                    'error_phrase' => $user_results['errors']
                );
                $this->throwError(self::USER_ERROR, $post_error, $error_message);
                // Throw error message.
            }
        } else {
            // Reesult was successful, return results.
            $this->sendResponse($user_results);
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
            case 'createconversation': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if ($this->hasAPIKey() && !$this->hasRequest('grab_as')) {
                    // The 'grab_as' argument has not been set, throw error.
                    $this->throwError(3, 'grab_as');
                } else if ($this->hasAPIKey() && !$this->getRequest('grab_as')) {
                    // Throw error if the 'grab_as' argument is set but empty.
                    $this->throwError(1, 'grab_as');
                } 

                $conversation_data = array();

                // Array of required parameters.
                $required_parameters = array('recipients', 'title', 'message');

                // Array of additional parameters.
                $additional_parameters = array('open_invite', 'conversation_locked');

                foreach ($required_parameters as $required_parameter) {
                    // Check if the required parameter is set and not empty.
                    $this->checkRequestParameter($required_parameter);

                    // Set the request value.
                    $conversation_data[$required_parameter] = $this->getRequest($required_parameter);
                }

                if (strpos($this->getRequest('recipients'), ',') !== FALSE) {
                    $recipient_array = explode(',', $this->getRequest('recipients'));
                    foreach ($recipient_array as $recipient) {
                        $user = $this->getXenAPI()->getUser($recipient);
                        if (!$user->isRegistered()) {
                            // Requested user was not registered, throw error.
                            $this->throwError(4, 'user', $recipient);
                        }
                    }
                } else {
                    $user = $this->getXenAPI()->getUser($this->getRequest('recipients'));
                    if (!$user->isRegistered()) {
                        // Requested user was not registered, throw error.
                        $this->throwError(4, 'user', $this->getRequest('recipients'));
                    }
                }

                foreach ($additional_parameters as $additional_parameter) {
                    if ($this->hasRequest($additional_parameter)) {
                        // Set the request value.
                        $conversation_data[$additional_parameter] = TRUE;
                    }
                }

                // Create the conversation object.
                $conversation_results = $this->xenAPI->createConversation($this->getUser(), $conversation_data);

                $this->handleUserError($conversation_results, 'conversation_creation_error', 'creating a new conversation');
        case 'createconversationreply': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if ($this->hasAPIKey() && !$this->hasRequest('grab_as')) {
                    // The 'grab_as' argument has not been set, throw error.
                    $this->throwError(3, 'grab_as');
                } else if ($this->hasAPIKey() && !$this->getRequest('grab_as')) {
                    // Throw error if the 'grab_as' argument is set but empty.
                    $this->throwError(1, 'grab_as');
                } 

                $conversation_reply_data = array();

                // Array of required parameters.
                $required_parameters = array('conversation_id', 'message');

                foreach ($required_parameters as $required_parameter) {
                    // Check if the required parameter is set and not empty.
                    $this->checkRequestParameter($required_parameter);

                    // Set the request value.
                    $conversation_reply_data[$required_parameter] = $this->getRequest($required_parameter);
                }

                // Try to grab the thread from XenForo.
                $conversation = $this->getXenAPI()->getConversation($this->getRequest('conversation_id'), $this->getUser());
                if ($conversation == NULL) {
                     // Could not find the conversation, throw error.
                    $this->throwError(19, 'conversation', $this->getRequest('conversation_id'));
                }

                // Create the conversation reply object.
                $conversation_reply_results = $this->xenAPI->createConversationReply($this->getUser(), $conversation_reply_data);

                $this->handleUserError($conversation_reply_results, 'conversation_reply_creation_error', 'creating a new conversation reply');
            case 'createpost': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if ($this->hasAPIKey() && !$this->hasRequest('grab_as')) {
                    // The 'grab_as' argument has not been set, throw error.
                    $this->throwError(3, 'grab_as');
                    break;
                } else if ($this->hasAPIKey() && !$this->getRequest('grab_as')) {
                    // Throw error if the 'grab_as' argument is set but empty.
                    $this->throwError(1, 'grab_as');
                    break;
                } 

                if (!$this->hasRequest('thread_id')) {
                    // The 'thread_id' argument has not been set, throw error.
                    $this->throwError(3, 'thread_id');
                    break;
                } else if (!$this->getRequest('thread_id')) {
                    // Throw error if the 'thread_id' argument is set but empty.
                    $this->throwError(1, 'thread_id');
                    break;
                }

                // Try to grab the thread from XenForo.
                $thread = $this->getXenAPI()->getThread($this->getRequest('thread_id'), array(), $this->getUser());
                if ($thread == NULL) {
                     // Could not find the thread, throw error.
                    $this->throwError(19, 'thread', $this->getRequest('thread_id'));
                }

                if (!$this->hasRequest('message')) {
                    // The 'message' argument has not been set, throw error.
                    $this->throwError(3, 'message');
                    break;
                } else if (!$this->getRequest('message')) {
                    // Throw error if the 'message' argument is set but empty.
                    $this->throwError(1, 'message');
                    break;
                }

                $post_data = array(
                    'thread_id' => $thread['thread_id'],
                    'message'   => $this->getRequest('message')
                );

                // Create the post object.
                $post_results = $this->xenAPI->createPost($this->getUser(), $post_data);

                $this->handleUserError($post_results, 'post_creation_error', 'creating a new post');
        case 'createprofilepost': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                // Array of required parameters.
                $required_parameters = array('message');

                foreach ($required_parameters as $required_parameter) {
                    // Check if the required parameter is set and not empty.
                    $this->checkRequestParameter($required_parameter);
                }

                if ($this->hasRequest('user')) {
                    if (!$this->getRequest('user')) {
                        // Throw error if the 'user' argument is set but empty.
                        $this->throwError(1, 'user');
                        break;
                    }
                    $profile_user = $this->getXenAPI()->getUser($this->getRequest('user'));
                    if (!$user->isRegistered()) {
                        // Requested user was not registered, throw error.
                        $this->throwError(4, 'user', $this->getRequest('user'));
                    }
                } else {
                    $profile_user = $user;
                }

                $profile_post_data = array(
                    'user_id' => $profile_user->data['user_id'],
                    'message'   => $this->getRequest('message')
                );

                // Create the post object.
                $profile_post_results = $this->xenAPI->createProfilePost($user, $profile_post_data);

                $this->handleUserError($profile_post_results, 'profile_post_creation_error', 'creating a new profile post');
            case 'createprofilepostcomment': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if ($this->hasAPIKey() && !$this->hasRequest('grab_as')) {
                    // The 'grab_as' argument has not been set, throw error.
                    $this->throwError(3, 'grab_as');
                } else if ($this->hasAPIKey() && !$this->getRequest('grab_as')) {
                    // Throw error if the 'grab_as' argument is set but empty.
                    $this->throwError(1, 'grab_as');
                } 

                // Array of required parameters.
                $required_parameters = array('profile_post_id', 'message');

                foreach ($required_parameters as $required_parameter) {
                    // Check if the required parameter is set and not empty.
                    $this->checkRequestParameter($required_parameter);
                }

                // Try to grab the node from XenForo.
                $profile_post = $this->getXenAPI()->getProfilePost($this->getRequest('profile_post_id'), array(), $this->getUser());
                if ($profile_post == NULL) {
                     // Could not find the node, throw error.
                    $this->throwError(19, 'profile post', $this->getRequest('profile_post_id'));
                }

                $profile_post_comment_data = array(
                    'profile_post_id' => $profile_post['profile_post_id'],
                    'profile_user_id' => $profile_post['profile_user_id'],
                    'message'         => $this->getRequest('message')
                );

                // Create the post object.
                $profile_post_comment_results = $this->xenAPI->createProfilePostComment($this->getUser(), $profile_post_comment_data);

                $this->handleUserError($profile_post_comment_results, 'profile_post_comment_creation_error', 'creating a new profile post comment');
            case 'createthread': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if ($this->hasAPIKey() && !$this->hasRequest('grab_as')) {
                    // The 'grab_as' argument has not been set, throw error.
                    $this->throwError(3, 'grab_as');
                    break;
                } else if ($this->hasAPIKey() && !$this->getRequest('grab_as')) {
                    // Throw error if the 'grab_as' argument is set but empty.
                    $this->throwError(1, 'grab_as');
                    break;
                } 

                if (!$this->hasRequest('node_id')) {
                    // The 'node_id' argument has not been set, throw error.
                    $this->throwError(3, 'node_id');
                    break;
                } else if (!$this->getRequest('node_id')) {
                    // Throw error if the 'node_id' argument is set but empty.
                    $this->throwError(1, 'node_id');
                    break;
                }

                // Try to grab the node from XenForo.
                $node = $this->getXenAPI()->getNode($this->getRequest('node_id'), array(), $this->getUser());
                if ($node == NULL) {
                     // Could not find the node, throw error.
                    $this->throwError(19, 'node', $this->getRequest('node_id'));
                }

                if (!$this->hasRequest('title')) {
                    // The 'title' argument has not been set, throw error.
                    $this->throwError(3, 'title');
                    break;
                } else if (!$this->getRequest('title')) {
                    // Throw error if the 'title' argument is set but empty.
                    $this->throwError(1, 'title');
                    break;
                }

                if (!$this->hasRequest('message')) {
                    // The 'message' argument has not been set, throw error.
                    $this->throwError(3, 'message');
                    break;
                } else if (!$this->getRequest('message')) {
                    // Throw error if the 'message' argument is set but empty.
                    $this->throwError(1, 'message');
                    break;
                }

                $thread_data = array();

                // Array of additional parameters.
                $additional_parameters = array('prefix_id', 'discussion_open', 'sticky');

                foreach ($additional_parameters as $additional_parameter) {
                    // Check if the additional parameter is set and not empty.
                    $this->checkRequestParameter($additional_parameter, FALSE);

                    if ($this->getRequest($additional_parameter)) {
                        // Set the request value.
                        $thread_data[$additional_parameter] = $this->getRequest($additional_parameter);
                    }
                }

                $thread_data += array(
                    'node_id' => $node['node_id'],
                    'title'     => $this->getRequest('title'),
                    'message'   => $this->getRequest('message')
                );

                // Create the thread object.
                $thread_results = $this->xenAPI->createThread($this->getUser(), $thread_data);

                $this->handleUserError($thread_results, 'thread_creation_error', 'creating a new thread');
            case 'deletepost': 
                /**
                * TODO
                *
                * EXAMPLE:
                *   - api.php
                */
                if (!$this->hasRequest('post_id')) {
                    // The 'post_id' argument has not been set, throw error.
                    $this->throwError(3, 'post_id');
                    break;
                } else if (!$this->getRequest('post_id')) {
                    // Throw error if the 'post_id' argument is set but empty.
                    $this->throwError(1, 'post_id');
                    break;
                }

                if ($this->hasRequest('reason')) {
                    if (!$this->getRequest('reason')) {
                        // Throw error if the 'reason' argument is set but empty.
                        $this->throwError(1, 'reason');
                        break;
                    }
                    $reason = $this->getRequest('reason');
                } else {
                    $reason = NULL;
                }

                // Try to grab the post from XenForo.
                $post = $this->getXenAPI()->getPost($this->getRequest('post_id'), array(), $this->getUser());
                if ($post == NULL) {
                     // Could not find the post, throw error.
                    $this->throwError(19, 'post', $this->getRequest('post_id'));
                }

                $delete_results = $this->xenAPI->deletePost($this->getRequest('post_id'), $reason, $this->hasRequest('hard_delete'), $this->getUser());

                $this->handleUserError($delete_results, 'post_deletion_error', 'deleting post');
            case 'edituser':
                /**
                * Edits the user.
                */
                if (!$this->hasRequest('user')) {
                    // The 'user' argument has not been set, throw error.
                    $this->throwError(3, 'user');
                    break;
                } else if (!$this->getRequest('user')) {
                    // Throw error if the 'user' argument is set but empty.
                    $this->throwError(1, 'user');
                    break;
                }
                if ($this->hasRequest('custom_field_identifier')) {
                    if (!$this->getRequest('custom_field_identifier')) {
                        // Throw error if the 'custom_field_identifier' argument is set but empty.
                        $this->throwError(1, 'custom_field_identifier');
                        break;
                    }
                    $user = $this->getXenAPI()->getUser($this->getRequest('user'), array('custom_field' => $this->getRequest('custom_field_identifier')));
                } else {
                    // Get the user object.
                    $user = $this->getXenAPI()->getUser($this->getRequest('user'));
                }
                if (!$user->isRegistered()) {
                    // Requested user was not registered, throw error.
                    $this->throwError(4, 'user', $this->getRequest('user'));
                }

                // Init the edit array.
                $edit_data = array();

                if ($this->hasRequest('group')) {
                    // Request has value.
                    if (!$this->getRequest('group')) {
                        // Throw error if the 'group' argument is set but empty.
                        $this->throwError(1, 'group');
                        break;
                    }
                    $group = $this->getXenAPI()->getGroup($this->getRequest('group'));
                    if (!$group) {
                        $edit_error = array(
                            'error_id' => 2,
                            'error_key' => 'group_not_found', 
                            'error_field' => 'group', 
                            'error_phrase' => 'Could not find group with parameter "' . $this->getRequest('group') . '"'
                        );
                        $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                    }
                    // Set the group id of the edit.
                    $edit_data['group_id'] = $group['user_group_id'];
                }

                $group_fields = array('add_groups', 'remove_groups');
                foreach ($group_fields as $group_field) {
                    if (!$this->hasRequest($group_field)) {
                        continue;
                    }
                    // Request has value.
                    if (!$this->getRequest($group_field)) {
                        // Throw error if the $group_field argument is set but empty.
                        $this->throwError(1, $group_field);
                    }
                    // Initialize the array.
                    $edit_data[$group_field] = array();

                    // Check if value is an array.
                    if (strpos($this->getRequest($group_field), ',') !== FALSE) {
                        // Value is an array, explode it.
                        $groups = explode(',', $this->getRequest($group_field));

                        // Loop through the group values.
                        foreach ($groups as $group_value) {
                            // Grab the group from the group value.
                            $group = $this->getXenAPI()->getGroup($group_value);

                            // Check if group was found.
                            if (!$group) {
                                // Group was not found, throw error.
                                $edit_error = array(
                                    'error_id' => 2,
                                    'error_key' => 'group_not_found', 
                                    'error_field' => $group_field, 
                                    'error_phrase' => 'Could not find group with parameter "' . $group_value . '" in array "' . $this->getRequest('add_group') . '"'
                                );
                                $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                            }
                            // Add the group_id to the the add_group array.
                            $edit_data[$group_field][] = $group['user_group_id'];
                        }
                    } else {
                        // Grab the group from the group value.
                        $group = $this->getXenAPI()->getGroup($this->getRequest($group_field));

                        // Check if group was found.
                        if (!$group) {
                            // Group was not found, throw error.
                            $edit_error = array(
                                'error_id' => 2,
                                'error_key' => 'group_not_found', 
                                'error_field' => $group_field, 
                                'error_phrase' => 'Could not find group with parameter "' . $this->getRequest($group_field) . '"'
                            );
                            $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                        }
                        // Add the group_id to the the add_groups array.
                        $edit_data[$group_field][] = $group['user_group_id'];
                    }
                }


                if ($this->hasRequest('custom_fields')) {
                    // Request has value.
                    if (!$this->getRequest('custom_fields')) {
                        // Throw error if the 'custom_fields' argument is set but empty.
                        $this->throwError(1, 'custom_fields');
                        break;
                    }
                    $custom_fields = $this->getCustomArray($this->getRequest('custom_fields'));

                    // Check if we found any valid custom fields, throw error if not.
                    if (count($custom_fields) == 0) {
                        // The custom fields array was empty, throw error.
                        $edit_error = array(
                            'error_id' => 5,
                            'error_key' => 'invalid_custom_fields', 
                            'error_field' => 'custom_fields', 
                            'error_phrase' => 'The custom fields values were invalid, valid values are: '
                                            . 'custom_fields=custom_field1=custom_value1,custom_field2=custom_value2 '
                                            . 'but got: "' . $this->getRequest('custom_fields') . '" instead'
                        );
                        $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                    }
                    $edit_data['custom_fields'] = $custom_fields;
                }

                // List of fields that are accepted to be edited.
                $edit_fields = array('username', 'password', 'email', 'gender', 'custom_title', 'style_id', 'timezone', 'visible', 'dob_day', 'dob_month', 'dob_year', 'user_state');

                // List of fields that the request should ignore.
                $ignore_fields = array('hash', 'action', 'user');

                // Let's check which fields are set.
                foreach ($this->data as $data_key => $data_item) {
                    if (!in_array($data_key, $ignore_fields) && in_array($data_key, $edit_fields) && $this->checkRequestParameter($data_key, FALSE)) {
                        $edit_data[$data_key] = $data_item;
                    }
                }

                if (count($edit_data) == 0) {
                    // There are no fields set, throw error.
                    $this->throwError(8, $edit_fields);
                }
               
                // Get edit results.
                $edit_results = $this->getXenAPI()->editUser($user, $edit_data);

                if (!empty($edit_results['error'])) {
                    // The registration failed, process errors.
                    if (is_array($edit_results['errors'])) {
                        // The error message was an array, loop through the messages.
                        $error_keys = array();
                        foreach ($edit_results['errors'] as $error_field => $error) {
                            if (!($error instanceof XenForo_Phrase)) {
                                $edit_error = array(
                                    'error_id' => 1,
                                    'error_key' => 'field_not_recognised', 
                                    'error_field' => $error_field, 
                                    'error_phrase' => $error
                                );
                                $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');

                            }

                            // Let's init the edit error array.
                            $edit_error = array(
                                'error_id' => $this->getUserErrorID($error->getPhraseName()),
                                'error_key' => $error->getPhraseName(), 
                                'error_field' => $error_field, 
                                'error_phrase' => $error->render()
                            );

                            $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                        }
                    } else {
                        $edit_error = array(
                            'error_id' => $edit_results['error'],
                            'error_key' => 'general_user_edit_error', 
                            'error_phrase' => $edit_results['errors']
                        );
                        $this->throwError(self::USER_ERROR, $edit_error, 'editing an user');
                        // Throw error message.
                    }
                } else {
                    // Edit was successful, return results.
                    $this->sendResponse($edit_results);
                }
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
            case 'getaddon': 
                /**
                * Returns the addon information depending on the 'value' argument.
                *
                * NOTE: Only addon ID's can be used for the 'value' parameter.
                *       Addon ID's can be found by using the 'getAddons' action.
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
            case 'getconversation':
                if (!$this->hasRequest('conversation_id')) {
                    // The 'conversation_id' argument has not been set, throw error.
                    $this->throwError(3, 'conversation_id');
                    break;
                } else if (!$this->getRequest('conversation_id')) {
                    // Throw error if the 'conversation_id' argument is set but empty.
                    $this->throwError(1, 'conversation_id');
                    break;
                }

                // Try to grab the thread from XenForo.
                $conversation = $this->getXenAPI()->getConversation($this->getRequest('conversation_id'), $user, array('join' => XenForo_Model_Conversation::FETCH_FIRST_MESSAGE));
                if ($conversation == NULL) {
                     // Could not find the conversation, throw error.
                    $this->throwError(19, 'conversation', $this->getRequest('conversation_id'));
                }

                // Send the response.
                $this->sendResponse($conversation);
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
                
                // Get the group from XenForo.
                $group = $this->getXenAPI()->getGroup($string);

                if (!$group) {
                    // Could not find any groups, throw error.
                    $this->throwError(4, 'group', $string);
                } else {
                    // Group was found, send response.
                    $this->sendResponse($group);
                }
                break;
            case 'getconversations':
                /**
                * Grabs the conversations from the specified user.
                * 
                * NOTE: The 'value' argument will only work for the user itself and
                *       not on others users unless the permission argument for the 
                *       'getconversations' action is changed (default permission: private).
                *
                * EXAMPLES: 
                *   - api.php?action=getConversations&hash=USERNAME:HASH
                *   - api.php?action=getConversations&value=USERNAME&hash=USERNAME:HASH
                *   - api.php?action=getConversations&value=USERNAME&hash=API_KEY
                */
                // Init variables.
                $conditions = array();
                $this->setLimit(10);
                $fetch_options = array('limit' => $this->limit, 'join' => XenForo_Model_Conversation::FETCH_FIRST_MESSAGE);

                // Grab the conversations.
                $conversations = $this->getXenAPI()->getConversations($user, $conditions, $fetch_options);

                // Send the response.
                $this->sendResponse(array('count' => count($conversations), 'conversations' => $conversations));
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
                
                // Get the group from XenForo.
                $group = $this->getXenAPI()->getGroup($string);

                if (!$group) {
                    // Could not find any groups, throw error.
                    $this->throwError(4, 'group', $string);
                } else {
                    // Group was found, send response.
                    $this->sendResponse($group);
                }
                break;
            case 'getnode':
                /**
                * Returns the node information depending on the 'value' argument.
                *
                * NOTE: Only node ID's can be used for the 'value' parameter.
                *       Node ID's can be found by using the 'getNodes' action.
                *
                *       The user needs permission to see the thread if the request is
                *       using a user hash and not an API key.
                *
                * EXAMPLE:
                *   - api.php?action=getNode&value=4&hash=USERNAME:HASH
                *   - api.php?action=getNode&value=4&hash=API_KEY
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
                // Try to grab the node from XenForo.
                $node = $this->getXenAPI()->getNode($string);
                if ($node == NULL) {
                     // Could not find the node, throw error.
                    $this->throwError(19, 'node', $string);
                } else if (!$this->hasAPIKey() && !$this->getXenAPI()->canViewNode($this->getUser(), $node)) {
                    if (isset($this->grab_as)) {
                        // Thread was found but the 'grab_as' user is not permitted to view the node.
                        $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this node');
                    } else { 
                        // Thread was found but the user is not permitted to view the node.
                        $this->throwError(20, 'You do', 'this node');
                    }
                } else if ($this->hasAPIKey() && isset($this->grab_as) && !$this->getXenAPI()->canViewNode($this->getUser(), $node)) {
                    // Thread was found but the 'grab_as' user is not permitted to view the node.
                    $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this node');
                } else {
                     // Thread was found, and the request was permitted.
                    $this->sendResponse($node);
                }
                break;
            case 'getnodes':
                /**
                * Returns a list of nodes.
                *
                * EXAMPLES: 
                *   - api.php?action=getNodes&hash=USERNAME:HASH
                *   - api.php?action=getNodes&hash=API_KEY
                */
                // Init variables.
                $this->setLimit(10);
                $fetch_options = array('limit' => $this->limit);

                // Check if request has node_type.
                if ($this->hasRequest('node_type')) {
                    if (!$this->getRequest('node_type')) {
                        // Throw error if the 'node_type' argument is set but empty.
                        $this->throwError(1, 'node_type');
                    }

                    // Set the node_type.
                    $node_type = strtolower($this->getRequest('node_type'));

                    // Check if the node type that is set exists.
                    if (!in_array($node_type, $this->getXenAPI()->getNodeTypes()) && $node_type != 'all') {
                        // Node type could not be found in the node type list, throw error.
                        $this->throwError(23, $this->getRequest('node_type'), implode(', ', $this->getXenAPI()->getNodeTypes()));
                    }
                } else {
                    $node_type = 'all';
                }

                // Get the nodes.
                $nodes = $this->getXenAPI()->getNodes($node_type, $fetch_options, $this->getUser());

                // Send the response.
                $this->sendResponse(array('count' => count($nodes), 'nodes' => $nodes));
            case 'getpost':
                /**
                * Returns the post information depending on the 'value' argument.
                *
                * NOTE: Only post ID's can be used for the 'value' parameter.
                *       Post ID's can be found by using the 'getPosts' action.
                *
                *       The user needs permission to see the thread if the request is
                *       using a user hash and not an API key.
                *
                * EXAMPLE:
                *   - api.php?action=getPost&value=820&hash=USERNAME:HASH
                *   - api.php?action=getPost&value=820&hash=API_KEY
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
                // Try to grab the post from XenForo.
                $post = $this->getXenAPI()->getPost($string, array('join' => XenForo_Model_Post::FETCH_FORUM));
                if ($post == NULL) {
                     // Could not find the post, throw error.
                    $this->throwError(19, 'post', $string);
                } else if (!$this->hasAPIKey() && !$this->getXenAPI()->canViewPost($this->getUser(), $post)) {
                    if (isset($this->grab_as)) {
                        // Post was found but the 'grab_as' user is not permitted to view the post.
                        $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this post');
                    } else { 
                        // Post was found but the user is not permitted to view the post.
                        $this->throwError(20, 'You do', 'this post');
                    }
                } else if ($this->hasAPIKey() && isset($this->grab_as) && !$this->getXenAPI()->canViewPost($this->getUser(), $post)) {
                    // Post was found but the 'grab_as' user is not permitted to view the post.
                    $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this post');
                } else {
                     // Post was found, and the request was permitted.
                    $this->sendResponse($post);
                }
                break;
            case 'getposts':
                /**
                * Returns a list of posts.
                *
                * NOTE: Only usernames and user ID's can be used for the 'author' parameter.
                *
                * EXAMPLES: 
                *   - api.php?action=getPosts&hash=USERNAME:HASH
                *   - api.php?action=getPosts&hash=API_KEY
                *   - api.php?action=getPosts&author=Contex&hash=USERNAME:HASH
                *   - api.php?action=getPosts&author=1&hash=API_KEY
                */
                // Init variables.
                $conditions = array();
                $this->setLimit(10);
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
                    unset($user);
                }

                // Check if request has node id.
                if ($this->hasRequest('node_id')) {
                    if (!$this->getRequest('node_id') && (is_numeric($this->getRequest('node_id')) && $this->getRequest('node_id') != 0)) {
                        // Throw error if the 'node_id' argument is set but empty.
                        $this->throwError(1, 'node_id');
                    } else if (!is_numeric($this->getRequest('node_id'))) {
                        // Throw error if the 'node_id' argument is set but not a number.
                        $this->throwError(21, 'node_id');
                    }
                    if (!$this->xenAPI->getNode($this->getRequest('node_id'))) {
                        // Could not find any nodes, throw error.
                        $this->throwError(4, 'node', $this->getRequest('node_id'));
                    }
                    // Add the node ID to the query conditions.
                    $conditions['node_id'] = $this->getRequest('node_id');
                }

                // Check if request has thread id.
                if ($this->hasRequest('thread_id')) {
                    if (!$this->getRequest('thread_id') && (is_numeric($this->getRequest('thread_id')) && $this->getRequest('thread_id') != 0)) {
                        // Throw error if the 'thread_id' argument is set but empty.
                        $this->throwError(1, 'thread_id');
                    } else if (!is_numeric($this->getRequest('thread_id'))) {
                        // Throw error if the 'thread_id' argument is set but not a number.
                        $this->throwError(21, 'thread_id');
                    }
                    if (!$this->xenAPI->getThread($this->getRequest('thread_id'))) {
                        // Could not find any threads, throw error.
                        $this->throwError(4, 'thread_id', $this->getRequest('thread_id'));
                    }
                    // Add the node ID to the query conditions.
                    $conditions['thread_id'] = $this->getRequest('thread_id');
                }

                // Check if the order by argument is set.
                $order_by_field = $this->checkOrderBy(array('post_id', 'thread_id', 'user_id', 'username', 'post_date', 'attach_count', 'likes', 'node_id'));

                // Add the order by options to the fetch options.
                if ($this->hasRequest('order_by')) {
                    $fetch_options['order']          = $order_by_field;
                    $fetch_options['orderDirection'] = $this->order;
                }

                // Get the posts.
                $posts = $this->getXenAPI()->getPosts($conditions, $fetch_options, $this->getUser());

                // Send the response.
                $this->sendResponse(array('count' => count($posts), 'posts' => $posts));
            case 'getprofilepost':
                /**
                * Returns the profile post information depending on the 'value' argument.
                *
                * NOTE: Only profile post ID's can be used for the 'value' parameter.
                *       Profile post ID's can be found by using the 'getProfilePosts' action.
                *
                *       The user needs permission to see the profile post if the request is
                *       using a user hash and not an API key.
                *
                * EXAMPLE:
                *   - api.php?action=getProfilePost&value=820&hash=USERNAME:HASH
                *   - api.php?action=getProfilePost&value=820&hash=API_KEY
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
                // Try to grab the profile post from XenForo.
                $profile_post = $this->getXenAPI()->getProfilePost($string);
                if ($profile_post == NULL) {
                     // Could not find the profile post, throw error.
                    $this->throwError(19, 'profile post', $string);
                } else if (!$this->hasAPIKey() && !$this->getXenAPI()->canViewProfilePost($this->getUser(), $profile_post)) {
                    if (isset($this->grab_as)) {
                        // Thread was found but the 'grab_as' user is not permitted to view the thread.
                        $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this profile post');
                    } else { 
                        // Thread was found but the user is not permitted to view the profile post.
                        $this->throwError(20, 'You do', 'this profile post');
                    }
                } else if ($this->hasAPIKey() && isset($this->grab_as) && !$this->getXenAPI()->canViewProfilePost($this->getUser(), $profile_post)) {
                    // Thread was found but the 'grab_as' user is not permitted to view the profile post.
                    $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this profile post');
                } else {
                     // Post was found, and the request was permitted.
                    $this->sendResponse($profile_post);
                }
                break;
            case 'getprofileposts':
                /**
                * Returns a list of profile posts.
                *
                * NOTE: Only usernames and user ID's can be used for the 'author' parameter.
                *
                * EXAMPLES: 
                *   - api.php?action=getProfilePosts&hash=USERNAME:HASH
                *   - api.php?action=getProfilePosts&hash=API_KEY
                *   - api.php?action=getProfilePosts&author=Contex&hash=USERNAME:HASH
                *   - api.php?action=getProfilePosts&author=1&hash=API_KEY
                */
                // Init variables.
                $conditions = array();
                $this->setLimit(10);
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
                    $conditions['author_id'] = $user->getID();
                    unset($user);
                }

                // Check if request has profile user.
                if ($this->hasRequest('profile')) {
                    if (!$this->getRequest('profile')) {
                        // Throw error if the 'profile' argument is set but empty.
                        $this->throwError(1, 'profile');
                        break;
                    }
                    // Grab the user object of the profile.
                    $user = $this->xenAPI->getUser($this->getRequest('profile'));
                    if (!$user->isRegistered()) {
                        // Throw error if the 'author' user is not registered.
                        $this->throwError(4, 'user', $this->getRequest('profile'));
                        break;
                    }
                    // Add the user ID to the query conditions.
                    $conditions['profile_id'] = $user->getID();
                    unset($user);
                }

                // Check if the order by argument is set.
                $order_by_field = $this->checkOrderBy(array('profile_post_id', 'profile_user_id', 'user_id', 'username', 'post_date', 
                                                            'attach_count', 'likes', 'comment_count', 'first_comment_date', 
                                                            'last_comment_date'));

                // Add the order by options to the fetch options.
                if ($this->hasRequest('order_by')) {
                    $fetch_options['order']          = $order_by_field;
                    $fetch_options['orderDirection'] = $this->order;
                }

                // Get the profile posts.
                $profile_posts = $this->getXenAPI()->getProfilePosts($conditions, $fetch_options, $this->getUser());

                // Send the response.
                $this->sendResponse(array('count' => count($profile_posts), 'profile_posts' => $profile_posts));
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
            case 'getstats':
                /**
                * Returns a summary of stats.
                *
                * EXAMPLE:
                *   - api.php?action=getStats
                */
                $latest_user = $this->xenAPI->getLatestUser();
                $this->sendResponse(array(
                    'threads'                => $this->xenAPI->getStatsItem('threads'),
                    'posts'                  => $this->xenAPI->getStatsItem('posts'),
                    'conversations'          => $this->xenAPI->getStatsItem('conversations'),
                    'conversations_messages' => $this->xenAPI->getStatsItem('conversations_messages'),
                    'members'                => $this->xenAPI->getStatsItem('users'),
                    'latest_member'          => array('user_id' => $latest_user->getID(), 'username' => $latest_user->getUsername()),
                    'registrations_today'    => $this->xenAPI->getStatsItem('registrations_today'),
                    'threads_today'          => $this->xenAPI->getStatsItem('threads_today'),
                    'posts_today'            => $this->xenAPI->getStatsItem('posts_today'),
                    'users_online'           => $this->xenAPI->getUsersOnlineCount($this->getUser())
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
                $fetchOptions = array();
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

                // Check if request has grab_content.
                if ($this->hasRequest('grab_content')) {
                    $fetchOptions['grab_content'] = TRUE;

                    // Check if request has content_limit.
                    if ($this->hasRequest('content_limit')) {
                        if (!$this->getRequest('content_limit') && (is_numeric($this->getRequest('content_limit')) && $this->getRequest('content_limit') != 0)) {
                            // Throw error if the 'content_limit' argument is set but empty.
                            $this->throwError(1, 'content_limit');
                            break;
                        } else if (!is_numeric($this->getRequest('content_limit'))) {
                            // Throw error if the 'content_limit' argument is set but not a number.
                            $this->throwError(21, 'content_limit');
                        }
                        $fetchOptions['content_limit'] = $this->getRequest('content_limit');
                    }
                }

                // Try to grab the thread from XenForo.
                $thread = $this->getXenAPI()->getThread($string, $fetchOptions, $this->getUser());
                if ($thread == NULL) {
                     // Could not find the thread, throw error.
                    $this->throwError(19, 'thread', $string);
                } else if (!$this->hasAPIKey() && !$this->getXenAPI()->canViewThread($this->getUser(), $thread)) {
                    if (isset($this->grab_as)) {
                        // Thread was found but the 'grab_as' user is not permitted to view the thread.
                        $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this thread');
                    } else { 
                        // Thread was found but the user is not permitted to view the thread.
                        $this->throwError(20, 'You do', 'this thread');
                    }
                } else if ($this->hasAPIKey() && isset($this->grab_as) && !$this->getXenAPI()->canViewThread($this->getUser(), $thread)) {
                    // Thread was found but the 'grab_as' user is not permitted to view the thread.
                    $this->throwError(20, $this->getUser()->getUsername() . ' does', 'this thread');
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
                $this->setLimit(10);
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
                    unset($user);
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

                // Check if request has grab_content.
                if ($this->hasRequest('grab_content')) {
                    $fetch_options['grab_content'] = TRUE;

                    // Check if request has content_limit.
                    if ($this->hasRequest('content_limit')) {
                        if (!$this->getRequest('content_limit') && (is_numeric($this->getRequest('content_limit')) && $this->getRequest('content_limit') != 0)) {
                            // Throw error if the 'content_limit' argument is set but empty.
                            $this->throwError(1, 'content_limit');
                            break;
                        } else if (!is_numeric($this->getRequest('content_limit'))) {
                            // Throw error if the 'content_limit' argument is set but not a number.
                            $this->throwError(21, 'content_limit');
                        }
                        $fetch_options['content_limit'] = $this->getRequest('content_limit');
                    }
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
            case 'register':
                /**
                * Registers a user.
                */
                // Init user array.
                $user_data = array();

                // Array of required parameters.
                $required_parameters = array('username', 'password', 'email');

                // Array of additional parameters.
                $additional_parameters = array('timezone', 'gender', 'dob_day', 'dob_month', 'dob_year', 'ip_address');

                foreach ($required_parameters as $required_parameter) {
                    // Check if the required parameter is set and not empty.
                    $this->checkRequestParameter($required_parameter);

                    // Set the request value.
                    $user_data[$required_parameter] = $this->getRequest($required_parameter);
                }

                foreach ($additional_parameters as $additional_parameter) {
                    // Check if the additional parameter is set and not empty.
                    $this->checkRequestParameter($additional_parameter, FALSE);

                    if ($this->getRequest($additional_parameter)) {
                        // Set the request value.
                        $user_data[$additional_parameter] = $this->getRequest($additional_parameter);
                    }
                }

                if ($this->hasRequest('group')) {
                    // Request has value.
                    if (!$this->getRequest('group')) {
                        // Throw error if the 'group' argument is set but empty.
                        $this->throwError(1, 'group');
                        break;
                    }
                    $group = $this->getXenAPI()->getGroup($this->getRequest('group'));
                    if (!$group) {
                        $registration_error = array(
                            'error_id' => 2,
                            'error_key' => 'group_not_found', 
                            'error_field' => 'group', 
                            'error_phrase' => 'Could not find group with parameter "' . $this->getRequest('group') . '"'
                        );
                        $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                    }
                    // Set the group id of the registration.
                    $user_data['group_id'] = $group['user_group_id'];
                }

                if ($this->hasRequest('custom_fields')) {
                    // Request has value.
                    if (!$this->getRequest('custom_fields')) {
                        // Throw error if the 'custom_fields' argument is set but empty.
                        $this->throwError(1, 'custom_fields');
                        break;
                    }
                    $custom_fields = $this->getCustomArray($this->getRequest('custom_fields'));

                    // Check if we found any valid custom fields, throw error if not.
                    if (count($custom_fields) == 0) {
                        // The custom fields array was empty, throw error.
                        $registration_error = array(
                            'error_id' => 5,
                            'error_key' => 'invalid_custom_fields', 
                            'error_field' => 'custom_fields', 
                            'error_phrase' => 'The custom fields values were invalid, valid values are: '
                                            . 'custom_fields=custom_field1=custom_value1,custom_field2=custom_value2 '
                                            . 'but got: "' . $this->getRequest('custom_fields') . '" instead'
                        );
                        $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                    }
                    $user_data['custom_fields'] = $custom_fields;
                }

                // Check if add groups is set.
                if ($this->hasRequest('add_groups')) {
                    // Request has value.
                    if (!$this->getRequest('add_groups')) {
                        // Throw error if the 'add_groups' argument is set but empty.
                        $this->throwError(1, 'add_groups');
                    }
                    // Initialize the array.
                    $user_data['add_groups'] = array();

                    // Check if value is an array.
                    if (strpos($this->getRequest('add_groups'), ',') !== FALSE) {
                        // Value is an array, explode it.
                        $groups = explode(',', $this->getRequest('add_groups'));

                        // Loop through the group values.
                        foreach ($groups as $group_value) {
                            // Grab the group from the group value.
                            $group = $this->getXenAPI()->getGroup($group_value);

                            // Check if group was found.
                            if (!$group) {
                                // Group was not found, throw error.
                                $registration_error = array(
                                    'error_id' => 2,
                                    'error_key' => 'group_not_found', 
                                    'error_field' => 'add_groups', 
                                    'error_phrase' => 'Could not find group with parameter "' . $group_value . '" in array "' . $this->getRequest('add_group') . '"'
                                );
                                $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                            }
                            // Add the group_id to the the add_group array.
                            $user_data['add_groups'][] = $group['user_group_id'];
                        }
                    } else {
                        // Grab the group from the group value.
                        $group = $this->getXenAPI()->getGroup($this->getRequest('add_groups'));

                        // Check if group was found.
                        if (!$group) {
                            // Group was not found, throw error.
                            $registration_error = array(
                                'error_id' => 2,
                                'error_key' => 'group_not_found', 
                                'error_field' => 'add_groups', 
                                'error_phrase' => 'Could not find group with parameter "' . $this->getRequest('add_groups') . '"'
                            );
                            $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                        }
                        // Add the group_id to the the add_groups array.
                        $user_data['add_groups'][] = $group['user_group_id'];
                    }
                }

                if ($this->hasRequest('user_state')) {
                    // Request has user_state.
                    if (!$this->getRequest('user_state')) {
                        // Throw error if the 'user_state' argument is set but empty.
                        $this->throwError(1, 'user_state');
                        break;
                    }
                    // Set the user state of the registration.
                    $user_data['user_state'] = $this->getRequest('user_state');
                }

                if ($this->hasRequest('language_id')) {
                    // Request has language_id.
                    if (!$this->getRequest('language_id')) {
                        // Throw error if the 'language_id' argument is set but empty.
                        $this->throwError(1, 'language_id');
                        break;
                    }
                    // Set the language id of the registration.
                    $user_data['language_id'] = $this->getRequest('language_id');
                }

                $registration_results = $this->getXenAPI()->register($user_data);

                if (!empty($registration_results['error'])) {
                    // The registration failed, process errors.
                    if (is_array($registration_results['errors'])) {
                        // The error message was an array, loop through the messages.
                        $error_keys = array();
                        foreach ($registration_results['errors'] as $error_field => $error) {
                            if (!($error instanceof XenForo_Phrase)) {
                                $registration_error = array(
                                    'error_id' => 1,
                                    'error_key' => 'field_not_recognised', 
                                    'error_field' => $error_field, 
                                    'error_phrase' => $error
                                );
                                $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');

                            }

                            // Let's init the registration error array.
                            $registration_error = array(
                                'error_id' => $this->getUserErrorID($error->getPhraseName()),
                                'error_key' => $error->getPhraseName(), 
                                'error_field' => $error_field, 
                                'error_phrase' => $error->render()
                            );
                            
                            $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                        }
                    } else {
                        $registration_error = array(
                            'error_id' => $registration_results['error'],
                            'error_key' => 'general_user_registration_error', 
                            'error_phrase' => $registration_results['errors']
                        );

                        $this->throwError(self::USER_ERROR, $registration_error, 'registering a new user');
                    }
                } else {
                    // Registration was successful, return results.
                    $this->sendResponse($registration_results);
                }
                break;
            default:
                // Action was supported but has not yet been added to the switch statement, throw error.
                $this->throwError(11, $this->getAction());
        }
        $this->throwError(7, 'executing action', $this->getAction());
    }
    
    /**
    * Send the response array in JSON.
    */
    public function sendResponse($data) {
        if ($this->hasRequest('debug')) {
            $data['debug'] = $this->getXenAPI()->getDebugData();
        }
        header('Content-type: application/json');
        die(json_encode($data));
    }
}