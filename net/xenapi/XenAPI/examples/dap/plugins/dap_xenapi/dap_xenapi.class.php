<?php
/*
This file is part of DAP Xenforo Plugin <http://www.xenapi.net/dap>.

DAP Xenforo Plugin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DAP Xenforo Plugin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DAP Xenforo Plugin.  If not, see <http://www.gnu.org/licenses/>.
*/
class dap_xenapi {
	const PARAMETERS_FIELDS  = 'dap_xenapi:API_KEY:PROTOCOL:API_URL:GROUP';
	/**
	* Default constructor.
	*/
	function dap_xenapi()
	{ 
	}

	/**
	* This function is called by DAP once a user registers.
	*/
	function register($user_id, $product_id, $parameters) 
	{
		// Tell the log that we recieved the request.
		$this->log(
			'register', 
			'Registering user ID: ' . $user_id . ' with XenAPI.'
		);

		// Grab the DAP user from the user ID.
		$dap_user = Dap_User::loadUserById($user_id);

		// Set the unique username.
		$username = trim($dap_user->getFirst_name()) 
				  . ' ' . trim($dap_user->getLast_name());

		// Tell the log that we recieved the request.
		$this->log(
			'register', 
			'Registering user ID: ' 
				. $user_id . ' with username "' . $username . '".'
		);

		// Set the variables of the DAP user.
		$user_data = array(
			'username'   => $username,
			'password'   => trim($dap_user->getPassword()),
			'email'      => trim($dap_user->getEmail()),
			'user_state' => 'valid',
			'ip_address' => trim($dap_user->getIpaddress())
		);

		// Split the parameters into an array.
		$data = explode(':', $parameters);

		// Initialize the API data.
		try 
		{
			$api_data = $this->initializeAPIData($data);
		} 
		catch (Exception $e) 
		{
			// The initilization failed, log error and return exception message.
			$this->log('initializeAPIData', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		// Get the additional parameters.
		try 
		{
			$additional_parameters = $this->getAdditionalParameters(
					$data, 
					$parameters
				);
		} 
		catch (Exception $e) 
		{
			// The API query failed, log error and return exception message.
			$this->log('getAdditionalParameters', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		// Set which group the user should have.
		$user_data['add_groups'] = $additional_parameters['group'];

		// Check if the custom field identifier parameter is set.
		if (!empty($additional_parameters['custom_field_identifier'])) 
		{
			// Log that we found a custom field identifier.
			$this->log(
				'register', 
				'Found custom field identifier: ' 
					. $additional_parameters['custom_field_identifier'] 
					. '=' . $username . ' ' . $user_id
			);

			// Set the custom field identifier.
			$user_data['custom_fields'] = $additional_parameters['custom_field_identifier'] 
										. '=' 
										. $username . ' ' . $user_id;
		}

		// Unset the additional parameters.
		unset($additional_parameters);

		// Execute the API query.
		try 
		{
			$this->apiRegister(
				$api_data['api_url'], 
				$api_data['api_key'], 
				$user_data
			);
		} 
		catch (Exception $e) 
		{
			// The API query failed, log error and return exception message.
			$this->log('apiRegister', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		return 0;
	}

	/**
	* This function is called by DAP once a user is removed.
	*/
	function unregister($user_id, $product_id, $parameters)
	{
		// Tell the log that we recieved the request.
		$this->log(
			'unregister', 
			'Editing user ID: ' . $user_id . ' with XenAPI.'
		);

		// Grab the DAP user from the user ID.
		$dap_user = Dap_User::loadUserById($user_id);

		// Set the unique username.
		$username = trim($dap_user->getFirst_name()) 
				  . ' ' . trim($dap_user->getLast_name());

		// Set the variables of the DAP user.
		$user_data = array(
			'user' => $username
		);

		// Split the parameters into an array.
		$data = explode(':', $parameters);

		// Initialize the API data.
		try 
		{
			$api_data = $this->initializeAPIData($data);
		} 
		catch (Exception $e) 
		{
			// The initilization failed, log error and return exception message.
			$this->log('initializeAPIData', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		// Get the additional parameters.
		try 
		{
			$additional_parameters = $this->getAdditionalParameters(
				$data, 
				$parameters
			);
		} 
		catch (Exception $e) 
		{
			// The API query failed, log error and return exception message.
			$this->log('getAdditionalParameters', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		// Set which group to remove.
		$user_data['remove_groups'] = $additional_parameters['group'];

		// Check if the custom field identifier parameter is set.
		if (!empty($additional_parameters['custom_field_identifier'])) 
		{
			// Log that we found a custom field identifier.
			$this->log(
				'unregister', 
				'Found custom field identifier: ' 
					. $additional_parameters['custom_field_identifier']
			);

			// Set the custom field identifier.
			$user_data['custom_field_identifier'] = $additional_parameters['custom_field_identifier'];
		}

		// Unset the additional parameters.
		unset($additional_parameters);

		// Execute the API query.
		try 
		{
			$this->apiEditUser(
				$api_data['api_url'], 
				$api_data['api_key'], 
				$user_data
			);
		} 
		catch (Exception $e) 
		{
			// The API query failed, log error and return exception message.
			$this->log('getResults', $e->getMessage(), 'error');
			return $e->getMessage();
		}

		return 0;
	}

	private function handleAPIError($api_response, $api_url, $api_key, $action, 
		$user_data
	) {
		// Decode the JSON.
		$api_response = json_decode($api_response, TRUE);

		/* 
		Check if the JSON decode failed 
		(meaning that the results was not a JSON string).
		*/
 		if (json_last_error() != JSON_ERROR_NONE) 
 		{
			// The request failed, throw exception.
			$this->log(
				'handleAPIError', 
				'Request failed, results was not a JSON string: ' 
					. $api_response,
	  			'error'
			);
			return NULL;
 		}

		// Log the error ID and error message.
		$this->log(
			'handleAPIError', 
			'API returned error id ' . $api_response['error'] . ': ' 
				. $api_response['message'], 
			'error'
		);

		// Check if the error is a user error.
		if (!empty($api_response['user_error_id']))
		{
			/* 
			The error was a user error, 
			log the user error ID and user error message/phrase.
			*/
			$this->log(
				'handleAPIError', 
				'Found user error id ' . $api_response['user_error_id'] . ': ' 
					. $api_response['user_error_phrase'], 
				'error'
			);

			// Check if user already exist.
			if ($api_response['user_error_id'] == 40) 
			{
				// User exist, let's edit the user instead.
				$this->log(
					'handleAPIError', 
					'User already exist, attempting to edit user instead.', 
					'warning'
				);

				// Init the edit data.
				$edit_data = array(
					'user' 			=> $user_data['username'],
					'add_groups' => $user_data['add_groups']
				);

				// Check if the custom field identifier parameter is set.
				if (!empty($user_data['custom_field_identifier'])) 
				{
					// Log that we found a custom field identifier.
					$this->log(
						'handleAPIError', 
						'Found custom field identifier: ' 
							. $user_data['custom_field_identifier']
					);

					// Set the custom field identifier.
					$edit_data['custom_field_identifier'] = $user_data['custom_field_identifier'];
				}

				// Execute the API edit request.
				$this->apiEditUser($api_url, $api_key, $edit_data);
			}

			// Check if the user error field is set.
			if (!empty($api_response['user_error_field']))
			{
				// User error field is set, log it.
				$this->log(
					'handleAPIError', 
					'User error field: ' . $api_response['user_error_field'], 
					'error'
				);
			}

			// Check if the user error key is set.
			if (!empty($api_response['user_error_key']))
			{
				// User error key is set, log it.
				$this->log(
					'handleAPIError', 
					'User error key: ' . $api_response['user_error_key'], 
					'error'
				);
			}
		}
	}

	private function getAdditionalParameters($data, $parameters)
	{
		// Init the additional parameters.
		$additional_parameters = array();

		// Check if the group value is set.
		if (!isset($data[4]))
		{
			// Group value is not set, throw error message.
			throw Exception(
				'Missing group ID/name. Params should be ' 
		  		. '(' . self::PARAMETERS_FIELDS . ':GROUP), but is (' 
	  			. $parameters . ')'
			);
		}
		else if (empty($data[4]))
		{
	 		// Group value is set but empty, throw error message.
			throw Exception(
				'Group ID/name is empty. Params should be ' 
			  	. '(' . self::PARAMETERS_FIELDS . '), but is (' 
		  		. $parameters . ')'
			);
		}

		// Set the group.
		$additional_parameters['group'] = $data[4];

		// Check if the custom identifier field value is set.
		if (isset($data[5]))
		{
			if (empty($data[5]))
			{
		 		/* 
		 		Custom identifier field is set but empty, throw error message.
		 		*/
				throw Exception(
					'Custom identifier field is set but empty. Params should be' 
 				  	. ' (' . self::PARAMETERS_FIELDS 
			  		. ':CUSTOM_USER_FIELD), but is (' . $parameters . ')'
 				);
			}

			/*
			Set the custom identifier field of 
			which we want to identify the user with.
			*/
			$additional_parameters['custom_field_identifier'] = $data[5];
		}
		return $additional_parameters;
	}

	private function initializeAPIData($data) 
	{
		// Grab the API key from the parameters.
		$api_key = $this->getAPIKey($data);

		// Check if we found the API key from the parameters.
		if ($api_key == NULL) 
		{
			// Could not find an API key, throw exception.
			throw new Exception(
				'Missing API key. Params should be ' 
		  		. '(' . self::PARAMETERS_FIELDS 
		  		. '), but is (' . $parameters . ')'
			);
		}

		// We assume the API key was found.
		$this->log('initializeAPIData', 'Found API key = ' . $api_key . '.');

		// Grab the API key from the parameters.
		$api_url = $this->getAPIURL($data);

		// Check if we found the API URL from the parameters.
		if ($api_url == NULL) 
		{
			// Could not find an API URL, throw exception.
			throw new Exception(
				'Missing API URL. Params should be ' 
		  		. '(' . self::PARAMETERS_FIELDS . '), but is (' 
	  			. $parameters . ')'
			);
		}

		// We assume the API URL was found.
		$this->log('initializeAPIData', 'Found API URL = ' . $api_url);

		return array('api_key' => $api_key, 'api_url' => $api_url);
	}

	/**
	* Get the API key from the intput parameters, 
	* returns NULL if no API key could be found.
	*/
	private function getAPIKey($data) 
	{
		if (isset($data[1]) && !empty($data[1])) 
		{
			// We assume the API key was found and return it.
			return $data[1];
		}
		// An API key could not be found, returning NULL.
		return NULL;
	}

	/**
	* Get the API url from the intput parameters, 
	* returns NULL if no API url could be found.
	*/
	private function getAPIURL($data) 
	{
		if (isset($data[2]) && !empty($data[2]) 
			&& isset($data[3]) && !empty($data[3])) 
		{
			// Lowercase the protocol.
			$data[2] = strtolower($data[2]);

			// Let's make sure the protocol is correct.
			if ($data[2] != 'http' && $data[2] != 'https')
			{
				// The protocol was invalid, log error and return NULL.
				$this->log(
					'getAPIURL', 
					'The protocol was invalid, expected "http" or "https",'
						. 'but got: ' . $data[2], 
					'error'
				);
				return NULL;
			}

			// We assume the URL key was found and return it.
			return strtolower($data[2]) . '://' . $data[3];
		}
		// An API URL could not be found, returning NULL.
		return NULL;
	}

	/**
	* Make it easier to log the messages to file.
	*/
	protected function log($method, $message, $log_level = '')
	{
		// Set the log prefix.
		$log_prefix = 'dap_xenapi.class.php: ' . $method . '(): ' 
					. (!empty($log_level) ? strtoupper($log_level) . ': ' : '')
					. ': ';

		/*
		Split the message into an array as 
		DAP only allows the max length of 200 characters.
		*/
		$message_array = str_split($message, 200 - strlen($log_prefix));

		// Loop through the messages and log them.
		foreach ($message_array as $message) 
		{
			// Log the message.
			logToFile($log_prefix . $message, LOG_INFO_DAP);
		}
	}

	private function apiRegister($api_url, $api_key, $user_data) 
	{
		$this->getResults($api_url, $api_key, 'register', $user_data);
	}

	private function apiEditUser($api_url, $api_key, $user_data) 
	{
		$this->getResults($api_url, $api_key, 'editUser', $user_data);
	}

	/**
	* This function handles everything related to the XenAPI, 
	* The function will fallback to file_get_contents if cURL is not found.
	* it will either return a JSON string, or NULL if something wrong happend.
	*/
	private function getResults($api_url = NULL, $api_key = NULL, 
		$action = NULL, array $user_data
	) {
		// Check if all the required parameters have been initialized.
		if ($api_url == NULL || $api_key == NULL || $action == NULL)
		{
			// One of the variables were not initialized, throe exception.
			throw new Exception(
				'One or more of the required parameters were NULL. ' 
				. 'api_key=' . $api_url . ', api_key=' . $api_key 
				. ', action=' . $action
		   );
		}

		// Initialize the API data.
		$api_data = array(
			'hash' => $api_key,
			'action' => $action
		);

		// Merge the API data array with the user data array.
		$api_data = array_merge($user_data, $api_data);

		// Check if cURL is available, fallback to file_get_contents if not.
		if (is_callable('curl_init'))
		{
			// cURL was found avaiable.
			$this->log('getResults', 'cURL was found.');

			// Initialize cURL with the input values.
			$curl_handle = curl_init();
			curl_setopt($curl_handle, CURLOPT_URL, $api_url);
			curl_setopt($curl_handle, CURLOPT_RETURNTRANSFER, 1);
			curl_setopt($curl_handle, CURLOPT_POST, 1);
			curl_setopt($curl_handle, CURLOPT_POSTFIELDS, $api_data);

			// Grab thet data of the cURL data.
			$response = curl_exec($curl_handle);

			// Check if something went wrong with the request.
			if ($response === FALSE)
			{
				// The cURL request failed, throw exception.
				throw new Exception(
					'Request failed with action: ' . $action 
				  . ', cURL error: ' . curl_error($curl_handle)
				);
			}

			// Get the HTTP status code.
			$http_status_code = curl_getinfo($curl_handle, CURLINFO_HTTP_CODE);

			// Close th cURL handle.
			curl_close($curl_handle);

			// Check if the status code was 200 (OK).
			if ($http_status_code != 200) 
			{
				// Check if the error parameter is set.
				if (!empty($response['error'])) 
				{
					$this->handleAPIError(
						$response, 
						$api_url, 
						$api_key, 
						$action, 
						$user_data
					);
				}

				/* 
				The request failed, response header did not return status 200, 
				throw exception.
				*/
				throw new Exception(
					'Request failed with action: ' . $action 
				  . ', HTTP status code was not 200: ' . $http_status_code
				);
			}
		}
		else
		{
			// cURL is not avaiable, fallback to file_get_contents instead.
			$this->log(
				'getResults', 
				'Could not find cURL, '
					.'falling back to file_get_contents instead', 
				'warning'
			);

			// Options for the stream.
			$options = array(
			    'http' => array(
			        'header'  => "Content-type: " 
			        		   . "application/x-www-form-urlencoded\r\n",
			        'method'  => 'POST',
			        'content' => http_build_query($api_data),
			    ),
			);

			// Create a stream with the options we set above.
			$context  = stream_context_create($options);

			// Get the results of the API query.
			$response = file_get_contents($api_url, FALSE, $context);

			// Check if something went wrong with the request.
			if ($response === FALSE) 
			{
				// The request failed, throw exception.
				throw new Exception('Request failed with action: ' . $action);
			}

			// Check if the status code was 200 (OK).
			if (strpos($http_response_header[0], '200') === FALSE) 
			{
				// Check if the error parameter is set.
				if (!empty($response['error'])) 
				{
					$this->handleAPIError(
						$response, 
						$api_url, 
						$api_key, 
						$action, 
						$user_data
					);
				}

				/* 
				The request failed, 
				response header did not return status 200, throw exception.
				*/
				throw new Exception(
					'Request failed with action: ' . $action 
				  	. ', HTTP status code was not 200: ' 
				  	. $http_response_header[0]
				);
			}
		}
		/* 
		For debugging: 
		$this->log(
			'getResults', 
			'Got response from the XenAPI:' . $response . '.'
		);
		*/

		// Decode the JSON.
		$response_decoded = json_decode($response, TRUE);

		/* 
		Check if the JSON decode failed 
		(meaning that the results was not a JSON string).
 		*/
 		if (json_last_error() != JSON_ERROR_NONE) 
 		{
			// The request failed, throw exception.
			throw new Exception(
				'Request failed with action: ' . $action 
			  . ', results was not a JSON string: ' . $response
			);
 		}

 		/* 
 		The results was a JSON response and contained no errors, 
 		return the results.
 		*/
 		return $response_decoded;
	}
}
?>