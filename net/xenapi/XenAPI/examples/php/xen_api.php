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
class XenAPI 
{
	const USER_AGENT = 'XenAPI/1.0';
	private $url, $api_key, $method, $parameters = NULL;
	private $timeout = 45;

	public function __construct($url, $api_key = NULL)
	{
		$this->url = $url;
		$this->api_key = $api_key;
	}

	public function getURL()
	{
		return $this->url;
	}

	public function setURL($url)
	{
		$this->url = $url;
	}

	public function getAPIKey()
	{
		return $this->api_key;
	}

	public function setAPIKey($api_key)
	{
		$this->api_key = $api_key;
	}

	public function getTimeout()
	{
		return $this->timeout;
	}

	public function setTimeout($timeout)
	{
		$this->timeout = $timeout;
	}

	private function setAction($action)
	{
		$this->setMethod($action);
	}

	private function getAction()
	{
		return $this->getMethod();
	}

	private function setMethod($method)
	{
		$this->method = $method;
	}

	private function getMethod()
	{
		return $this->method;
	}

	private function setParameters(array $parameters)
	{
		$this->parameters = $parameters;
	}

	private function getParameters()
	{
		return $this->parameters;
	}

	private function getAPIURL()
	{
		return $this->getURL()
			. '?action=' . $this->getMethod()
			. ($this->getParameters() !== NULL 
				&& is_array($this->getParameters()) 
				&& count($this->getParameters()) > 0 
					? '&' . http_build_query($this->getParameters()) 
					: ''
			);
	}

	private function getResponse($url)
	{
		if (is_callable('curl_init')) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE); 
		  	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE); 
		  	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0); 
			curl_setopt($ch, CURLOPT_TIMEOUT, $this->getTimeout());
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_USERAGENT, self::USER_AGENT);
			$result = curl_exec($ch);
			$info = curl_getinfo($ch);
			if (curl_errno($ch) || $info['http_code'] != 200) {
				$error_number = curl_errno($ch);
				curl_close($ch);
				throw new Exception($result, $info['http_code']);
			} else {
				curl_close($ch);
				return $result;
			}
		} else {
			ini_set('default_socket_timeout', $this->getTimeout());
			$context = stream_context_create(array(
				'http' => array(
				    'method'  => 'GET',
				    'timeout' => $this->getTimeout()
				)
			));
			return file_get_contents($url, 0, $context);
		}
	}

	private function execute()
	{
		$response = $this->getResponse($this->getAPIURL());
		return json_decode($response, TRUE);
	}

	public function authenticate($username, $password)
	{
		$this->setMethod('authenticate');
		$this->setParameters(array(
			'username' => $username,
			'password' => $password
		));
		return $this->execute();
	}

	public function createAlert($user, $cause_user, $content_type, $content_id, $alert_action)
	{
		$this->setMethod('createAlert');
		$this->setParameters(array(
			'user'         => $user,
			'cause_user'   => $cause_user,
			'content_type' => $content_type,
			'content_id'   => $content_id,
			'alert_action' => $alert_action
		));
		return $this->execute();
	}

	public function getActions()
	{
		$this->setMethod('getActions');
		return $this->execute();
	}

	public function login($username, $password, $ip_address)
	{
		$this->setMethod('login');
		$this->setParameters(array(
			'username'   => $username,
			'password'   => $password,
			'ip_address' => $ip_address
		));
		$response = $this->execute();

		$success = setcookie(
			$response['cookie_name'], 
			$response['cookie_id'], 
			$response['cookie_expiration'], 
			$response['cookie_path'], 
			$response['cookie_domain'],
			$response['cookie_secure'],
			TRUE
		);

		return $success;
	}
}
?>