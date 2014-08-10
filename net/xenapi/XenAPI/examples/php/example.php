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
header('Content-type: text/plain');
require_once 'xen_api.php';

$xenAPI = new XenAPI('http://xenapi.net/api.php', 'REPLACE_THIS_WITH_AN_API_KEY');
try {
	$response = $xenAPI->login('Contex', 'Password', '127.0.0.1');
	var_dump($response);
} catch (Exception $e) {
	if ($e->getCode() == 400) {
		$error = json_decode($e->getMessage(), TRUE);
		die('API call failed: API ERROR CODE=' . $error['error'] . ' & API ERROR MESSAGE=' . $error['message']);
	} else {
		die('API call failed: HTTP RESPONSE=' . $e->getMessage() . ' & HTTP STATUS CODE=' . $e->getCode());
	}
}