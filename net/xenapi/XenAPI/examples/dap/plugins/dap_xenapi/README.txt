=== DAP Xenforo Plugin ===
License: LGPLv3 or later
License URI: http://www.gnu.org/licenses/lgpl-3.0-standalone.html
Version: 1.0

DAP Xenforo Plugin allows to automatically register DAP users with a XenForo installation.

== Description ==

DAP Xenforo Plugin allows to automatically register DAP users with a XenForo installation when they register.

This is achived by using a XenForo REST API called XenAPI <http://www.xenapi.net/>.

Using XenAPI makes it possible to have DAP and XenForo running on different servers, meaning DAP Xenforo Plugin does not
depend on a local installation of XenForo to function.

DAP XenForo Plugin send a register request to the XenForo installation via XenAPI to register the user.
In addition, if the group parameter is set, upon the removal of a DAP user; DAP XenForo Plugin sends an additional 
request to the XenForo installation via XenAPI. This request moves the XenForo user to a specified XenForo group.

By default, DAP XenForo Plugin will register the username by using the first name and last name of the user, meaning
the username format of the XenForo user will become `FirstName LastName`, the issue with this is we will have no way to
identify the user if the user changes the username/email in the XenForo installation.
A workaround to this is to use XenForo's custom fields, we can then identify the DAP user with a custom identifier.
The custom identifier uses the following format: `FirstName LastName UserID`

It is HIGHLY recommend to use a custom field as a unique identifier.

== Installation ==

Follow each step carefully as they are all crucial for the installation.

1. Download XenAPI for Xenforo from the GitHub repository, found here: 
   https://github.com/Contex/XenAPI/archive/master.zip
2. Open the downloaded ZIP archive.
3. Upload `/XenAPI-master/net/xenapi/XenAPI/api.php` to the root directory of your XenForo installation.
4. Generate a hash by using an online service, like http://www.miraclesalad.com/webtools/md5.php
5. Set an API key for XenAPI, this can be done by editing the `api.php` file and replacing the `API_KEY` string with
   the hash generated in step 4.
6. Upload `/XenAPI-master/net/xenapi/XenAPI/examples/dap/plugins/dap_xenapi/dap_xenapi.class.php` to 
   `/plugins/dap_xenapi/` of your DAP installation.
7. If you are NOT using the group parameter, you can skip this step and continue from step 8.
	a. Login to your XenForo Admin panel and go to user groups, `Users -> User Groups -> List User Groups`.
	b. Find the group you wish the user to be assigned to when they register.
	c. Note the ID of the group, we'll use it later, `admin.php?user-groups/example-group.6/edit`, 6 is the group ID.
8. If you are NOT using a custom field identifier you can skip this step and continue from step 9.
	a. Login to your XenForo Admin panel and go to custom user fields, 
	   `Users -> User Customization -> Custom User Fields`.
	b. Press `+ Create New Field` in the upper right hand corner.
	c. Set a custom field title, set display location to `Preferences` and set the custom field ID.
	   Note the ID of the group for the next step, an example of a group ID would be 'unique_user'.
9. We now need to create the string that is going to be sent to DAP XenForo Plugin.
   Here's the the string that is sent to DAP XenForo Plugin:
   `dap_xenapi:API_KEY:PROTOCOL:API_LOCATION:GROUP_ID:CUSTOM_FIELD_IDENTIFIER`

   a. `API_KEY` should be replaced with the hash you generated in step 4 and used in step 5.
      Example API_KEY: a5b2b1f2mc1mas2f3
   b. `PROTOCOL` should be replaced with which protocol you wish to use, current options are only `http` and `https`.
      Please note that if you use `http`, the password of the user will be sent over a unecrypted protocol.
      Example PROTOCOL: https
   c. `API_LOCATION` should be replaced with the location of XenAPI's file, `api.php`, which you should now have in the
      root directory of your XenForo installation. Make sure you do NOT include the `http` of the URL.
      Example API_LOCATION: example.com/forum/api.php
   d. `GROUP_ID` should be replaced with the group ID you wish the user to be assigned to, this is the group ID you 
      found in step 7. If you wish not to assign the user to a group, you can remove this parameter or set it to `0`.
      Example GROUP_ID: 6
      Example GRPOU_ID: 0
   e. `CUSTOM_FIELD_IDENTIFIER` should be replaced with the field ID you created in step 8. If do not wish to use the 
      custom field identifier, remove this field.
      Example CUSTOM_FIELD_IDENTIFIER: unique_user.

   Examples:
   a. Just register the user with the XenForo installation: `dap_xenapi:a5b2b1f2mc1mas2f3:https:example.com/forum/api.php`.
   b. Register the user AND assign the user to a specific group: `dap_xenapi:a5b2b1f2mc1mas2f3:https:example.com/forum/api.php:6`.
   c. Register the user AND assign the user to a specific group AND use a custom field identifier: `dap_xenapi:a5b2b1f2mc1mas2f3:https:example.com/forum/api.php:6:unique_user`.
   d. Register the user AND set a custom field identifier: `dap_xenapi:a5b2b1f2mc1mas2f3:https:example.com/forum/api.php:0:unique_user`.

   It is recommended to use example c.
10. Open your DAP installation administration and go into product management (Products/Levels -> Manage).
11. Find the product you wish to integrate XenForo with, click on the `Notifications` tab.
12. Add the string you created in step 9 to the `Plugin Notification upon User "Add"`
    and `Plugin Notification upon User "Add"` fields.

== Frequently Asked Questions ==

= I need help/support, where can I get it? =

You can email me at me@contex.me or post a message in the XenAPI thread: http://xenforo.com/community/threads/34270

= Does this plugin take in count for password changes? =

Not at this time.

= Does this plugin take in count for email/username changes? =

No, but if you use the custom field identifier, you will not run into any issues with the communication between DAP and XenForo.