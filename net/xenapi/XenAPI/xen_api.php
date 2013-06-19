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
        require_once($this->xfDir . '/library/XenForo/Autoloader.php');
        XenForo_Autoloader::getInstance()->setupAutoloader($this->xfDir. '/library');
        XenForo_Application::initialize($this->xfDir . '/library', $this->xfDir);
        XenForo_Application::set('page_start_time', microtime(TRUE));

        // Disable XenForo's PHP 
        XenForo_Application::disablePhpErrorHandler();

        // Enable error logging for PHP.
        error_reporting(E_ALL & ~E_NOTICE);
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

    public function createConversation($user, $conversation_data = array()) { 
       if ($user == NULL) {
            // An user is required to create a new conversation.
            return array('error' => 13, 'errors' => 'User is required to create a conversation.');
        }

        $this->getModels()->checkModel('user', XenForo_Model::create('XenForo_Model_User'));
        $this->checkUserPermissions($user);
        if (!$this->getModels()->getModel('user')->canStartConversations($null, $user->getData())) {
            // User does not have permission to post in this thread.
            return array('error' => 14, 'errors' => 'The user does not have permissions to create a new conversation.');
        }

        // TODO: Check if user has permissions to start a conversation with the specified recepients.

        $conversation_data['message'] = XenForo_Helper_String::autoLinkBbCode($conversation_data['message']);

        $writer = XenForo_DataWriter::create('XenForo_DataWriter_ConversationMaster');
        $writer->setExtraData(XenForo_DataWriter_ConversationMaster::DATA_ACTION_USER, $user->data);
        $writer->setExtraData(XenForo_DataWriter_ConversationMaster::DATA_MESSAGE, $conversation_data['message']);
        $writer->set('user_id', $user->data['user_id']);
        $writer->set('username', $user->data['username']);
        $writer->set('title', $conversation_data['title']);
        $writer->set('open_invite', $conversation_data['open_invite']);
        $writer->set('conversation_open', $conversation_data['conversation_locked'] ? 0 : 1);
        $writer->addRecipientUserNames(explode(',', $conversation_data['recipients'])); // checks permissions

        $messageDw = $writer->getFirstMessageDw();
        $messageDw->set('message', $conversation_data['message']);

        $writer->preSave();

        if ($writer->hasErrors()) {
            // The post creation failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        $writer->save();
        $conversation = $writer->getMergedData();

        $this->getModels()->checkModel('conversation', XenForo_Model::create('XenForo_Model_Conversation'));
        $this->getModels()->getModel('conversation')->markConversationAsRead($conversation['conversation_id'], $user->data['user_id'], XenForo_Application::$time);

        return $conversation;
    }

    public function createConversationReply($user, $conversation_reply_data = array()) { 
       if ($user == NULL) {
            // An user is required to create a new conversation.
            return array('error' => 13, 'errors' => 'User is required to create a conversation reply.');
        }

        $conversation = $this->getConversation($conversation_reply_data['conversation_id'], $user);

        $this->getModels()->checkModel('conversation', XenForo_Model::create('XenForo_Model_Conversation'));
        if (!$this->getModels()->getModel('conversation')->canReplyToConversation($conversation, $null, $user->getData())) {
            // User does not have permission to reply to this conversation.
            return array('error' => 14, 'errors' => 'The user does not have permissions to reply to this conversation.');
        }

        $conversation_reply_data['message'] = XenForo_Helper_String::autoLinkBbCode($conversation_reply_data['message']);

        $writer = XenForo_DataWriter::create('XenForo_DataWriter_ConversationMessage');
        $writer->setExtraData(XenForo_DataWriter_ConversationMessage::DATA_MESSAGE_SENDER, $user->getData());
        $writer->set('conversation_id', $conversation['conversation_id']);
        $writer->set('user_id', $user->data['user_id']);
        $writer->set('username', $user->data['username']);
        $writer->set('message', $conversation_reply_data['message']);
        $writer->preSave();

        if ($writer->hasErrors()) {
            // The conversation reply creation failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        $writer->save();

        $conversation_reply = $writer->getMergedData();

        $this->getModels()->getModel('conversation')->markConversationAsRead($conversation['conversation_id'], $user->data['user_id'], XenForo_Application::$time, 0, FALSE);

        return $conversation_reply;
    }

    public function createPost($user, $post_data = array()) { 
       if ($user == NULL) {
            // An user is required to create a new post.
            return array('error' => 13, 'errors' => 'User is required to create a post.');
        }

        $fetchOptions = array('permissionCombinationId' => $user->data['permission_combination_id']);

        $thread = $this->getThread($post_data['thread_id']);
        $forum = $this->getForum($thread['node_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));
        $permissions = XenForo_Permission::unserializePermissions($forum['node_permission_cache']);

        if (!$this->canViewThread($user, $thread, $permissions) || !$this->canReplyToThread($user, $thread, $forum, $permissions)) {
            // User does not have permission to post in this thread.
            return array('error' => 14, 'errors' => 'The user does not have permissions to post in this thread.');
        }

        $input['message'] = XenForo_Helper_String::autoLinkBbCode($post_data['message']);

        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));
        $writer = XenForo_DataWriter::create('XenForo_DataWriter_DiscussionMessage_Post');
        $writer->set('user_id', $user->data['user_id']);
        $writer->set('username', $user->data['username']);
        $writer->set('message', $input['message']);
        $writer->set('message_state', $this->getModels()->getModel('post')->getPostInsertMessageState($thread, $forum));
        $writer->set('thread_id', $thread['thread_id']);
        $writer->setExtraData(XenForo_DataWriter_DiscussionMessage_Post::DATA_FORUM, $forum);
        $writer->preSave();

        if ($writer->hasErrors()) {
            // The post creation failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        $writer->save();
        $post = $writer->getMergedData();

        $this->getModels()->checkModel('thread_watch', XenForo_Model::create('XenForo_Model_ThreadWatch'));

        $this->getModels()->getModel('thread_watch')->setThreadWatchStateWithUserDefault($user->data['user_id'], $thread['thread_id'], $user->data['default_watch_state']);

        return $post;
    }

    public function createProfilePost($user, $profile_post_data = array()) { 
       if ($user == NULL) {
            // An user is required to create a new post.
            return array('error' => 13, 'errors' => 'User is required to create a profile post.');
        }

        $this->getModels()->checkModel('user_profile', XenForo_Model::create('XenForo_Model_UserProfile'));

        $profile_user = $profile_post_data['user_id'];
        $this->checkUserPermissions($profile_user, array('followingUserId' => $user->data['user_id']));
        $this->checkUserPermissions($user, array('followingUserId' => $profile_user->data['user_id']));

        if (!$this->getModels()->getModel('user_profile')->canPostOnProfile($profile_user->getData(), $null, $user->getData())) {
            return array('error' => 14, 'errors' => 'The user does not have permissions to create a new profile post');
        }

        if ($user->data['user_id'] == $profile_post_data['user_id']) {
            $profile_post_id = $this->getModels()->getModel('user_profile')->updateStatus($profile_post_data['message'], XenForo_Application::$time, $user->getData());
        } else {
            $this->getModels()->checkModel('profile_post', XenForo_Model::create('XenForo_Model_ProfilePost'));
            $writer = XenForo_DataWriter::create('XenForo_DataWriter_DiscussionMessage_ProfilePost');
            $writer->set('user_id', $user->data['user_id']);
            $writer->set('username', $user->data['username']);
            $writer->set('message', $profile_post_data['message']);
            $writer->set('profile_user_id', $profile_user->data['user_id']);
            $writer->set('message_state', $this->getModels()->getModel('profile_post')->getProfilePostInsertMessageState($profile_user->getData(), $user->getData()));
            $writer->setExtraData(XenForo_DataWriter_DiscussionMessage_ProfilePost::DATA_PROFILE_USER, $profile_user->getData());
            $writer->preSave();

            if ($writer->hasErrors()) {
                // The profile post creation failed, return errors.
                return array('error' => TRUE, 'errors' => $writer->getErrors());
            }

            $writer->save();

            $profile_post_id = $writer->get('profile_post_id');
        }

        return $this->getProfilePost($profile_post_id);
    }

    public function createProfilePostComment($user, $profile_post_data = array()) { 
       if ($user == NULL) {
            // An user is required to create a new post.
            return array('error' => 13, 'errors' => 'User is required to create a profile post comment.');
        }

        $this->getModels()->checkModel('profile_post', XenForo_Model::create('XenForo_Model_ProfilePost'));

        $profile_post = $this->getProfilePost($profile_post_data['profile_post_id']);

        $profile_user = $profile_post_data['profile_user_id'];
        $this->checkUserPermissions($profile_user, array('followingUserId' => $user->data['user_id']));
        $this->checkUserPermissions($user, array('followingUserId' => $profile_user->data['user_id']));

        if (!$this->getModels()->getModel('profile_post')->canCommentOnProfilePost($profile_post, $profile_user->getData(), $null, $user->getData())) {
            return array('error' => 14, 'errors' => 'The user does not have permissions to create a new profile post');
        }

        $writer = XenForo_DataWriter::create('XenForo_DataWriter_ProfilePostComment');
        $writer->setExtraData(XenForo_DataWriter_ProfilePostComment::DATA_PROFILE_USER, $profile_user->getData());
        $writer->setExtraData(XenForo_DataWriter_ProfilePostComment::DATA_PROFILE_POST, $profile_post);
        $writer->bulkSet(array(
            'profile_post_id' => $profile_post['profile_post_id'],
            'user_id' => $user->data['user_id'],
            'username' => $user->data['username'],
            'message' => $profile_post_data['message']
        ));

        $writer->preSave();

        if ($writer->hasErrors()) {
            // The profile post comment creation failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        $writer->save();

        return array_values($this->getModels()->getModel('profile_post')->getProfilePostCommentsByProfilePost($profile_post['profile_post_id']));
    }


    public function createThread($user, $thread_data = array()) {
        // TODO: Add support for polls. 
       if ($user == NULL) {
            // An user is required to create a new thread.
            return array('error' => 13, 'errors' => 'User is required to create a thread.');
        }

        $forum = $this->getForum($thread_data['node_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));

        $permissions = XenForo_Permission::unserializePermissions($forum['node_permission_cache']);

        // Check if user can view the forum, if not; it's most likely private or the user has not access to the forum.
        if (!$this->canViewNode($user, $forum, $permissions) || !$this->canPostThreadInForum($user, $forum, $permissions)) {
            // User does not have permission to post in this thread.
            return array('error' => 14, 'errors' => 'The user does not have permissions to create a new thread in this forum.');
        }

        $input['title'] = $thread_data['title'];

        $input['message'] = XenForo_Helper_String::autoLinkBbCode($thread_data['message']);

        if (!empty($thread_data['prefix_id'])) {
            $input['prefix_id'] = $thread_data['prefix_id'];
        }

        $this->getModels()->checkModel('thread_prefix', XenForo_Model::create('XenForo_Model_ThreadPrefix'));

        if (!$this->getModels()->getModel('thread_prefix')->verifyPrefixIsUsable($input['prefix_id'], $thread_data['node_id'])) {
            $input['prefix_id'] = 0; // not usable, just blank it out
        }

        $writer = XenForo_DataWriter::create('XenForo_DataWriter_Discussion_Thread');
        $writer->bulkSet(array(
            'user_id' => $user->data['user_id'],
            'username' => $user->data['username'],
            'title' => $input['title'],
            'prefix_id' => $input['prefix_id'],
            'node_id' => $thread_data['node_id']
        ));

        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));

        // discussion state changes instead of first message state
        $writer->set('discussion_state', $this->getModels()->getModel('post')->getPostInsertMessageState(array(), $forum));

        $this->getModels()->checkModel('forum', XenForo_Model::create('XenForo_Model_Forum'));

        // discussion open state - moderator permission required
        if (!empty($thread_data['discussion_open']) && $this->getModels()->getModel('forum')->canLockUnlockThreadInForum($forum, $null, $permissions, $user->getData())) {
            $writer->set('discussion_open', $thread_data['discussion_open']);
        }

        // discussion sticky state - moderator permission required
        if (!empty($thread_data['sticky']) && $this->getModels()->getModel('forum')->canStickUnstickThreadInForum($forum, $null, $permissions, $user->getData())) {
            $writer->set('sticky', $thread_data['sticky']);
        }

        $postWriter = $writer->getFirstMessageDw();
        $postWriter->set('message', $input['message']);
        $postWriter->setExtraData(XenForo_DataWriter_DiscussionMessage_Post::DATA_FORUM, $forum);

        $writer->setExtraData(XenForo_DataWriter_Discussion_Thread::DATA_FORUM, $forum);

        $writer->preSave();

        if ($writer->hasErrors()) {
            // The thread creation failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        $writer->save();

        $thread = $writer->getMergedData();

        $this->getModels()->checkModel('thread_watch', XenForo_Model::create('XenForo_Model_ThreadWatch'));
        $this->getModels()->getModel('thread_watch')->setThreadWatchStateWithUserDefault($user->data['user_id'], $thread['thread_id'], $user->data['default_watch_state']);

        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        $this->getModels()->getModel('thread')->markThreadRead($thread, $forum, XenForo_Application::$time, $user->getData());

        return $thread;
    }

    public function deletePost($post_id, $reason = NULL, $hard_delete = FALSE, $user = NULL) { 
        if ($hard_delete) {
            $delete_type = 'hard';
        } else {
            $delete_type = 'soft';
        }
        if ($reason != NULL) {
            $options = array('reason' => $reason);
        } else {
            $options = array();
        }

        $post = $this->getPost($post_id);
        if ($user != NULL) {
            $fetchOptions = array('permissionCombinationId' => $user->data['permission_combination_id']);
            $thread = $this->getThread($post['thread_id'], $fetchOptions);
            $forum = $this->getForum($thread['node_id'], $fetchOptions);
            $permissions = XenForo_Permission::unserializePermissions($forum['node_permission_cache']);
        } else {
            $thread = $this->getThread($post['thread_id']);
            $forum = $this->getForum($thread['node_id']);  
        }

        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));

        if ($user != NULL && (!$this->canViewThread($user, $thread, $permissions) || !$this->getModels()->getModel('post')->canDeletePost($post, $thread, $forum, $delete_type, $null, $permissions, $user->getData()))) {
            // User does not have permission to delete this post.
            return array('error' => 14, 'errors' => 'The user does not have permissions to delete this post.');
        }

        $this->getModels()->getModel('post')->deletePost($post_id, $delete_type, $options, $forum);

        if ($delete_type == 'hard') {
            $post['message_state'] = 'hard_deleted';
        } else {
            $post['message_state'] = 'deleted';
        }

        return $post;
    }

    public function editUser($user, $edit_data = array()) {
        if (!$user) {
            return array('error' => 3, 'errors' => 'The user array key was not set.');
        }
        if (!$user->isRegistered()) {
            return array('error' => 4, 'errors' => 'User is not registered.');
        }
        if (empty($user->data['dob_day'])) {
            // We need the full profile of the user, let's re-grab the user and get the full profile.
            $user = $this->getUser($user->getID(), array('join' => XenForo_Model_User::FETCH_USER_FULL));
        }
        $this->getModels()->checkModel('user', XenForo_Model::create('XenForo_Model_User'));
        // Check if user is super admin.
        if ($this->getModels()->getModel('user')->isUserSuperAdmin($user->data)) {
            // User is super admin, we do not allow editing super admins, return error.
            return array('error' => 6, 'errors' => 'Editing super admins is disabled.');
        }

        if (!empty($edit_data['password'])) {
            // Create a new variable for the password.
            $password = $edit_data['password'];

            // Unset the password from the user data array.
            unset($edit_data['password']);
        }

        // Init the diff array.
        $diff_array = array();

        // Create the data writer object for registrations, and set the defaults.
        $writer = XenForo_DataWriter::create('XenForo_DataWriter_User');

        // Set the existing data of the user before we submit the data.
        $writer->setExistingData($user->data);

        // Let the writer know that the edit is legit and made by an administrator.
        $writer->setOption(XenForo_DataWriter_User::OPTION_ADMIN_EDIT, TRUE);

        if (!empty($edit_data['group_id'])) {
            // Group ID is set.
            $writer->set('user_group_id', $edit_data['group_id']);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($edit_data['group_id']);
        }

        if (!empty($edit_data['remove_group_id'])) {
            // Group ID is set.
            #$writer->set('user_group_id', $edit_data['group_id']);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($edit_data['remove_group_id']);
        }
        if (!empty($edit_data['add_groups'])) {
            // Add group is set.

            // Check if there are any custom fields in the data array.
            if (!is_array($edit_data['add_groups']) || count($edit_data['add_groups']) == 0) {
                // The edit failed, return errors.
                return array('error' => 7, 'errors' => 'The add_groups parameter needs to be an array and have at least 1 item.');
            }

            // Initialize some arrays.
            $groups = array();
            $groups_exist = array();

            // Check if there are more than one custom array.
            if (strpos($user->data['secondary_group_ids'], ',') !== FALSE) {
                // Value is an array, explode it.
                $groups = explode(',', $user->data['secondary_group_ids']);
            } else {
                // Value is not an array, just add the single group  to the array.
                $groups[] = $user->data['secondary_group_ids'];
            }

            // Loop through the groups that are going to be added to check if the user already have the groups.
            foreach ($edit_data['add_groups'] as $group_id) {
                // Check if the user already is in the group.
                if (in_array($group_id, $groups)) {
                    // User is already in the group, add the group ID to the group_exist array.
                    $groups_exist[] = $group_id;
                } else {
                    // User is not in the group, add the group ID to the new_groups array.
                    $groups[] = $group_id;
                    $diff_array['new_secondary_groups'][] = $group_id;
                }
            }

            // Check if the user is in one or more of the specified groups.
            if (count($groups_exist) > 0) {
                // The user was already in one or more groups, return error.
                return array('error' => 8, 'errors' => 'The user is already a member of the group ID\'s: (' . implode(',', $groups_exist) . ')');
            }

            // Set the secondary group(s) of the user.
            $writer->setSecondaryGroups($groups);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($edit_data['add_groups']);
        }

        if (!empty($edit_data['remove_groups'])) {
            // Remove group is set.

            // Check if there are any custom fields in the data array.
            if (!is_array($edit_data['remove_groups']) || count($edit_data['remove_groups']) == 0) {
                // The edit failed, return errors.
                return array('error' => 11, 'errors' => 'The remove_groups parameter needs to be an array and have at least 1 item.');
            }

            // Initialize some arrays.
            $groups = array();
            $groups_not_exist = array();

            // Check if there are more than one custom array.
            if (strpos($user->data['secondary_group_ids'], ',') !== FALSE) {
                // Value is an array, explode it.
                $groups = explode(',', $user->data['secondary_group_ids']);
            } else {
                // Value is not an array, just add the single group to the array.
                $groups[] = $user->data['secondary_group_ids'];
            }

            // Loop through the groups that are going to be added to check if the user already have the groups.
            foreach ($edit_data['remove_groups'] as $group_key => $group_id) {
                // Check if the user already is in the group.
                if (!in_array($group_id, $groups) && $user->data['user_group_id'] != $group_id) {
                    // User is already in the group, add the group ID to the group_exist array.
                    $groups_not_exist[] = $group_id;
                } else {
                    // Check if user's primary group is the group ID.
                    if (!empty($user->data['user_group_id']) && $user->data['user_group_id'] == $group_id) {
                        // User's primary group ID was found in the remove_groups array, move the user to the default registration group.
                        $writer->set('user_group_id', XenForo_Model_User::$defaultRegisteredGroupId);
                         $diff_array['removed_group'] = $group_id;
                    } else {
                        // User is in the group, add the group ID to the remove_groups array.
                        $diff_array['removed_secondary_groups'][] = $group_id;
                    }
                    // Unset the group id.
                    unset($groups[$group_key]);
                }
            }

            // Check if the user is in one or more of the specified groups.
            if (count($groups_not_exist) > 0) {
                // The user was already in one or more groups, return error.
                return array('error' => 12, 'errors' => 'The user is not a member of group ID\'s: (' . implode(',', $groups_not_exist) . ')');
            }

            // Set the secondary group(s) of the user.
            $writer->setSecondaryGroups($groups);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($edit_data['remove_groups']);
        }

        if (!empty($edit_data['secondary_group_ids'])) {
            // Secondary group ID's are set.
            $writer->setSecondaryGroups(unserialize($edit_data['secondary_group_ids']));

            // We need to unset the secondary group id's as we don't want it to be included into the bulk set.
            unset($edit_data['secondary_group_ids']);
        }

        if (!empty($edit_data['custom_fields'])) {
            // Custom fields are set.

            // Check if there are any custom fields in the data array.
            if (count($edit_data['custom_fields']) > 0) {
                // There were one or more custom fields set, set them in the writer.
                $writer->setCustomFields($edit_data['custom_fields']);
            }
            // We need to unset the custom fields as we don't want it to be included into the bulk set.
            unset($edit_data['custom_fields']);
        }

        // Bulkset the edited data.
        $writer->bulkSet($edit_data);

        if (isset($password)) {
            // Set the password for the data writer.
            $writer->setPassword($password, $password);
        }

        // Set the data for the data writer.
        $writer->bulkSet($edit_data);

        // Pre save the data.
        $writer->preSave();

        if ($writer->hasErrors()) {
            // The edit failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        // Save the user to the database.
        $writer->save();
         
        // Get the user data.
        $user_data = $writer->getMergedData();

        // Check the difference between the before and after data.
        $diff_array = array_merge(array_diff($user->data, $user_data), $diff_array);

        foreach ($diff_array as $diff_key => $diff_value) {
            if (isset($user_data[$diff_key])) {
                $diff_array[$diff_key] = $user_data[$diff_key];
            }
        }

        if (isset($diff_array['secondary_group_ids'])) {
            unset($diff_array['secondary_group_ids']);
        }

        if (!empty($diff_array['custom_fields'])) {
            // Check the difference in the custom fields.
            $custom_fields_diff_array = array_diff(unserialize($user->data['custom_fields']), unserialize($diff_array['custom_fields']));

            unset($diff_array['custom_fields']);

            // Loop through the differences and add them to the diff array.
            foreach ($custom_fields_diff_array as $custom_fields_diff_key => $custom_fields_diff_value) {
                $diff_array['custom_fields'][$custom_fields_diff_key] = $custom_fields_diff_value;
            }
        }

        if (isset($password)) {
            // Password is changed, make sure we add it to the difference array.
            $diff_array['password'] = 'OK';
        }

        if (count($diff_array) == 0) {
            // Nothing was changed, throw error.
            return array('error' => 9, 'errors' => 'No values were changed.');
        }

        return $diff_array;
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
    * Returns all the conversations of the user.
    */
    public function getConversations($user, $conditions = array(), $fetchOptions = array()) {
        $this->getModels()->checkModel('conversation', XenForo_Model::create('XenForo_Model_Conversation'));
        return $this->getModels()->getModel('conversation')->getConversationsForUser($user->getID(), $conditions, $fetchOptions);
    }

    public function getConversation($conversation, $user, $fetchOptions = array()) {
        $this->getModels()->checkModel('conversation', XenForo_Model::create('XenForo_Model_Conversation'));
        return $this->getModels()->getModel('conversation')->getConversationForUser($conversation, $user->getData(), $fetchOptions);
    }

    public function getGroup($group) {
        // Get the group from the database.
        return $this->getDatabase()->fetchRow("SELECT * FROM `xf_user_group` WHERE `user_group_id` = '$group' OR `title` = '$group' OR `user_title` = '$group'");
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
            case 'conversations':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_conversation_master');
            case 'conversations_messages':
                return $this->getModels()->getModel('database')->fetchOne('SELECT COUNT(*) FROM xf_conversation_message');
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
    public function checkUserPermissions(&$user, array $fetchOptions = array()) {
        if ($user != NULL) {
            $this->getModels()->checkModel('user', XenForo_Model::create('XenForo_Model_User'));

            if (!is_array($user) && !($user instanceof User)) {
                $user = $this->getUser($user, array_merge($fetchOptions, array('join' => XenForo_Model_User::FETCH_USER_PERMISSIONS)));
                if (empty($user->data['permissions'])) {
                    // Check if the user data has the permissions set, set it if not.
                    $user->data['permissions'] = XenForo_Permission::unserializePermissions($user->data['global_permission_cache']);
                    // Unset the permissions serialized cache as we don't need it anymore.
                    unset($user->data['global_permission_cache']);
                }
            } else {
                if (empty($user->data['global_permission_cache'])) {
                    // Check if the user data has permissions cache set, grab it if not.
                    $user = $this->getUser($user->getID(), array_merge($fetchOptions, array('join' => XenForo_Model_User::FETCH_USER_PERMISSIONS)));
                }

                if (empty($user->data['permissions'])) {
                    // Check if the user data has the permissions set, set it if not.
                    $user->data['permissions'] = XenForo_Permission::unserializePermissions($user->data['global_permission_cache']);
                    // Unset the permissions serialized cache as we don't need it anymore.
                    unset($user->data['global_permission_cache']);
                }
            }
        }
    }

    /**
    * TODO
    */
    public function getUsersOnlineCount($user = NULL) {
        $this->getModels()->checkModel('session', XenForo_Model::create('XenForo_Model_Session'));
        if ($user != NULL) {
            // User parameter is not null, make sure to follow privacy of the users.
            $this->getModels()->checkModel('user', XenForo_Model::create('XenForo_Model_User'));

            // Check user permissions.
            $this->checkUserPermissions($user);

            // Check if the user can bypass user privacy.
            $bypass = $this->getModels()->getModel('user')->canBypassUserPrivacy($null, $user->getData());
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
    * Returns the Node array of the $node_id parameter.
    */
    public function getForum($node_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('forum', XenForo_Model::create('XenForo_Model_Forum'));
        return $this->getModels()->getModel('forum')->getForumById($node_id, $fetchOptions);
    }

    /**
    * Returns the Link Forum array of the $node_id parameter.
    */
    public function getLinkForum($node_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('link_forum', XenForo_Model::create('XenForo_Model_LinkForum'));
        return $this->getModels()->getModel('link_forum')->getLinkForumById($node_id, $fetchOptions);
    }


    /**
    * Returns the Node array of the $node_id parameter.
    */
    public function getNode($node_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('node', XenForo_Model::create('XenForo_Model_Node'));
        $node = $this->getModels()->getModel('node')->getNodeById($node_id, $fetchOptions);
        if (!empty($node['node_type_id'])) {
            switch (strtolower($node['node_type_id'])) {
                case 'forum':
                    return $this->getForum($node['node_id'], $fetchOptions);
                case 'linkforum':
                    return $this->getLinkForum($node['node_id'], $fetchOptions);
                case 'page':
                    return $this->getPage($node['node_id'], $fetchOptions);
                case 'category':
                default:
                    return $node;
            }
        }
        return $node;
    }

    /**
    * Returns a list of nodes.
    */
    public function getNodes($node_type = 'all', $fetchOptions = array('limit' => 10), $user = NULL) {
        $this->getModels()->checkModel('node', XenForo_Model::create('XenForo_Model_Node'));

        // Get the node list.
        $node_list = $this->getModels()->getModel('node')->getAllNodes();

        // Check if the node type that is set exists.
        if ($node_type == NULL || !in_array($node_type, $this->getNodeTypes())) {
            $node_type = 'all';
        }
        
        // Loop through the nodes to check if the user has permissions to view the thread.
        foreach ($node_list as $key => &$node) {      
            if ($node_type != 'all' && strtolower($node['node_type_id']) != $node_type) {
                // Node type does not equal the requested node type, unset the node and continue the loop.
                unset($node_list[$key]);
                continue;
            }

            // Check if user is set.
            if ($user != NULL) {
                // Get the node.
                $node = $this->getNode($node['node_id'], array_merge($fetchOptions, array('permissionCombinationId' => $user->data['permission_combination_id'])));
                $permissions = XenForo_Permission::unserializePermissions($node['node_permission_cache']);

                // User does not have permission to view this nodes, unset it and continue the loop.
                if (!$this->canViewNode($user, $node, $permissions)) {
                    unset($node_list[$key]);
                    continue;
                }

                // Unset the permissions values.
                unset($node_list[$key]['node_permission_cache']);
            } else {
                // Get the node.
                $node = $this->getNode($node['node_id'], $fetchOptions);
            }
        }
        return $node_list;
    }

    public function getDebugData() {
        $database_debug = XenForo_Debug::getDatabaseDebugInfo($this->getModels()->getModel('database'));
        unset($database_debug['queryHtml']);
        $included_files_debug = XenForo_Debug::getIncludedFilesDebugInfo(get_included_files());
        unset($included_files_debug['includedFileHtml']);
        return array(
            'time'     => microtime(TRUE) - XenForo_Application::get('page_start_time'),
            'database' => $database_debug,
            'memory'   => array(
                'usage' => memory_get_usage(),
                'peak'  => memory_get_peak_usage()
            ),
            'included_files' => $included_files_debug
        );
    }

    /**
    * TODO
    */
    public function getNodeTypes() {
        $this->getModels()->checkModel('node', XenForo_Model::create('XenForo_Model_Node'));
        return array_keys(array_change_key_case($this->getModels()->getModel('node')->getAllNodeTypes(), CASE_LOWER));
    }

    /**
    * Returns the Page array of the $node_id parameter.
    */
    public function getPage($node_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('page', XenForo_Model::create('XenForo_Model_Page'));
        return $this->getModels()->getModel('page')->getPageById($node_id, $fetchOptions);
    }

    /**
    * TODO
    */
    public function canViewNode($user, $node, $permissions = NULL) {
        // Check if the forum model has initialized.
        if (!empty($node['node_type_id'])) {
            if ($permissions == NULL) {
                // Let's grab the permissions.
                $node = $this->getNode($node['node_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));

                // Unserialize the permissions.
                $permissions = XenForo_Permission::unserializePermissions($node['node_permission_cache']);
            }
            switch (strtolower($node['node_type_id'])) {
                case 'category':
                    $this->getModels()->checkModel('category', XenForo_Model::create('XenForo_Model_Category'));
                    return $this->getModels()->getModel('category')->canViewCategory($node, $null, $permissions, $user->getData());
                case 'forum':
                    $this->getModels()->checkModel('forum', XenForo_Model::create('XenForo_Model_Forum'));
                    return $this->getModels()->getModel('forum')->canViewForum($node, $null, $permissions, $user->getData());
                case 'linkforum':
                    $this->getModels()->checkModel('link_forum', XenForo_Model::create('XenForo_Model_LinkForum'));
                    return $this->getModels()->getModel('link_forum')->canViewLinkForum($node, $null, $permissions, $user->getData());
                case 'page':
                    $this->getModels()->checkModel('page', XenForo_Model::create('XenForo_Model_Page'));
                    return $this->getModels()->getModel('page')->canViewPage($node, $null, $permissions, $user->getData());
            }
        }
        return FALSE;
    }

    /**
    * Returns the Post array of the $post_id parameter.
    */
    public function getPost($post_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));
        $post = $this->getModels()->getModel('post')->getPostById($post_id, $fetchOptions);
        if (!empty($fetchOptions['join'])) {
            // Unset the thread values.
            Post::stripThreadValues($post);
        }
        return $post;
    }

    /**
    * Returns a list of posts.
    */
    public function getPosts($conditions = array(), $fetchOptions = array('limit' => 10), $user = NULL) {
        if (!empty($conditions['node_id']) || (!empty($fetchOptions['order']) && strtolower($fetchOptions['order']) == 'node_id')) {
            // We need to grab the thread info to get the node_id.
            $fetchOptions = array_merge($fetchOptions, array('join' => XenForo_Model_Post::FETCH_THREAD));
        }
        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));
        if ($user != NULL) {
            // User is set, we need to include permissions.
            if (!isset($fetchOptions['join'])) {
                // WE need to grab the thread to get the node permissions.
                $fetchOptions = array_merge($fetchOptions, array('join' => XenForo_Model_Post::FETCH_THREAD));
            }
            // User is set, we therefore have to grab the permissions to check if the user is allowed to view the post.
            $fetchOptions = array_merge($fetchOptions, array('permissionCombinationId' => $user->data['permission_combination_id']));
        }
        // Prepare query conditions.
        $whereConditions = Post::preparePostConditions($this->getModels()->getModel('database'), $this->getModels()->getModel('post'), $conditions);
        $sqlClauses = $this->getModels()->getModel('post')->preparePostJoinOptions($fetchOptions);
        $limitOptions = $this->getModels()->getModel('post')->prepareLimitFetchOptions($fetchOptions);

        // Since the Post model of XenForo does not have order by implemented, we have to do it ourselves.
        if (!empty($fetchOptions['order'])) {
            $orderBySecondary = '';
            switch ($fetchOptions['order']) {
                case 'post_id':
                case 'thread_id':
                case 'user_id':
                case 'username':
                case 'attach_count':
                case 'likes':
                    $orderBy = 'post.' . $fetchOptions['order'];
                    break;
                case 'node_id':
                    $orderBy = 'thread.' . $fetchOptions['order'];
                    break;
                case 'post_date':
                default:
                    $orderBy = 'post.post_date';
            }
            // Check if order direction is set.
            if (!isset($fetchOptions['orderDirection']) || $fetchOptions['orderDirection'] == 'desc') {
                $orderBy .= ' DESC';
            } else {
                $orderBy .= ' ASC';
            }
            $orderBy .= $orderBySecondary;
        }
        $sqlClauses['orderClause'] = (isset($orderBy) ? "ORDER BY $orderBy" : '');

        // Execute the query and get the result.
        $post_list = $this->getModels()->getModel('post')->fetchAllKeyed($this->getModels()->getModel('post')->limitQueryResults(
            '
                SELECT post.*
                    ' . $sqlClauses['selectFields'] . '
                FROM xf_post AS post ' . $sqlClauses['joinTables'] . '
                WHERE ' . $whereConditions . '
                ' . $sqlClauses['orderClause'] . '
            ', $limitOptions['limit'], $limitOptions['offset']
        ), 'post_id');

        if ($user != NULL || isset($fetchOptions['join'])) {
            // Loop through the posts to unset some values that are not needed.
            foreach ($post_list as $key => $post) {
                if ($user != NULL) {
                    // Check if the user has permissions to view the post.
                    $permissions = XenForo_Permission::unserializePermissions($post['node_permission_cache']);
                    if (!$this->getModels()->getModel('post')->canViewPost($post, array('node_id' => $post['node_id']), array(), $null, $permissions, $user->getData())) {
                        // User does not have permission to view this post, unset it and continue the loop.
                        unset($post_list[$key]);
                        continue;
                    }
                    // Unset the permissions values.
                    unset($post_list[$key]['node_permission_cache']);
                }

                if (isset($fetchOptions['join'])) {
                    // Unset some not needed thread values.
                    Post::stripThreadValues($post_list[$key]);
                }
            }
        }
        return array_values($post_list);
    }

    /**
    * Check if user has permissions to view post.
    */
    public function canViewPost($user, $post, $permissions = NULL) {
        // Check if the post model has initialized.
        $this->getModels()->checkModel('post', XenForo_Model::create('XenForo_Model_Post'));
        if ($permissions == NULL) {
            // Let's grab the permissions.
            $post = $this->getPost($post['post_id'], array(
                'permissionCombinationId' => $user->data['permission_combination_id'],
                'join' => XenForo_Model_Post::FETCH_FORUM
            ));

            // Unserialize the permissions.
            $permissions = XenForo_Permission::unserializePermissions($post['node_permission_cache']);
        }
        return $this->getModels()->getModel('post')->canViewPost($post, array('node_id' => $post['node_id']), array(), $null, $permissions, $user->getData());
    }

    public function canPostThreadInForum($user, $forum, $permissions = NULL) {
        // Does not take in count of private nodes.
        if (!empty($forum['node_type_id'])) {
            if ($permissions == NULL) {
                // Let's grab the permissions.
                $forum = $this->getForum($forum['node_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));

                // Unserialize the permissions.
                $permissions = XenForo_Permission::unserializePermissions($forum['node_permission_cache']);
            }
            $this->getModels()->checkModel('forum', XenForo_Model::create('XenForo_Model_Forum'));
            return $this->getModels()->getModel('forum')->canPostThreadInForum($forum, $null, $permissions, $user->getData());
        }
        return FALSE;
    }

    public function canReplyToThread($user, $thread, $forum, $permissions = NULL) {
        // Check if the thread model has initialized.
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        if ($permissions == NULL) {
            // Let's grab the permissions.
            $thread = $this->getThread($thread['thread_id'], array('permissionCombinationId' => $user->data['permission_combination_id']));

            // Unserialize the permissions.
            $permissions = XenForo_Permission::unserializePermissions($thread['node_permission_cache']);
        }
        return $this->getModels()->getModel('thread')->canReplyToThread($thread, $forum, $null, $permissions, $user->getData());
    }

    /**
    * Returns the Post array of the $post_id parameter.
    */
    public function getProfilePost($profile_post_id, $fetchOptions = array()) {
        $this->getModels()->checkModel('profile_post', XenForo_Model::create('XenForo_Model_ProfilePost'));
        return $this->getModels()->getModel('profile_post')->getProfilePostById($profile_post_id, $fetchOptions);
    }

    /**
    * Returns a list of profile posts.
    */
    public function getProfilePosts($conditions = array(), $fetchOptions = array('limit' => 10), $user = NULL) {
        $this->getModels()->checkModel('profile_post', XenForo_Model::create('XenForo_Model_ProfilePost'));
        if ($user != NULL) {
            // User is set, we need to include permissions.
            $this->checkUserPermissions($user);
        }

        // Default the sql condition.
        $sqlConditions = array();

        if (count($conditions) > 0) {
            // We need to make our own check for these conditions as XenForo's functions doesn't fully support what we want.

            // Check if the author id is set.
            if (!empty($conditions['author_id'])) {
                $sqlConditions[] = "profile_post.user_id = " . $this->getModels()->getModel('database')->quote($conditions['author_id']);
            }

            // Check if the profile id is set.
            if (!empty($conditions['profile_id'])) {
                $sqlConditions[] = "profile_post.profile_user_id = " . $this->getModels()->getModel('database')->quote($conditions['profile_id']);
            }
        }

        // Use the model function to get conditions for clause from the sql conditions.
        $whereConditions = $this->getModels()->getModel('profile_post')->getConditionsForClause($sqlConditions);

        // Prepare query conditions.
        $sqlClauses = $this->getModels()->getModel('profile_post')->prepareProfilePostFetchOptions($fetchOptions);
        $limitOptions = $this->getModels()->getModel('profile_post')->prepareLimitFetchOptions($fetchOptions);

        // Since the profile post model of XenForo does not have order by implemented, we have to do it ourselves.
        if (!empty($fetchOptions['order'])) {
            $orderBySecondary = '';
            switch ($fetchOptions['order']) {
                case 'profile_post_id':
                case 'profile_user_id':
                case 'user_id':
                case 'username':
                case 'attach_count':
                case 'likes':
                case 'comment_count':
                case 'first_comment_date':
                case 'last_comment_date':
                    $orderBy = 'profile_post.' . $fetchOptions['order'];
                    break;
                case 'post_date':
                default:
                    $orderBy = 'profile_post.post_date';
            }
            // Check if order direction is set.
            if (!isset($fetchOptions['orderDirection']) || $fetchOptions['orderDirection'] == 'desc') {
                $orderBy .= ' DESC';
            } else {
                $orderBy .= ' ASC';
            }
            $orderBy .= $orderBySecondary;
        }
        $sqlClauses['orderClause'] = (isset($orderBy) ? "ORDER BY $orderBy" : '');

        // Execute the query and get the result.
        $profile_post_list = $this->getModels()->getModel('profile_post')->fetchAllKeyed($this->getModels()->getModel('profile_post')->limitQueryResults(
            '
                SELECT profile_post.*
                    ' . $sqlClauses['selectFields'] . '
                FROM xf_profile_post AS profile_post ' . $sqlClauses['joinTables'] . '
                WHERE ' . $whereConditions . '
                ' . $sqlClauses['orderClause'] . '
            ', $limitOptions['limit'], $limitOptions['offset']
        ), 'profile_post_id');

        if ($user != NULL) {
            // Loop through the profile posts to check permissions
            foreach ($profile_post_list as $key => $profile_post) {
                // Check if the user has permissions to view the profile post.
                if (!$this->getModels()->getModel('profile_post')->canViewProfilePost($profile_post, array(), $null, $user->getData())) {
                    // User does not have permission to view this profile post, unset it and continue the loop.
                    unset($profile_post_list[$key]);
                }
            }
        }

        // Return the profile post list.
        return array_values($profile_post_list);
    }

    /**
    * Check if user has permissions to view post.
    */
    public function canViewProfilePost($user, $profile_post, $permissions = NULL) {
        // Check if the profile post model has initialized.
        $this->getModels()->checkModel('profile_post', XenForo_Model::create('XenForo_Model_ProfilePost'));

        // Check if the user object has the permissions data.
        $this->checkUserPermissions($user);

        // Return if the user has permissions to view the profile post.
        return $user != NULL && $this->getModels()->getModel('profile_post')->canViewProfilePost($profile_post, array(), $null, $user->getData());
    }



    /**
    * Returns the Thread array of the $thread_id parameter.
    */
    public function getThread($thread_id, array $fetchOptions = array(), $user = NULL) {
        if (isset($fetchOptions['grab_content'])) {
            $grab_content = TRUE;
            unset($fetchOptions['grab_content']);
        }
        if (isset($fetchOptions['content_limit'])) {
            $content_limit = $fetchOptions['content_limit'];
            unset($fetchOptions['content_limit']);
        } else {
            $content_limit = 1;
        }
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        $thread = $this->getModels()->getModel('thread')->getThreadById($thread_id, $fetchOptions);
        if (!$thread) {
            return $thread;
        }
        if (isset($grab_content)) {
            $posts = $this->getPosts(array('thread_id' => $thread_id), array('limit' => $content_limit), $user);
            $thread['content'] = array('count' => count($posts), 'content' => $posts);
            unset($posts);
        }
        return $thread;
    }

    /**
    * Returns a list of threads.
    */
    public function getThreads($conditions = array(), $fetchOptions = array('limit' => 10), $user = NULL) {
        $this->getModels()->checkModel('thread', XenForo_Model::create('XenForo_Model_Thread'));
        if (isset($fetchOptions['grab_content'])) {
            $grab_content = TRUE;
            unset($fetchOptions['grab_content']);
        }
        if (isset($fetchOptions['content_limit'])) {
            $content_limit = $fetchOptions['content_limit'];
            unset($fetchOptions['content_limit']);
        } else {
            $content_limit = 1;
        }
        if ($user == NULL && !isset($grab_content)) {
            $thread_list = $this->getModels()->getModel('thread')->getThreads($conditions, $fetchOptions);
            return $thread_list;
        } else if ($user != NULL) {
            $thread_list = $this->getModels()->getModel('thread')->getThreads($conditions, array_merge($fetchOptions, array('permissionCombinationId' => $user->data['permission_combination_id'])));
        } else {
            $thread_list = $this->getModels()->getModel('thread')->getThreads($conditions, $fetchOptions);
        }
        if ($user != NULL || isset($grab_content)) {
            // Loop through the threads to check if the user has permissions to view the thread.
            foreach ($thread_list as $key => &$thread) {
                if ($user != NULL) {
                    $permissions = XenForo_Permission::unserializePermissions($thread['node_permission_cache']);
                    if (!$this->getModels()->getModel('thread')->canViewThread($thread, array(), $null, $permissions, $user->getData())) {
                        // User does not have permission to view this thread, unset it and continue the loop.
                        unset($thread_list[$key]);
                    }
                    // Unset the permissions values.
                    unset($thread_list[$key]['node_permission_cache']);
                }
                if (isset($grab_content)) {
                    $posts = $this->getPosts(array('thread_id' => $thread['thread_id']), array('limit' => $content_limit), $user);
                    $thread['content'] = array('count' => count($posts), 'content' => $posts);
                    unset($posts);
                }
            }
        }
        return array_values($thread_list);
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
        return $this->getModels()->getModel('thread')->canViewThread($thread, array(), $null, $permissions, $user->getData());
    }
    
    /**
    * Returns the User class of the $input parameter.
    *
    * The $input parameter can be an user ID, username or e-mail.
    * Returns FALSE if $input is NULL.
    */
    public function getUser($input, $fetchOptions = array()) {
        if (!empty($fetchOptions['custom_field'])) {
            $results = $this->getDatabase()->fetchRow("SELECT `user_id` FROM `xf_user_field_value` WHERE `field_id` = '" . $fetchOptions['custom_field'] . "' AND `field_value` = '$input'");
            if (!empty($results['user_id'])) {
                $input = $results['user_id'];
            }
        }
        if ($input == FALSE || $input == NULL) {
            return FALSE;
        } else if (is_numeric($input)) {
            // $input is a number, grab the user by an ID.
            $user = new User($this->models, $this->models->getUserModel()->getUserById($input, $fetchOptions));
            if (!$user->isRegistered()) {
                // The user ID was not found, grabbing the user by the username instead.
                return new User($this->models, $this->models->getUserModel()->getUserByName($input, $fetchOptions));
            }
            return $user;
        } else if ($this->models->getUserModel()->couldBeEmail($input)) {
            // $input is an e-mail, return the user of the e-mail.
            return new User($this->models, $this->models->getUserModel()->getUserByEmail($input, $fetchOptions));
        } else {
            // $input is an username, return the user of the username.
            return new User($this->models, $this->models->getUserModel()->getUserByName($input, $fetchOptions));
        }
    }

    /**
    * TODO
    */
    public function register($user_data) {
        if (empty($user_data['username'])) {
            // Username was empty, return error.
            return array('error' => 10, 'errors' => 'Missing required parameter: username');
        } else if (empty($user_data['password'])) {
            // Password was empty, return error.
            return array('error' => 10, 'errors' => 'Missing required parameter: password');
        } else if (empty($user_data['email'])) {
            // Email was empty, return error.
            return array('error' => 10, 'errors' => 'Missing required parameter: email');
        }

        // Create a new variable for the password.
        $password = $user_data['password'];

        // Unset the password from the user data array.
        unset($user_data['password']);

        if (!empty($user_data['ip_address'])) {
            // Create a new variable for the ip address.
            $ip_address = $user_data['ip_address'];

            // Unset the ip address from the user data array.
            unset($user_data['ip_address']);
        }

        // Get the default options from XenForo.
        $options = XenForo_Application::get('options');

        // Create the data writer object for registrations, and set the defaults.
        $writer = XenForo_DataWriter::create('XenForo_DataWriter_User');
        if ($options->registrationDefaults) {
            // Set the default registration options if it's set in the XenForo options.
            $writer->bulkSet($options->registrationDefaults, array('ignoreInvalidFields' => TRUE));
        }

        if (!empty($user_data['group_id'])) {
            // Group ID is set.
            $writer->set('user_group_id', $user_data['group_id']);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($user_data['group_id']);
        } else {
            // Group ID is not set, default back to default.
            $writer->set('user_group_id', XenForo_Model_User::$defaultRegisteredGroupId);
        }

        if (!empty($user_data['user_state'])) {
            // User state is set.
            $writer->set('user_state', $user_data['user_state']);
        } else {
            // User state is not set, default back to default.
            $writer->advanceRegistrationUserState();
        }

        if (!empty($user_data['language_id'])) {
            // Language ID is set.
            $writer->set('language_id', $user_data['language_id']);
        } else {
            // Language ID is not set, default back to default.
            $writer->set('language_id', $options->defaultLanguageId);
        }

        if (!empty($user_data['custom_fields'])) {
            // Custom fields are set.

            // Check if there are any custom fields in the data array.
            if (count($user_data['custom_fields']) > 0) {
                // There were one or more custom fields set, set them in the writer.
                $writer->setCustomFields($user_data['custom_fields']);
            }
            // We need to unset the custom fields as we don't want it to be included into the bulk set.
            unset($user_data['custom_fields']);
        }

        if (!empty($user_data['add_groups'])) {
            // Add group is set.

            // Check if there are any custom fields in the data array.
            if (!is_array($user_data['add_groups']) || count($user_data['add_groups']) == 0) {
                // The edit failed, return errors.
                return array('error' => 7, 'errors' => 'The add_groups parameter needs to be an array and have at least 1 item.');
            }

            // Set the secondary group(s) of the user.
            $writer->setSecondaryGroups($user_data['add_groups']);

            // We need to unset the group id as we don't want it to be included into the bulk set.
            unset($user_data['add_groups']);
        }

        // Check if Gravatar is enabled, set the gravatar if it is and there's a gravatar for the email.
        if ($options->gravatarEnable && XenForo_Model_Avatar::gravatarExists($data['email'])) {
            $writer->set('gravatar', $user_data['email']);
        }

        // Set the data for the data writer.
        $writer->bulkSet($user_data);

        // Set the password for the data writer.
        $writer->setPassword($password, $password);

        // Pre save the data.
        $writer->preSave();

        if ($writer->hasErrors()) {
            // The registration failed, return errors.
            return array('error' => TRUE, 'errors' => $writer->getErrors());
        }

        // Save the user to the database.
        $writer->save();
         
        // Get the User as a variable:
        $user = $writer->getMergedData();

        // Check if IP is set.
        if (!empty($user_data['ip_address'])) {
            // Log the IP of the user that registered.
            XenForo_Model_Ip::log($user['user_id'], 'user', $user['user_id'], 'register', $ip_address);
        }
         
        return $user;
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

class Post {
    public static function stripThreadValues(&$post) {
        unset($post['reply_count']);
        unset($post['view_count']);
        unset($post['sticky']);
        unset($post['discussion_state']);
        unset($post['discussion_open']);
        unset($post['discussion_type']);
        unset($post['first_post_id']);
        unset($post['first_post_likes']);
        unset($post['last_post_date']);
        unset($post['last_post_id']);
        unset($post['last_post_user_id']);
        unset($post['last_post_username']);
        unset($post['prefix_id']);
        unset($post['thread_user_id']);
        unset($post['thread_username']);
        unset($post['thread_post_date']);
    }
    public static function preparePostConditions($db, $model, array $conditions) {
        $sqlConditions = array();

        if (!empty($conditions['forum_id']) && empty($conditions['node_id'])) {
            $conditions['node_id'] = $conditions['forum_id'];
        }

        if (!empty($conditions['node_id'])) {
            if (is_array($conditions['node_id'])) {
                $sqlConditions[] = 'thread.node_id IN (' . $db->quote($conditions['node_id']) . ')';
            } else {
                $sqlConditions[] = 'thread.node_id = ' . $db->quote($conditions['node_id']);
            }
        }

        if (!empty($conditions['thread_id'])) {
            if (is_array($conditions['thread_id'])) {
                $sqlConditions[] = 'post.thread_id IN (' . $db->quote($conditions['thread_id']) . ')';
            } else {
                $sqlConditions[] = 'post.thread_id = ' . $db->quote($conditions['thread_id']);
            }
        }

        if (!empty($conditions['prefix_id'])) {
            if (is_array($conditions['prefix_id'])) {
                $sqlConditions[] = 'thread.prefix_id IN (' . $db->quote($conditions['prefix_id']) . ')';
            } else {
                $sqlConditions[] = 'thread.prefix_id = ' . $db->quote($conditions['prefix_id']);
            }
        }

        if (!empty($conditions['post_date']) && is_array($conditions['post_date'])) {
            list($operator, $cutOff) = $conditions['post_date'];

            $model->assertValidCutOffOperator($operator);
            $sqlConditions[] = "post.post_date $operator " . $db->quote($cutOff);
        }

        // thread starter
        if (isset($conditions['user_id'])) {
            $sqlConditions[] = 'post.user_id = ' . $db->quote($conditions['user_id']);
        }

        return $model->getConditionsForClause($sqlConditions);
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
?>