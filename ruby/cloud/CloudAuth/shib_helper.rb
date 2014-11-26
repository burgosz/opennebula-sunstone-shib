# -------------------------------------------------------------------------- #
# Copyright 2002-2013, OpenNebula Project (OpenNebula.org), C12G Labs        #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #
require 'opennebula'

include OpenNebula

# Helper class to call methods in ShibCloudAuth module
class Shib_Helper

    # initalize some instance variable
    def initialize(config, logger)
        @config = config
        @logger = logger

        one_xmlrpc = @config[:one_xmlrpc]
        @session_string = @config[:one_auth_username] + ':' + @config[:one_auth_passwd]
    	@client = Client.new(@session_string, one_xmlrpc)
    end

    # creating new user
    # @param username username of user to be created
    def create_user(username)
    	@logger.debug("Creating user with name: #{username}...")
    	userobject = OpenNebula::User.new(OpenNebula::User.build_xml,@client)
    	rc = userobject.allocate(username,generate_password)
    	if OpenNebula.is_error?(rc)
    		@logger.error("Error occured while creating user: #{rc.message}")
    		return nil
    	else
    		@logger.debug("User with name: #{username} and with ID: #{userobject.id}, created.")
    		return userobject.id
    	end

    end

    # create groups if they do not exists
    # @param groupnames groupnames to be created
    def create_groups(groupnames)
        groupnames.map {|groupname| @logger.debug("Checking #{groupname} for existence...")
        if get_groupid(groupname) == nil
				@logger.debug("Looks like #{groupname} is empty, therefore creating it")
				groupobject = OpenNebula::Group.new(OpenNebula::Group.build_xml,@client)
				rc = groupobject.allocate(groupname)
				if OpenNebula.is_error?(rc)
    				@logger.error("Error occured while creating group: #{rc.message}")
    		    end
            end
        }
    end

    # get user's ID
    # @param username username
    # @return user's ID
    def get_userid(username)
	    @logger.debug("New code is running")
	    user_pool = OpenNebula::UserPool.new(@client)
	    rc = user_pool.info
	    @logger.debug("UserPool: #{user_pool} RC: #{rc}")
	    if OpenNebula.is_error?(rc)
	        @logger.error("Error occured while getting the user pool info: #{rc.message}")
	    end
	    user_pool.each do |user|
	        if user.name == username
				@logger.debug("Returning user id: #{user.id} for username: #{user.name}")
				return user.id
	        end
	    end
	    return nil
    end

    # get group ID of a group
    # @param groupname groupname
    # @return group's ID
    def get_groupid(groupname)
    	@logger.debug("Getting group id for group name: #{groupname}")
	    group_pool = OpenNebula::GroupPool.new(@client)
	    rc = group_pool.info
	    if OpenNebula.is_error?(rc)
	        @logger.error("Error occured while getting the group pool info: #{rc.message}")
	    end
	    group_pool.each do |group|
	        if group.name == groupname
				@logger.debug("Returning group id: #{group.id} for groupname: #{group.name}")
				return group.id
	        end
	    end
	    return nil
    end

    # handle user's group
    # @param userid user's ID
    # @param groupnames groupnames in which the user belongs
    def handle_groups(userid, groupnames)
    	user = OpenNebula::User.new(OpenNebula::User.build_xml(userid),@client)
    	rc = user.info
    	if OpenNebula.is_error?(rc)
    		@logger.error("Error occured while getting userinfo: #{rc.message}")
    	end
        create_groups(groupnames)
        new_groupids = groupnames.map {|groupname| get_groupid(groupname)}
        preference_listids = @config[:shib_entitlement_priority].map {|preference| get_groupid(preference)}

        # make the first valid group from the preference list primary group of the user
        primary_groupid = (preference_listids & new_groupids).shift
        if primary_groupid.nil?
            primary_groupid = new_groupids[0]
        end


        rc = user.chgrp(primary_groupid)
        if OpenNebula.is_error?(rc)
        	@logger.error("Error while changing primary group of user: #{rc.message}")
        	return nil
        end

        old_groupids = user.groups
        if old_groupids.nil?
        	@logger.error("Error while getting group membeships.")
        	return nil
        end

        # collect the secondary groups from the user have to be removed or added
        groups_to_remove = (old_groupids - new_groupids)
        groups_to_remove.delete(primary_groupid)
        groups_to_add = (new_groupids - old_groupids)
        groups_to_add.delete(primary_groupid)

		@logger.debug("Old group ids: #{old_groupids}")
		@logger.debug("New group ids: #{new_groupids}")
		@logger.debug("groups to add: #{groups_to_add}")
		@logger.debug("groups to remove: #{groups_to_remove}")
        
        # add user to the new secondary groups
        if !groups_to_add.empty?
            groups_to_add.map {|new_groupid|
                rc = user.addgroup(new_groupid)
                if OpenNebula.is_error?(rc)
                	@logger.error("Error while adding user to group: #{rc.message}")
                end
            }
        end

        # remove user from the old secondary groups
        if !groups_to_remove.empty?
            groups_to_remove.map {|old_groupid|
                rc = user.delgroup(old_groupid)
                if OpenNebula.is_error?(rc)
                	@logger.error("Error while removing user from group: #{rc.message}")
                	return nil
                end
            }
        end
    end

    # get array of groupnames created from SAML entitlement string
    # @param entitlement_str SAML entitlement string
    # @return array of groupnames
    def get_groups(entitlement_str)
        valid_entitlements = Array.new
        entitlements = entitlement_str.split(';')
        for ent in entitlements
            ents = ent.split(':')
            if ents[ents.length-2] == @config[:shib_ent_prefix]
                valid_entitlements.push(ents.last)
            end
        end
        return valid_entitlements
    end

    # create random password for new users
    # @return random password
    def generate_password
        return rand(36 ** 20).to_s(36)
    end

end
