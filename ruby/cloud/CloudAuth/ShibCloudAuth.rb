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

DIR=File.dirname(__FILE__)
$: << DIR

require 'shib_helper.rb'
require 'xmlrpc/client'
require 'rubygems'
require 'nokogiri'

# @mainpage  Shibboleth Cloud Auth module for OpenNebula Sunstone
#
# @section desc Description
# This is a new authentication module for OpenNebula Sunstone.
# Shib Cloud Auth module is useful, when a SingleSignOn login is needed, where the Service Provider realised with a Shibboleth SP.
# In this case, login handled by Shibboleth and so the Sunstone 
# auth module (this one) controls the authorization of the users. \n
# If a new user wants to login, this module creates a new account for the user. The user's primary group and his secondary groups also created from the entitlements that come to Shibboleth in a SAML message.
# 
# @section conf Configuration
# Configuration file is at the end of the main Sunstone configuration file (sunstone-server.conf).
# Some configuration option is selfdescriptive (like :shib_host, :shib_logoutpage, :one_auth_for_shib). The rest of the options modify the behaviour of this authentication module.
# First an Apache HTTP VirtualHost location have to be created, a possible example can be see here:
# <Location /one>
#        # shibboleth shield 
#        AllowOverride all 
#        Order allow,deny 
#        Allow from all 
#        AuthType shibboleth
#        require valid-user
#        ShibUseHeaders On
#        ShibRequireSession On
# </Location>
#
# When OpenNebula authorizes a user this module uses some Apache HTTP header variable, where the SAML message datas are stored. After a successful authentication from the Apache HTTP header variables this module can read the actual user's datas.
# Example:
# :shib_username: HTTP_EPPN
# :shib_entitlement: HTTP_ENTITLEMENT
# :shib_entitlement_priority:
#    - admin
#    - alpha
#    - bravo
#
# In the example above the name of the user are stored in the HTTP_EPPN header variable, and the entitlements / privileges are stored in the HTTP_ENTITLEMENT header variable. The primary group of the user is calculated from the shib_entitlement_priority list, where the first existing groupname will be his primary group.

module ShibCloudAuth
    def do_auth(env, params={})
        auth = Rack::Auth::Basic::Request.new(env)

        if auth.provided? && auth.basic?
            @logger.info{"shib helper"}
            # create helper
            shib = Shib_Helper.new(@conf, @logger)
            
            # get username from session
            username = params['shib_username']

            # if new user wants to login then create it
            userid = shib.get_userid(username).to_i
            if userid == 0
                userid = shib.create_user(username).to_i
            end

            if !params['shib_entitlement'].empty?
                # get groupnames from entitlement
				groupnames = shib.get_groups(params['shib_entitlement'])
                # add user to given groups remove him from the old groups
                shib.handle_groups(userid, groupnames)
            else
                # if new user does not have any entitlement then refuse to login
                return nil
            end            

            return username
        end

        return nil
    end
end
