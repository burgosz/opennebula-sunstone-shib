opennebula-sunstone-shib
========================

Shibboleth plugin for Sunstone 4.10

Installation
========================
Download the install.sh script, and the patch file (plugin.patch).
Add execute permission to the script: chmod +x install.sh
Review the configuration in /etc/one/sunstone-server.conf file.

Configuration
========================
:shib_logoutpage: /Shibboleth.sso/Logout  --The Shibboleth logout URL
:one_auth_username: oneadmin              --Username of the admin user
:one_auth_passwd: oneadminpass            --Password of the admin user
:shib_ent_prefix: opennebula              --Entitlement prefix
:shib_username: HTTP_EPPN                 --Shibboleth attribute to use as username
:shib_entitlement: HTTP_ENTITLEMENT       --Shibboleth attribute to use as entitlement
:shib_entitlement_priority:               --Entitlement priority list
    - admin
    - alpha
    - bravo
