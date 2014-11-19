#!/bin/bash
read -p "Account name of admin? [oneadmin] " acc
read -p "Password of admin? " pass
sudo sed -i 's/:auth: .*/:auth: shib/' /etc/one/sunstone-server.conf
printf "#####################################################################$
## Shibboleth Auth module
#############################################################################$
#
## shib_host:                           Shibboleth host url
## shib_logoutpage:                     Shibboleth logout page
## one_auth_for_shib:                   $ONE_AUTH file location
## shib_username:                               SAML attribute to use as a us$
## shib_entitlement:                    SAML attribute to use as entitlement $
## shib_entitlement_priority    entitlement priority list
:shib_logoutpage: /Shibboleth.sso/Logout
:one_auth_username: $acc
:one_auth_passwd: $pass
:shib_ent_prefix: opennebula
:shib_username: HTTP_EPPN
:shib_entitlement: HTTP_ENTITLEMENT
:shib_entitlement_priority:
    - admin
    - alpha
    - bravo" | sudo tee -a /etc/one/sunstone-server.conf
pwd=$(pwd)
cd /usr/lib
patch -s -p0 -R -f < $pwd/plugin.patch

