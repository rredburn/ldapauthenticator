import ldap3
import re
from jupyterhub.auth import Authenticator

from tornado import gen
from traitlets import Unicode, Int, Bool, Union, List


class BPAuthenticator(Authenticator):
    server_address = Unicode(
        config=True,
        help='Address of LDAP server to contact'
    )
    server_port = Int(
        config=True,
        help='Port on which to contact LDAP server',
    )

    def _server_port_default(self):
        if self.use_ssl:
            return 636  # default SSL port for LDAP
        else:
            return 389  # default plaintext port for LDAP

    use_ssl = Bool(
        True,
        config=True,
        help='Use SSL to encrypt connection to LDAP server'
    )

    bind_dn_template = Unicode(
        config=True,
        help="""
        Template from which to construct the full dn
        when authenticating to LDAP. {username} is replaced
        with the actual username.

        Example:

            uid={username},ou=people,dc=wikimedia,dc=org
        """
    )


    allowed_groups = List(
        config=True,
        help="List of LDAP Group DNs whose members are allowed access"
    )

    valid_username_regex = Unicode(
        r'^[a-z][.a-z0-9_-]*$',
        config=True,
        help="""Regex to use to validate usernames before sending to LDAP

        Also acts as a security measure to prevent LDAP injection. If you
        are customizing this, be careful to ensure that attempts to do LDAP
        injection are rejected by your customization
        """
    )

    @gen.coroutine
    def authenticate(self, handler, data):
        email = data['username']
        password = data['password']
        atloc = email.find('@')
        username = email[:atloc] if atloc > 0 else email

        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, email):
            self.log.warn("Invalid username '%s'", email)
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('Empty password')
            return None

        server = ldap3.Server(
            self.server_address,
            port=self.server_port,
            use_ssl=self.use_ssl
        )

        userdn = None
        with ldap3.Connection(server, authentication=None, read_only=True) as conn:
            # translate email to serial
            if conn.search(search_base='ou=bluepages,o=ibm.com',
                           search_scope=ldap3.SUBTREE,
                           search_filter="(&(objectClass=ibmperson)(emailaddress=%s))" % email,
                           attributes=['dn']):
                for entry in conn.response:
                    userdn = entry['dn']
                    self.log.debug('userdn for %s is %s', email, userdn)
                    break

        if userdn is None:
            self.log.warn('could not determine userdn for %s', email)
            return None

        with ldap3.Connection(server, user=userdn, password=password, read_only=True) as conn:
            if not conn.bind():
                self.log.warn('login failed, likely invalid password')
                return None

        if self.allowed_groups:
            server = ldap3.Server(
                'bluegroups.ibm.com',
                port=self.server_port,
                use_ssl=self.use_ssl
            )
            with ldap3.Connection(server, authentication=None, read_only=True):
                for group in self.allowed_groups:
                    if conn.search(search_base='ou=memberlist,ou=ibmgroups,o=ibm.com',
                                   search_scope=ldap3.SUBTREE,
                                   search_filter="(&(objectclass=groupofuniquenames)(cn=%s))" % group,
                                   attributes=['uniquemember']):
                        if len(conn.response) == 1:
                            if userdn in conn.response[0]['attributes']['uniquemember']:
                                return username
                        else:
                            self.log.warn('failed to find bluegroup %s', group)
                # should have returned by this point
                self.log.warn('login failed, not in correct bluegroup')
                return None
        else:
            return username
