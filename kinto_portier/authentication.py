import logging
import requests

from pyramid import authentication as base_auth
from pyramid.interfaces import IAuthenticationPolicy
from urllib.parse import urljoin
from zope.interface import implementer

from kinto.core import utils
from kinto_portier.crypto import decrypt
from kinto_portier.utils import portier_conf

logger = logging.getLogger(__name__)


@implementer(IAuthenticationPolicy)
class PortierOAuthAuthenticationPolicy(base_auth.CallbackAuthenticationPolicy):
    def __init__(self, realm='Realm'):
        self.realm = realm
        self._cache = None

    def unauthenticated_userid(self, request):
        """Return the Portier userid or ``None`` if token could not be verified.
        """
        authorization = request.headers.get('Authorization', '')
        try:
            authmeth, token = authorization.split(' ', 1)
        except ValueError:
            return None
        if authmeth.lower() != 'portier':
            return None
        return self._verify_token(token, request)

    def forget(self, request):
        """A no-op. Credentials are sent on every request.
        Return WWW-Authenticate Realm header for Bearer token.
        """
        return [('WWW-Authenticate', 'Portier realm="%s"' % self.realm)]

    def _verify_token(self, user_token, request):
        """Verify the token extracted from the Authorization header.

        This method stores the result in two locations to avoid hitting the
        auth remote server as much as possible:

        - on the request object, in case the Pyramid authentication methods
          like `effective_principals()` or `authenticated_userid()` are called
          several times during the request cycle;

        - in the cache backend, to reuse validated token from one request to
          another (during ``cache_ttl_seconds`` seconds.)
        """
        # First check if this request was already verified.
        # `request.bound_data` is an attribute provided by Kinto to store
        # some data that is shared among sub-requests (e.g. default bucket
        # or batch requests)
        key = 'portier_verified_token'
        if key in request.bound_data:
            return request.bound_data[key]

        hmac_secret = request.registry.settings['userid_hmac_secret']
        userID = utils.hmac_digest(hmac_secret, user_token)
        auth_cache = request.registry.cache
        encrypted_email = auth_cache.get("portier:%s" % userID)

        if encrypted_email is None:
            return None

        email = decrypt(encrypted_email, user_token)

        # Save for next call.
        request.bound_data[key] = email

        return email


def portier_ping(request):
    """Verify if the portier server is ready."""
    server_url = portier_conf(request, 'broker_uri')

    portier = None

    if server_url is not None:
        portier = False
        try:
            conf_url = urljoin(server_url, '/.well-known/openid-configuration')
            timeout = float(portier_conf(request, 'heartbeat_timeout_seconds'))
            r = requests.get(conf_url, timeout=timeout)
            r.raise_for_status()
            portier = True
        except requests.exceptions.HTTPError:
            pass

    return portier
