import time
import unittest

import mock
import requests
from kinto.core.cache import memory as memory_backend
from kinto.core.testing import DummyRequest
from kinto.core.utils import random_bytes_hex, hmac_digest
from pyramid import httpexceptions

from kinto_portier import authentication, DEFAULT_SETTINGS


class PortierOAuthAuthenticationPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = authentication.PortierOAuthAuthenticationPolicy()
        self.backend = memory_backend.Cache(cache_prefix="tests")
        self.user_hmac_secret = random_bytes_hex(16)

        # Setup user
        self.email = 'foo@bar.com'
        self.user_key = hmac_digest(self.user_hmac_secret, self.email)
        self.backend.set(self.user_key, self.email)
        self.request = self._build_request()

    def tearDown(self):
        self.backend.flush()

    def _build_request(self):
        request = DummyRequest()
        request.bound_data = {}
        request.registry.cache = self.backend
        settings = DEFAULT_SETTINGS.copy()
        settings['portier.cache_ttl_seconds'] = '0.01'
        settings['userid_hmac_secret'] = self.user_hmac_secret
        request.registry.settings = settings
        request.headers['Authorization'] = 'Portier %s' % self.user_key
        return request

    def test_returns_none_if_authorization_header_is_missing(self):
        self.request.headers.pop('Authorization')
        user_id = self.policy.unauthenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_none_if_token_is_malformed(self):
        self.request.headers['Authorization'] = 'Portierfoo'
        user_id = self.policy.unauthenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_none_if_token_is_unknown(self):
        self.request.headers['Authorization'] = 'Carrier foo'
        user_id = self.policy.authenticated_userid(self.request)
        self.assertIsNone(user_id)

    def test_returns_portier_userid(self):
        user_id = self.policy.authenticated_userid(self.request)
        self.assertEqual(self.email, user_id)

    def test_returns_portier_userid_in_principals(self):
        principals = self.policy.effective_principals(self.request)
        self.assertIn(self.email, principals)

    def test_forget_uses_realm(self):
        policy = authentication.PortierOAuthAuthenticationPolicy(realm='Who')
        headers = policy.forget(self.request)
        self.assertEqual(headers[0],
                         ('WWW-Authenticate', 'Portier realm="Who"'))


class PortierPingTest(unittest.TestCase):
    def setUp(self):
        self.request = DummyRequest()
        self.request.registry.settings = DEFAULT_SETTINGS
        self.request.registry.settings['portier.broker_uri'] = 'http://broker-portier'

    def test_returns_none_if_oauth_deactivated(self):
        self.request.registry.settings['portier.broker_uri'] = None
        self.assertIsNone(authentication.portier_ping(self.request))

    @mock.patch('requests.get')
    def test_returns_true_if_ok(self, get_mocked):
        httpOK = requests.models.Response()
        httpOK.status_code = 200
        get_mocked.return_value = httpOK
        self.assertTrue(authentication.portier_ping(self.request))

    @mock.patch('requests.get')
    def test_returns_false_if_ko(self, get_mocked):
        get_mocked.side_effect = requests.exceptions.HTTPError()
        self.assertFalse(authentication.portier_ping(self.request))
