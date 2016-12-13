import mock
import unittest
import webtest

import kinto.core
from kinto.core.errors import ERRORS
from kinto.core.testing import FormattedErrorMixin
from kinto.core.utils import random_bytes_hex
from pyramid.config import Configurator
from six.moves.urllib.parse import parse_qs, urlparse
from time import sleep

from kinto_portier import __version__ as portier_version


def get_request_class(prefix):

    class PrefixedRequestClass(webtest.app.TestRequest):

        @classmethod
        def blank(cls, path, *args, **kwargs):
            path = '/%s%s' % (prefix, path)
            return webtest.app.TestRequest.blank(path, *args, **kwargs)

    return PrefixedRequestClass


class BaseWebTest(object):
    """Base Web Test to test your cornice service.

    It setups the database before each test and delete it after.
    """

    api_prefix = "v0"

    def __init__(self, *args, **kwargs):
        super(BaseWebTest, self).__init__(*args, **kwargs)
        self.app = self._get_test_app()
        self.headers = {
            'Content-Type': 'application/json',
        }

    def _get_test_app(self, settings=None):
        config = self._get_app_config(settings)
        wsgi_app = config.make_wsgi_app()
        app = webtest.TestApp(wsgi_app)
        app.RequestClass = get_request_class(self.api_prefix)
        return app

    def _get_app_config(self, settings=None):
        config = Configurator(settings=self.get_app_settings(settings))
        kinto.core.initialize(config, version='0.0.1')
        return config

    def get_app_settings(self, additional_settings=None):
        settings = kinto.core.DEFAULT_SETTINGS.copy()
        settings['includes'] = 'kinto_portier'
        settings['multiauth.policies'] = 'portier'
        authn = 'kinto_portier.authentication.PortierOAuthAuthenticationPolicy'
        settings['multiauth.policy.portier.use'] = authn
        settings['cache_backend'] = 'kinto.core.cache.memory'
        settings['cache_backend'] = 'kinto.core.cache.memory'
        settings['userid_hmac_secret'] = random_bytes_hex(16)
        settings['portier.broker_uri'] = 'https://broker.portier.io'

        if additional_settings is not None:
            settings.update(additional_settings)
        return settings


class LoginViewTest(BaseWebTest, unittest.TestCase):
    url = '/portier/login'

    def get_app_settings(self, additional_settings=None):
        additional_settings = additional_settings or {}
        additional_settings.update({
            'portier.requested_scope': 'openid email'
        })
        return super(LoginViewTest, self).get_app_settings(additional_settings)

    def test_redirect_parameter_is_mandatory(self):
        r = self.app.post(self.url, status=400)
        self.assertIn('redirect', r.json['message'])

    def test_redirect_parameter_should_be_refused_if_not_whitelisted(self):
        r = self.app.post_json(self.url, {"redirect": "http://not-whitelisted.tld"}, status=400)
        self.assertIn('redirect', r.json['message'])

    def test_redirect_parameter_should_be_accepted_if_whitelisted(self):
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '*.whitelist.ed')]):
            self.app.post_json(self.url, {"redirect": "http://iam.whitelist.ed"})

    def test_redirect_parameter_should_be_rejected_if_no_whitelist(self):
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '')]):
            r = self.app.post_json(self.url, {"redirect": "http://iam.whitelist.ed"}, status=400)
        self.assertIn('redirect', r.json['message'])

    def test_login_view_persists_nonce(self):
        r = self.app.post_json(self.url, {"redirect": "https://readinglist.firefox.com"})
        url = r.headers['Location']
        url_fragments = urlparse(url)
        queryparams = parse_qs(url_fragments.query)
        state = queryparams['nonce'][0]
        self.assertEqual(self.app.app.registry.cache.get('portier:nonce:%s' % state),
                         'https://readinglist.firefox.com')

    def test_login_view_persists_nonce_with_expiration(self):
        r = self.app.get(self.url)
        url = r.headers['Location']
        url_fragments = urlparse(url)
        queryparams = parse_qs(url_fragments.query)
        nonce = queryparams['nonce'][0]
        self.assertGreater(self.app.app.registry.cache.ttl(nonce), 299)
        self.assertLessEqual(self.app.app.registry.cache.ttl(nonce), 300)

    def test_login_view_redirects_to_authorization(self):
        settings = self.app.app.registry.settings
        oauth_endpoint = settings.get('portier.broker_uri')
        scope = '+'.join(settings.get('portier.requested_scope').split())

        r = self.app.get(self.url)
        self.assertEqual(r.status_code, 302)
        assert r.headers['Location'].startswith(oauth_endpoint + '/auth')
        assert scope in r.headers['Location']


class VerifyViewTest(FormattedErrorMixin, BaseWebTest, unittest.TestCase):
    url = '/portier/verify'
    login_url = '/portier/login?redirect=https://readinglist.firefox.com'

#     def __init__(self, *args, **kwargs):
#         super(VerifyViewTest, self).__init__(*args, **kwargs)
# 
#     def test_fails_if_no_ongoing_session(self):
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         resp = self.app.post(url, status=400)
#         error_msg = 'The OAuth session was not found, please re-authenticate.'
#         self.assertFormattedError(
#             resp, 400, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg)
# 
#     def test_fails_if_nonce_or_code_is_missing(self):
#         headers = {'Cookie': 'nonce=abc'}
#         for params in ['', '?nonce=abc', '?code=1234']:
#             r = self.app.get(self.url + params, headers=headers, status=400)
#             self.assertIn('missing', r.json['message'])
# 
#     def test_fails_if_nonce_does_not_match(self):
#         self.app.app.registry.cache.set('def', 'http://foobar')
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         resp = self.app.get(url, status=408)
#         error_msg = 'The OAuth session was not found, please re-authenticate.'
#         self.assertFormattedError(
#             resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg)
# 
#     def test_fails_if_nonce_was_already_consumed(self):
#         self.app.app.registry.cache.set('abc', 'http://foobar')
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         self.app.get(url)
#         resp = self.app.get(url, status=408)
#         error_msg = 'The OAuth session was not found, please re-authenticate.'
#         self.assertFormattedError(
#             resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg)
# 
#     def test_fails_if_nonce_has_expired(self):
#         with mock.patch.dict(self.app.app.registry.settings,
#                              [('portier.cache_ttl_seconds', 0.01)]):
#             r = self.app.get(self.login_url)
#         url = r.headers['Location']
#         url_fragments = urlparse(url)
#         queryparams = parse_qs(url_fragments.query)
#         nonce = queryparams['nonce'][0]
#         url = '{url}?nonce={nonce}&code=1234'.format(nonce=nonce, url=self.url)
#         sleep(0.02)
#         resp = self.app.get(url, status=408)
#         error_msg = 'The OAuth session was not found, please re-authenticate.'
#         self.assertFormattedError(
#             resp, 408, ERRORS.MISSING_AUTH_TOKEN, "Request Timeout", error_msg)
# 
#     def tests_redirects_with_token_traded_against_code(self):
#         self.app.app.registry.cache.set('abc', 'http://foobar?token=')
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         r = self.app.get(url)
#         self.assertEqual(r.status_code, 302)
#         self.assertEqual(r.headers['Location'],
#                          'http://foobar?token=oauth-token')
# 
#     def tests_return_503_if_fxa_server_behaves_badly(self):
#         self.fxa_trade.side_effect = fxa_errors.OutOfProtocolError
# 
#         self.app.app.registry.cache.set('abc', 'http://foobar')
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         self.app.get(url, status=503)
# 
#     def tests_return_400_if_client_error_detected(self):
#         self.fxa_trade.side_effect = fxa_errors.ClientError
# 
#         self.app.app.registry.cache.set('abc', 'http://foobar')
#         url = '{url}?nonce=abc&code=1234'.format(url=self.url)
#         self.app.get(url, status=400)


class CapabilityTestView(BaseWebTest, unittest.TestCase):

    def test_fxa_capability(self, additional_settings=None):
        resp = self.app.get('/')
        capabilities = resp.json['capabilities']
        self.assertIn('portier', capabilities)
        expected = {
            "version": portier_version,
            "url": "https://github.com/Kinto/kinto-portier",
            "description": "Authenticate users using Portier."
        }
        self.assertEqual(expected, capabilities['portier'])
