import mock
import unittest
import webtest

import kinto.core
from kinto.core.errors import ERRORS
from kinto.core.testing import FormattedErrorMixin
from kinto.core.utils import random_bytes_hex
from pyramid.config import Configurator
from urllib.parse import parse_qs, urlparse

from kinto_portier import __version__ as portier_version


MINIMAL_PORTIER_REQUEST = {
    "redirect": "http://iam.whitelist.ed",
    "email": "foo@bar.com"
}

MINIMAL_PORTIER_VERIFY_REQUEST = {
    "id_token": '4128913851c9c4305e43dba2a7e59baa5c2fe2b909c6b63d04668346c4fb1e7b'
}


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
        settings = {**kinto.core.DEFAULT_SETTINGS}
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

    def test_email_parameter_is_mandatory(self):
        r = self.app.post(self.url, status=400)
        self.assertIn('email', r.json['message'])

    def test_redirect_parameter_is_mandatory(self):
        body = {**MINIMAL_PORTIER_REQUEST}
        del body['redirect']
        r = self.app.post_json(self.url, body, status=400)
        self.assertIn('redirect', r.json['message'])

    def test_redirect_parameter_should_be_refused_if_not_whitelisted(self):
        body = {**MINIMAL_PORTIER_REQUEST}
        body['redirect'] = "http://not-whitelisted.tld"

        r = self.app.post_json(self.url, body, status=400)
        self.assertIn('redirect', r.json['message'])

    def test_redirect_parameter_should_be_accepted_if_whitelisted(self):
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '*.whitelist.ed')]):
            self.app.post_json(self.url, MINIMAL_PORTIER_REQUEST)

    def test_redirect_parameter_should_be_rejected_if_no_whitelist(self):
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '')]):
            r = self.app.post_json(self.url, MINIMAL_PORTIER_REQUEST, status=400)
        self.assertIn('redirect URL is not authorized', r.json['message'])

    def test_login_view_persists_nonce(self):
        body = {**MINIMAL_PORTIER_REQUEST}
        body['redirect'] = "https://readinglist.firefox.com"
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '*.firefox.com')]):
            r = self.app.post_json(self.url, body)
        url = r.headers['Location']
        url_fragments = urlparse(url)
        queryparams = parse_qs(url_fragments.query)
        state = queryparams['nonce'][0]
        self.assertEqual(self.app.app.registry.cache.get('portier:nonce:%s' % state),
                         'https://readinglist.firefox.com')

    def test_login_view_persists_nonce_with_expiration(self):
        body = {**MINIMAL_PORTIER_REQUEST}
        body['redirect'] = "https://readinglist.firefox.com"
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '*.firefox.com')]):
            r = self.app.post_json(self.url, body)
        url = r.headers['Location']
        url_fragments = urlparse(url)
        queryparams = parse_qs(url_fragments.query)
        nonce = queryparams['nonce'][0]
        self.assertGreater(self.app.app.registry.cache.ttl('portier:nonce:%s' % nonce), 299)
        self.assertLessEqual(self.app.app.registry.cache.ttl('portier:nonce:%s' % nonce), 300)

    def test_login_view_redirects_to_authorization(self):
        settings = self.app.app.registry.settings
        oauth_endpoint = settings.get('portier.broker_uri')
        scope = '+'.join(settings.get('portier.requested_scope').split())

        body = {**MINIMAL_PORTIER_REQUEST}
        body['redirect'] = "https://readinglist.firefox.com"
        with mock.patch.dict(self.app.app.registry.settings,
                             [('portier.webapp.authorized_domains',
                               '*.firefox.com')]):
            r = self.app.post_json(self.url, body)
        self.assertEqual(r.status_code, 302)
        assert r.headers['Location'].startswith(oauth_endpoint + '/auth')
        assert scope in r.headers['Location']


class VerifyViewTest(FormattedErrorMixin, BaseWebTest, unittest.TestCase):
    url = '/portier/verify'
    login_url = '/portier/login?redirect=https://readinglist.firefox.com'

    def __init__(self, *args, **kwargs):
        super(VerifyViewTest, self).__init__(*args, **kwargs)

    def test_success_if_get_verfied_worked(self):
        with mock.patch('kinto_portier.views.get_verified_email',
                        return_value=('foo@bar.com', 'http://redirect-url/#portier-token:')):
            resp = self.app.post_json(self.url, MINIMAL_PORTIER_VERIFY_REQUEST, status=302)
        assert 'Location' in resp.headers
        url = 'http://redirect-url/#portier-token:'
        assert resp.headers['Location'].startswith(url)

    def test_fails_if_get_verified_email_raises_a_value_error(self):
        with mock.patch('kinto_portier.views.get_verified_email',
                        side_effect=ValueError('Invalid token')):
            resp = self.app.post_json(self.url, MINIMAL_PORTIER_VERIFY_REQUEST, status=400)
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_AUTH_TOKEN, "Invalid Auth Token",
            "Portier token validation failed: Invalid token")

    def test_fails_if_id_token_is_missing(self):
        resp = self.app.post_json(self.url, {}, status=400)
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters",
            "id_token in body: Required")

    def test_returns_error_in_case_returned_from_broker(self):
        resp = self.app.post_json(self.url+'?error=INVALID&error_description=Not authorized',
                                  MINIMAL_PORTIER_VERIFY_REQUEST, status=400)
        self.assertFormattedError(
            resp, 400, ERRORS.INVALID_PARAMETERS, "Invalid parameters",
            "Broker error (INVALID): Not authorized")


class CapabilityTestView(BaseWebTest, unittest.TestCase):

    def test_portier_capability(self, additional_settings=None):
        resp = self.app.get('/')
        capabilities = resp.json['capabilities']
        self.assertIn('portier', capabilities)
        expected = {
            "version": portier_version,
            "url": "https://github.com/Kinto/kinto-portier",
            "description": "Authenticate users using Portier."
        }
        self.assertEqual(expected, capabilities['portier'])
