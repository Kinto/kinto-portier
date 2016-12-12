import colander
import uuid

from datetime import timedelta
from fnmatch import fnmatch
from cornice.validators import colander_validator, colander_body_validator
from pyramid import httpexceptions
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.settings import aslist
from six.moves.urllib.parse import urlencode, urlparse

from kinto.core import Service, utils
from kinto.core.errors import json_error_handler, raise_invalid
from kinto.core.resource.schema import URL
from kinto_portier.portier import get_verified_email
from kinto_portier.utils import portier_conf


login = Service(name='portier-login',
                path='/portier/login',
                error_handler=json_error_handler)

verify = Service(name='portier-verify',
                 path='/portier/verify',
                 error_handler=json_error_handler)


def persist_nonce(request):
    """Persist arbitrary string in cache.
    It will be matched when the user returns from the OAuth server login
    page.
    """
    nonce = uuid.uuid4().hex
    redirect_url = request.validated['redirect']
    expiration = float(portier_conf(request, 'cache_ttl_seconds'))

    cache = request.registry.cache
    cache.set("portier:nonce:%s" % nonce, redirect_url, expiration)

    return nonce


class PortierLoginRequest(colander.MappingSchema):
    email = colander.Email()
    redirect = URL()


def authorized_redirect(req, **kwargs):
    authorized = aslist(portier_conf(req, 'webapp.authorized_domains'))
    if 'redirect' not in req.validated:
        return True

    domain = urlparse(req.validated['redirect']).netloc

    if not any((fnmatch(domain, auth) for auth in authorized)):
        req.errors.add('querystring', 'redirect',
                       'redirect URL is not authorized')


@login.post(schema=PortierLoginRequest(), permission=NO_PERMISSION_REQUIRED,
            validators=(colander_body_validator, authorized_redirect))
def portier_login(request):
    """Helper to redirect client towards Portier login form."""
    nonce = persist_nonce(request)
    form_url = ('{broker_uri}auth?{query_args}')
    broker_uri = portier_conf(request, 'broker_uri')

    query_args = urlencode({
        'login_hint': request.validated['email'],
        'scope': portier_conf(request, 'requested_scope'),
        'nonce': nonce,
        'response_type': 'id_token',
        'response_mode': 'form_post',
        'client_id': '{scheme}://{host}'.format(scheme=request.registry.settings['http_scheme'],
                                                host=request.registry.settings['http_host']),
        'redirect_uri': request.route_url(verify.name),
    })

    return httpexceptions.HTTPFound(location=form_url.format(broker_uri=broker_uri,
                                                             query_args=query_args))


class PortierVerifyQuerystring(colander.MappingSchema):
    error = colander.SchemaNode(colander.String(), missing=colander.drop)
    error_description = colander.SchemaNode(colander.String(), missing=colander.drop)


class PortierVerifyPayload(colander.MappingSchema):
    id_token = colander.SchemaNode(colander.String())


class PortierVerifyRequest(colander.MappingSchema):
    body = PortierVerifyPayload()
    querystring = PortierVerifyQuerystring()

    def deserialize(self, cstruct=colander.null):
        appstruct = super(PortierVerifyRequest, self).deserialize(cstruct)
        error = appstruct['querystring'].get('error')
        if error:
            msg = 'Broker error (%s)' % error
            desc = appstruct['querystring'].get('error_description')
            if desc:
                msg += ': %s' % desc
            self.raise_invalid(msg)
        return appstruct


@verify.post(schema=PortierVerifyRequest(), permission=NO_PERMISSION_REQUIRED,
             validators=(colander_validator,))
def portier_verify(request):
    """Helper to redirect client towards Portier login form."""
    broker_uri = portier_conf(request, 'broker_uri')
    token = request.validated['body']['id_token']
    audience = '{scheme}://{host}'.format(scheme=request.registry.settings['http_scheme'],
                                          host=request.registry.settings['http_host']),

    try:
        email, stored_redirect = get_verified_email(
            broker_url=broker_uri,
            token=token,
            audience=audience,
            issuer=broker_uri,
            cache=request.registry.cache)
    except RuntimeError as exc:
        error_details = {
            'name': 'id_token',
            'location': 'body',
            'description': 'Portier token validation failed: %s' % exc
        }
        raise_invalid(request, **error_details)

    hmac_secret = request.registry.settings['userid_hmac_secret']
    user_token = utils.hmac_digest(hmac_secret, email)
    request.registry.cache.set('portier:' + user_token, email,
                               timedelta(days=1).seconds)

    return httpexceptions.HTTPFound(location='%s%s' % (stored_redirect, user_token))
