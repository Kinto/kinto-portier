import json
import re
from base64 import urlsafe_b64decode
from datetime import timedelta
from six.moves.urllib.request import urlopen

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def b64dec(string):
    """Decode unpadded URL-safe Base64 strings.
    Base64 values in JWTs and JWKs have their padding '=' characters stripped
    during serialization. Before decoding, we must re-append padding characters
    so that the encoded value's final length is evenly divisible by 4.
    """
    padding = '=' * ((4 - len(string) % 4) % 4)
    return urlsafe_b64decode(string + padding)


def discover_keys(broker, cache):
    """Discover and return a Broker's public keys.
    Returns a dict mapping from Key ID strings to Public Key instances.
    Portier brokers implement the `OpenID Connect Discovery`_ specification.
    This function follows that specification to discover the broker's current
    cryptographic public keys:
    1. Fetch the Discovery Document from ``/.well-known/openid-configuration``.
    2. Parse it as JSON and read the ``jwks_uri`` property.
    3. Fetch the URL referenced by ``jwks_uri`` to retrieve a `JWK Set`_.
    4. Parse the JWK Set as JSON and extract keys from the ``keys`` property.
    Portier currently only supports keys with the ``RS256`` algorithm type.
    .. _OpenID Connect Discovery:
        https://openid.net/specs/openid-connect-discovery-1_0.html
    .. _JWK Set: https://tools.ietf.org/html/rfc7517#section-5
    """
    # Check the cache
    cache_key = 'jwks:' + broker
    raw_jwks = cache.get(cache_key)
    if not raw_jwks:
        # Fetch Discovery Document
        res = urlopen(''.join((broker, '/.well-known/openid-configuration')))
        discovery = json.loads(res.read().decode('utf-8'))
        if 'jwks_uri' not in discovery:
            raise RuntimeError('No jwks_uri in discovery document')

        # Fetch JWK Set document
        raw_jwks = urlopen(discovery['jwks_uri']).read()

        # Cache JWK Set document
        cache.set(cache_key, raw_jwks, timedelta(minutes=5).seconds)

    # Decode and load the JWK Set document
    jwks = json.loads(raw_jwks.decode('utf-8'))
    if 'keys' not in jwks:
        raise RuntimeError('No keys found in JWK Set')

    # Return the discovered keys as a Key ID -> RSA Public Key dictionary
    return {key['kid']: jwk_to_rsa(key) for key in jwks['keys']
            if key['alg'] == 'RS256'}


def jwk_to_rsa(key):
    """Convert a deserialized JWK into an RSA Public Key instance."""
    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


def get_verified_email(broker_url, token, audience, issuer, cache):
    """Validate an Identity Token (JWT) and return its subject (email address).
    In Portier, the subject field contains the user's verified email address.
    This functions checks the authenticity of the JWT with the following steps:
    1. Verify that the JWT has a valid signature from a trusted broker.
    2. Validate that all claims are present and conform to expectations:
        * ``aud`` (audience) must match this website's origin.
        * ``iss`` (issuer) must match the broker's origin.
        * ``exp`` (expires) must be in the future.
        * ``iat`` (issued at) must be in the past.
        * ``sub`` (subject) must be an email address.
        * ``nonce`` (cryptographic nonce) must not have been seen previously.
    3. If present, verify that the ``nbf`` (not before) claim is in the past.
    Timestamps are allowed a few minutes of leeway to account for clock skew.
    This demo relies on the `PyJWT`_ library to check signatures and validate
    all claims except for ``sub`` and ``nonce``. Those are checked separately.
    .. _PyJWT: https://github.com/jpadilla/pyjwt
    """
    # Retrieve this broker's public keys
    keys = discover_keys(broker_url, cache)

    # Locate the specific key used to sign this JWT via its ``kid`` header.
    raw_header, _, _ = token.partition('.')
    header = json.loads(b64dec(raw_header).decode('utf-8'))
    try:
        pub_key = keys[header['kid']]
    except KeyError:
        raise RuntimeError('Cannot find public key with ID %s' % header['kid'])

    # Verify the JWT's signature and validate its claims
    try:
        payload = jwt.decode(token, pub_key,
                             algorithms=['RS256'],
                             audience=audience,
                             issuer=issuer,
                             leeway=3 * 60)
    except Exception as exc:
        raise RuntimeError('Invalid JWT: %s' % exc)

    # Validate that the subject resembles an email address
    if not re.match('.+@.+', payload['sub']):
        raise RuntimeError('Invalid email address: %s' % payload['sub'])

    # Invalidate the nonce used in this JWT to prevent re-use
    nonce_key = "portier:nonce:%s" % payload['nonce']
    redirect_uri = cache.get(nonce_key)
    if not redirect_uri:
        raise RuntimeError('Invalid, expired, or re-used nonce')
    cache.delete(nonce_key)

    # Done!
    return payload['sub'], redirect_uri
