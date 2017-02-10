import pkg_resources

from pyramid.exceptions import ConfigurationError

from kinto_portier.authentication import portier_ping

#: Module version, as defined in PEP-0396.
__version__ = pkg_resources.get_distribution(__package__).version


DEFAULT_SETTINGS = {
    'portier.cache_ttl_seconds': 5 * 60,
    'portier.session_ttl_seconds': None,
    'portier.heartbeat_timeout_seconds': 3,
    'portier.broker_uri': "https://broker.portier.io",
    'portier.requested_scope': 'openid email',
    'portier.webapp.authorized_domains': '',
}


def includeme(config):
    if not hasattr(config.registry, 'heartbeats'):
        message = ('kinto-portier should be included once Kinto is initialized. '
                   'Use setting ``kinto.includes`` instead of ``pyramid.includes``'
                   ' or include it manually.')
        raise ConfigurationError(message)

    settings = config.get_settings()

    defaults = {k: v for k, v in DEFAULT_SETTINGS.items() if k not in settings}
    config.add_settings(defaults)

    # Register heartbeat to ping the portier broker.
    config.registry.heartbeats['portier'] = portier_ping

    config.add_api_capability(
        "portier",
        version=__version__,
        description="Authenticate users using Portier.",
        url="https://github.com/Kinto/kinto-portier")

    config.scan('kinto_portier.views')
