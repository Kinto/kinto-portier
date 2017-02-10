Portier authentication support for Kinto
========================================

|travis| |master-coverage|

.. |travis| image:: https://travis-ci.org/Kinto/kinto-portier.svg?branch=master
    :target: https://travis-ci.org/Kinto/kinto-portier

.. |master-coverage| image::
    https://coveralls.io/repos/Kinto/kinto-portier/badge.png?branch=master
    :alt: Coverage
    :target: https://coveralls.io/r/Kinto/kinto-portier

*kinto-portier* enables authentication in *Kinto* applications using
an email address.

It provides:

* An authentication policy class;
* Integration with *Kinto* cache backend for token verifications;
* Integration with *Kinto* for heartbeat view checks;
* Some optional endpoints to perform the *OAuth* dance (*optional*).


* `Kinto documentation <http://kinto.readthedocs.io/en/latest/>`_
* `Issue tracker <https://github.com/Kinto/kinto-portier/issues>`_


Installation
------------

As `stated in the official documentation <https://developer.mozilla.org/en-US/Firefox_Accounts>`_,
Firefox Accounts OAuth integration is currently limited to Mozilla relying services.

Install the Python package:

::

    pip install kinto-portier


Include the package in the project configuration:

::

    kinto.includes = kinto_portier

And configure authentication policy using `pyramid_multiauth
<https://github.com/mozilla-services/pyramid_multiauth#deployment-settings>`_ formalism:

::

    multiauth.policies = portier
    multiauth.policy.portier.use = kinto_portier.authentication.PortierOAuthAuthenticationPolicy

By default, it will rely on the cache configured in *Kinto*.


Configuration
-------------

Fill those settings with the values obtained during the application registration:

::

    kinto.portier.broker_url = https://broker.portier.io
    kinto.portier.webapp.authorized_domains = *.github.io
    # kinto.portier.cache_ttl_seconds = 300
    # kinto.portier.state.ttl_seconds = 3600



Login flow
----------

OAuth Bearer token
::::::::::::::::::

Use the OAuth token with this header:

::

    Authorization: Portier <jwt_token>


:notes:

    If the token is not valid, this will result in a ``401`` error response.
