def portier_conf(request, name):
    key = 'portier.%s' % name
    return request.registry.settings[key]
