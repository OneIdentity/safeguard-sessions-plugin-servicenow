#
#   Copyright (c) 2020 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#

import requests
import pysnow
from safeguard.sessions.plugin.requests_tls import RequestsTLS


class ServiceNowClient:
    def __init__(self, instance=None, host=None, username=None, password=None, session=None):
        self._instance = instance
        self._host = host
        self._username = username
        self._password = password
        self._session = session
        self._client = self._construct_client()

    @classmethod
    def from_config(cls, plugin_configuration):
        instance = plugin_configuration.get("service_now", "instance")
        host = plugin_configuration.get("service_now", "host", required=(instance is None))
        user = plugin_configuration.get("service_now", "user", required=True)
        password = plugin_configuration.get("service_now", "password", required=True).strip()
        session = RequestsTLS.from_config(plugin_configuration).open_session()
        return cls(instance, host, user, password, session)

    def _construct_client(self):
        # If instance is not defined in the config, host is required. If both are defined, instance
        # takes precedence.
        with self._session as _session:
            _session.auth = requests.auth.HTTPBasicAuth(self._username, self._password)
            return (
                pysnow.Client(
                    instance=self._instance,
                    session=_session)
                if self._instance else pysnow.Client(
                    host=self._host,
                    session=_session
                )
            )

    def get_resource(self, resource_path):
        return self._client.resource(api_path=resource_path)
