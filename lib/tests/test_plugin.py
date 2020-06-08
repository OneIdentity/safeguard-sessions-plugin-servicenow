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

from ..plugin import Plugin
from safeguard.sessions.plugin_impl.test_utils.plugin import update_cookies

import pytest


@pytest.fixture
def plugin(plugin_config):
    return Plugin(plugin_config)


@pytest.fixture
def authenticate_parameters():
    def params(ticket_id):
        return dict(
            connection_name="the_connection",
            cookie={},
            session_cookie={},
            session_id="session1",
            gateway_user="gwuser",
            gateway_domain="gateway.domain",
            client_ip="1.2.3.4",
            client_port="2233",
            key_value_pairs={"tkt": ticket_id},
            protocol="ssh"
        )
    return params


@pytest.fixture
def authorize_parameters(authenticate_parameters):
    def params(ticket_id):
        p = authenticate_parameters(ticket_id)
        p.update(dict(
            gateway_groups="",
        ))
        return p
    return params


def test_authorize_successfull_with_ticket_id(plugin, authenticate_parameters, authorize_parameters):
    ticket_id = "CHG0000038"
    authentication_result = plugin.authenticate(
        **authenticate_parameters(ticket_id)
    )
    authorize_params = authorize_parameters(ticket_id)
    update_cookies(authorize_params, authentication_result)
    result = plugin.authorize(**authorize_params)

    assert verdict(result) == "ACCEPT"
    assert "Verified ServiceNow request: {}".format(ticket_id) in additional_metadata(result)


def test_not_configured_ticket_type_should_deny_connection(plugin, authorize_parameters):
    ticket_id = "ABC0000011"
    result = plugin.authorize(**authorize_parameters(ticket_id))

    assert verdict(result) == "DENY"
    assert "Ticket ID doesn't match any patterns; ticket_id={}".format(ticket_id) in additional_metadata(result)


def test_connection_error_deny_connection(plugin_config_custom_host, authorize_parameters, caplog):
    plugin = Plugin(plugin_config_custom_host("not_available"))
    result = plugin.authorize(**authorize_parameters("CHG0000038"))

    assert verdict(result) == "DENY"
    assert "Unknow error occured" in caplog.text


def verdict(result):
    return result["verdict"]


def additional_metadata(result):
    return result["additional_metadata"]
