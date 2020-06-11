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

import logging
import pytest
from textwrap import dedent

logger = logging.getLogger("spsservicenow_conftest")


@pytest.fixture
def snow_instance(site_parameters):
    return site_parameters["instance"]


@pytest.fixture
def snow_user(site_parameters):
    return site_parameters["user"]


@pytest.fixture
def snow_password(site_parameters):
    return site_parameters["password"]


@pytest.fixture
def mapped_user_id(site_parameters):
    return site_parameters["mapped_user_id"]


@pytest.fixture
def plugin_config(snow_instance, snow_user, snow_password, mapped_user_id):
    return dedent(
        """
        [service_now]
        instance={instance}
        user={user}
        password={password}

        [service_now_ticket_patterns]
        change=CHG.*

        [change]
        table=change_request
        query=active=true^approval=approved^assigned_to=$username^number=$ticket_id

        [auth]
        prompt=Provide ServiceNow request id:

        [usermapping source=explicit]
        gwuser={mapped_user_id}
        """.format(
            instance=snow_instance,
            user=snow_user,
            password=snow_password,
            mapped_user_id=mapped_user_id
        )
    )


@pytest.fixture
def plugin_config_custom_host(mapped_user_id):
    def config(instance):
        return dedent(
            """
            [service_now]
            instance={instance}
            user=admin
            password=passwd

            [service_now_ticket_patterns]
            change=CHG.*

            [change]
            table=change_request
            query=active=true^approval=approved^assigned_to=$username^number=$ticket_id

            [auth]
            prompt=Provide ServiceNow request id:

            [usermapping source=explicit]
            gwuser={mapped_user_id}

            [logging]
            log_level=debug
            """.format(
                instance=instance,
                mapped_user_id=mapped_user_id
            )
        )
    return config
