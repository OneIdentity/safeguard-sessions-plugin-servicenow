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


import re
from string import Template

from requests.exceptions import HTTPError

from pysnow.exceptions import ResponseError
from safeguard.sessions.plugin import AAPlugin, AAResponse

from .client import ServiceNowClient
from .wrap import Filter


class Plugin(AAPlugin):
    ERROR_MESSAGE_TEMPLATE = "Error from ServiceNow. Error: {error}, details: {details}"
    DENY_REASON_TEMPLATE = "Verfifying ServiceNow request with id: {ticket_id} failed"

    def _extract_mfa_password(self):
        if "tkt" in self.connection.key_value_pairs:
            return self.connection.key_value_pairs["tkt"]
        return super()._extract_mfa_password()

    def do_authorize(self):
        # If instance is not defined in the config, host is required. If both are defined, instance
        # takes precedence.
        ticket_id = self.mfa_password

        ticket_type_section = self._determine_section(ticket_id)
        if not ticket_type_section:
            return AAResponse.deny("Ticket ID doesn't match any patterns; ticket_id={}".format(ticket_id))

        table = self.plugin_configuration.get(ticket_type_section, "table", required=True).strip()
        templ = self.plugin_configuration.get(ticket_type_section, "query", required=True).strip()

        self.logger.debug("ServiceNow query template: {}".format(templ))
        query = Template(templ).substitute(Filter(self.connection), ticket_id=ticket_id, username=self.mfa_identity)
        self.logger.debug("ServiceNow query: {}".format(query))

        try:
            resource = ServiceNowClient.from_config(self.plugin_configuration).get_resource("/table/{}".format(table))
            response = resource.get(query=query, stream=True)
            result = response.first_or_none()
        except HTTPError as e:
            self.logger.debug(self.ERROR_MESSAGE_TEMPLATE.format(error=str(e), details=""))
            return AAResponse.deny(reason=self.DENY_REASON_TEMPLATE.format(ticket_id=ticket_id))
        except ResponseError as e:
            self.logger.debug(self.ERROR_MESSAGE_TEMPLATE.format(error=e.message, details=e.detail))
            return AAResponse.deny(reason=self.DENY_REASON_TEMPLATE.format(ticket_id=ticket_id))
        except Exception as e:
            self.logger.debug("Unknow error occured. Cannot verify ServiceNow request: {}".format(str(e)))
            return AAResponse.deny(reason=self.DENY_REASON_TEMPLATE.format(ticket_id=ticket_id))

        if result:
            self._update_service_now_ticket(resource, ticket_id)
            return AAResponse.accept(reason="Verified ServiceNow request: {}".format(ticket_id))
        else:
            return AAResponse.deny(
                reason="Ticket verification failed. No ServiceNow request matched by the provided query")

    def _determine_section(self, ticket_id, patterns_section="service_now_ticket_patterns"):
        for option in self.plugin_configuration.get_options(patterns_section):
            pattern = self.plugin_configuration.get(patterns_section, option).strip()
            if re.match(pattern, ticket_id, flags=re.I):
                return option

    def _update_service_now_ticket(self, resource, ticket_id):
        self.logger.info("Updating Service Now request with id: {}".format(ticket_id))
        try:
            update_payload = {"close_notes": "SPS session id: {}".format(self.connection.session_id)}
            resource.update(query={"number": ticket_id}, payload=update_payload)
        except HTTPError:
            self.logger.debug("Unable to update Service Now request with id: {}".format(ticket_id))
