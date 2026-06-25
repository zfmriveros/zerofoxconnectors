# File: zerofoxthreatintelligence_connector.py
#
# Copyright (c) ZeroFox, 2024-2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import base64
import json
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantom_rules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

from zerofoxthreatintelligence_consts import ZEROFOX_API_URL


KEY_INCIDENT_CONTAINER_LABEL = "ZeroFOX Key Incident"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATE_TIME_FORMAT_ALTERNATIVE = "%Y-%m-%dT%H:%M:%SZ"


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


@dataclass
class KeyIncident:
    analysis: str
    created_at: datetime
    updated_at: datetime
    headline: str
    incident_id: str
    risk_level: str
    solution: str
    tags: list[str]
    threat_types: list[str]
    title: str
    url: str
    attachments: list[str]

    def to_dict(self):
        new_dict = asdict(self)
        new_dict["created_at"] = self.created_at.strftime(DATE_TIME_FORMAT)
        new_dict["updated_at"] = self.updated_at.strftime(DATE_TIME_FORMAT)
        return new_dict


@dataclass
class KeyIncidentAttachment:
    content: str
    mime_type: str
    name: str
    created_at: str

    def to_dict(self):
        return asdict(self)


@dataclass
class SplunkContainer:
    label: str
    name: str
    source_data_identifier: str
    description: str
    status: str
    sensitivity: str
    severity: str
    start_time: str
    end_time: str
    hash: str
    tags: list[str]
    threat_types: list[str]
    title: str
    ingest_app_id: str
    data: dict

    def to_dict(self):
        return asdict(self)


class KeyIncidentsMapper:
    def __init__(self, app_id, container_label):
        self.app_id = app_id
        self._container_label = container_label

    def prepare_container(self, key_incident: KeyIncident) -> SplunkContainer:
        container = SplunkContainer(
            label=self._container_label,
            name=f"ZeroFOX Key Incident: {key_incident.incident_id}" + (f"- {key_incident.headline}" if key_incident.headline else ""),
            description=key_incident.analysis,
            severity=key_incident.risk_level.lower() if key_incident.risk_level != "Unknown" else "Medium",
            start_time=key_incident.created_at.strftime(DATE_TIME_FORMAT),
            end_time=key_incident.updated_at.strftime(DATE_TIME_FORMAT),
            sensitivity="white",
            status="new",
            source_data_identifier=key_incident.incident_id,
            data=key_incident.to_dict(),
            hash=key_incident.incident_id,
            tags=key_incident.tags,
            threat_types=key_incident.threat_types,
            title=key_incident.title,
            ingest_app_id=self.app_id,
        )
        return container

    def _convert_datetime_string_to_datetime(self, date_string):
        try:
            return datetime.strptime(date_string, DATE_TIME_FORMAT)
        except ValueError:
            return datetime.strptime(date_string, DATE_TIME_FORMAT_ALTERNATIVE)

    def dict_to_key_incident(self, incident_dict) -> KeyIncident:
        """Convert a dictionary to a KeyIncident object."""
        # Parse datetime strings to datetime objects
        created_at = self._convert_datetime_string_to_datetime(incident_dict.get("created_at"))
        updated_at = self._convert_datetime_string_to_datetime(incident_dict.get("updated_at"))

        # Create KeyIncident object
        key_incident = KeyIncident(
            analysis=incident_dict.get("analysis", ""),
            created_at=created_at,
            updated_at=updated_at,
            headline=incident_dict.get("headline", ""),
            incident_id=incident_dict.get("incident_id", ""),
            risk_level=incident_dict.get("risk_level", ""),
            solution=incident_dict.get("solution", ""),
            tags=incident_dict.get("tags", []),
            threat_types=incident_dict.get("threat_types", []),
            title=incident_dict.get("title", ""),
            url=incident_dict.get("url", ""),
            attachments=incident_dict.get("attachments", []),
        )

        return key_incident


class ZerofoxThreatIntelligenceConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None

        self._base_url = ZEROFOX_API_URL
        self._access_token = None
        self.mapper = None

    def _get_cti_headers(self):
        access_token = self._handle_get_token()

        return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "zf-source": "Splunk-SOAR"}

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {e}",
                ),
                None,
            )

        if 200 <= r.status_code < 399:
            self.debug_print("RETURNING JSON")
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {} Data from server: {}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        self.debug_print("RETURNING ERROR")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately
        if "json" in r.headers.get("Content-Type", ""):
            self.debug_print("processing json")
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            self.debug_print("processing html")
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            self.debug_print("processing empty")
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        """
        **kwargs can be any additional parameters that requests.request accepts
        """

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        self.debug_print(f"URL={url}")
        self.debug_print(f"kwargs={kwargs}")

        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), **kwargs)

            self.debug_print(f"r={r}")

        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Details: {e}",
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.debug_print("Testing Access Token...")
        self.debug_print(f"username={self._username}")

        params = {"username": self._username, "password": self._password}

        endpoint = "/auth/token/"

        url = ZEROFOX_API_URL + endpoint

        self.save_progress("Connecting to endpoint")

        self.debug_print(f"url={url}")

        ret_val, _ = self._make_rest_call("/auth/token/", action_result, method="post", json=params, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_ingestion_daterange(self, param):
        """
        Extract Phantom start time and end time as datetime objects.
        Divide by 1000 to resolve milliseconds.

        :param param: dict
        :return: start_time, end_time
        """
        try:
            start_time_param = float(param.get("start_time"))
            end_time_param = float(param.get("end_time"))
        except TypeError:
            self.error_print("start time or end time not specified")
            return None, None

        return datetime.fromtimestamp(start_time_param / 1000.0), datetime.fromtimestamp(end_time_param / 1000.0)

    def _handle_get_token(self):
        """
        Checks if the provided ZeroFOX API token is valid

        :return: bool
        """
        if self._access_token:
            return self._access_token

        self.debug_print("Fetching Access Token...")
        self.debug_print(f"username={self._username}")

        headers = None

        params = {"username": self._username, "password": self._password}

        endpoint = "/auth/token/"

        url = ZEROFOX_API_URL + endpoint
        response = requests.post(url, headers=headers, json=params)

        self.debug_print(f"url={url}")

        self.debug_print(f"response: {response}")
        self.debug_print(f"validate_api_token status: {response.status_code}")

        if response.status_code == 200:
            json_data = response.json()
            self._access_token = json_data["access"]
            return json_data["access"]
        else:
            return None

    def _handle_lookup_domain(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain_name = param["domain"]
        headers = self._get_cti_headers()

        domain_endpoints = ["c2-domains", "phishing"]
        total_results = 0
        for ep in domain_endpoints:
            if ep == "c2-domains":
                endpoint = f"/cti/c2-domains/?domain={domain_name}"
            elif ep == "phishing":
                endpoint = f"/cti/phishing/?domain={domain_name}"
            else:
                continue

            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")

            total_results = total_results + len(response["results"])
            matches = response.get("results", [])

            for match in matches:
                if ep == "c2-domains":
                    match["created_at"] = match.pop("created_at")
                    match["details"] = match.pop("tags")
                    match["ip"] = match["ip_addresses"][0]

                elif ep == "phishing":
                    match["created_at"] = match.pop("scanned")
                    match["ip"] = match["host"]["ip"]
                    match["details"] = match.pop("cert")

                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"

        action_result.update_summary(summary)
        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_email(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        email_address = param["email_address"]
        headers = self._get_cti_headers()

        email_endpoints = ["email-addresses", "compromised-credentials"]
        total_results = 0
        for ep in email_endpoints:
            if ep == "email-addresses":
                endpoint = f"/cti/email-addresses/?email={email_address}"
            elif ep == "compromised-credentials":
                endpoint = f"/cti/compromised-credentials/?email={email_address}"
            else:
                continue

            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")

            total_results = total_results + len(response["results"])
            matches = response.get("results", [])

            for match in matches:
                self.debug_print(f"match: {len(match)}")
                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"
        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_address = param["ip"]
        headers = self._get_cti_headers()

        ip_endpoints = ["botnet", "disruption", "phishing"]
        total_results = 0
        for ep in ip_endpoints:
            if ep == "botnet":
                endpoint = f"/cti/botnet/?ip_address={ip_address}"
            elif ep == "disruption":
                endpoint = f"/cti/disruption/?ip={ip_address}"
            elif ep == "phishing":
                endpoint = f"/cti/phishing/?host_ip={ip_address}"
            else:
                continue

            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print(f"response: {response}")
            self.debug_print(f"len: {len(response['results'])}")

            total_results = total_results + len(response["results"])

            matches = response.get("results", [])

            for match in matches:
                self.debug_print(f"match: {len(match)}")
                self.debug_print(f"type match: {type(match)}")

                if ep == "botnet":
                    match["created_at"] = match.pop("listed_at")
                    match["threat_type"] = "botnet"

                elif ep == "phishing":
                    match["created_at"] = match.pop("scanned")
                    match["threat_type"] = "phishing"

                action_result.add_data(match)

        summary = action_result.update_summary({})
        summary["total_objects"] = total_results
        summary["status"] = "success"
        summary["message"] = f"{total_results} results found"
        action_result.update_summary(summary)

        self.save_progress("success")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        the_hash = param["hash"]

        if len(the_hash) == 32:
            hash_type = "md5"
        elif len(the_hash) == 40:
            hash_type = "sha1"
        elif len(the_hash) == 64:
            hash_type = "sha256"
        elif len(the_hash) == 128:
            hash_type = "sha512"
        else:
            self.save_progress("Unrecognized hash length")
            return action_result.set_status(phantom.APP_ERROR, "Unrecognized hash length")

        headers = self._get_cti_headers()

        endpoint = f"/cti/malware/?{hash_type}={the_hash}"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        matches = response.get("results", [])

        for match in matches:
            action_result.add_data(match)

        self.debug_print(f"response: {response}")
        self.debug_print(f"len: {len(response['results'])}")

        summary = action_result.update_summary({})

        summary["total_objects"] = len(response["results"])
        summary["status"] = "success"
        summary["message"] = f"{len(response['results'])} results found"

        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_exploit(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        self.debug_print(f"Param: {param}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        the_cve = param["cve"]

        headers = self._get_cti_headers()

        endpoint = f"/cti/exploits/?cve={the_cve}"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        matches = response.get("results", [])

        for match in matches:
            action_result.add_data(match)

        self.debug_print(f"response: {response}")
        self.debug_print(f"len: {len(response['results'])}")

        summary = action_result.update_summary({})
        summary["total_objects"] = len(response["results"])
        summary["status"] = "success"
        summary["message"] = f"{len(response['results'])} results found"

        action_result.update_summary(summary)

        self.save_progress("success")

        return action_result.set_status(phantom.APP_SUCCESS)

    def __parse_file_content(self, data_uri):
        header_data_match = re.match(r"data:(.*?);base64,(.+)", data_uri)
        if not header_data_match:
            raise ValueError("Invalid data URL format")
        mime_type, data = header_data_match.groups()

        return mime_type, data

    def _extract_attachment_id(self, url) -> str:
        return url.split("/")[-2]

    def _get_cursor(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        cursor = query_params.get("cursor", [None])[0]
        return cursor

    def _get_key_incident_attachment(self, action_result, attachment_id) -> KeyIncidentAttachment:
        headers = self._get_cti_headers()
        endpoint = f"/cti/key-incident-attachment/{attachment_id}/"
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        mime_type, content = self.__parse_file_content(response.get("content"))

        return KeyIncidentAttachment(content=content, mime_type=mime_type, name=response["name"], created_at=response["created_at"])

    def get_key_incidents(self, action_result, start_time=None, end_time=None):
        ki_count = 0
        headers = self._get_cti_headers()
        endpoint = "/cti/key-incidents/"
        params = {
            "ordering": "update",
            "tags": "Key Incident",
        }
        if start_time:
            params["updated_after"] = start_time
        if end_time:
            params["updated_before"] = end_time

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params, headers=headers)

        for ki in response["results"]:
            ki_count += 1
            yield self.mapper.dict_to_key_incident(ki)

        if phantom.is_fail(ret_val):
            return None, action_result.get_status()

        self.debug_print("ki_count", ki_count)
        next_page_count = 0
        while next_page := response.get("next"):
            next_page_count += 1
            headers = self._get_cti_headers()
            self.debug_print(f"Processing next page: {response['next']}")
            self.debug_print(f"next_page_count: {next_page_count}")
            # Extract just the endpoint part by removing the base URL
            cursor = self._get_cursor(next_page)
            params.update(cursor=cursor)
            self.debug_print(f"cursor: {cursor}")
            ret_val, response = self._make_rest_call(endpoint, action_result, params=params, headers=headers)
            self.debug_print(f"ret_val: {ret_val}")

            if phantom.is_fail(ret_val):
                return None, action_result.get_status()
            for ki in response["results"]:
                ki_count += 1
                yield self.mapper.dict_to_key_incident(ki)
        self.debug_print(f"ki_count: {ki_count}")
        self.debug_print("No next page")

    def handle_action(self, param):
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())
        self.debug_print(f"Ingesting handle action in: {param}")
        action = {
            "test_connectivity": self._handle_test_connectivity,
            "lookup_email": self._handle_lookup_email,
            "lookup_ip": self._handle_lookup_ip,
            "lookup_hash": self._handle_lookup_hash,
            "lookup_domain": self._handle_lookup_domain,
            "lookup_exploit": self._handle_lookup_exploit,
            "on_poll": self._on_poll,
        }.get(action_id, None)

        ret_val = action(param=param) if action else phantom.APP_SUCCESS

        return ret_val

    def _create_tmp_attachment_file(self, ki_attachment: KeyIncidentAttachment) -> str:
        self.debug_print("CREATING KEY INCIDENT ATTACHMENT FILE")
        file_content = base64.b64decode(ki_attachment.content)
        with tempfile.NamedTemporaryFile(mode="wb", dir=Vault.get_vault_tmp_dir(), delete=False) as f:
            tmp_file_path = f.name
            self.debug_print(f"file_path: {tmp_file_path}")
            f.write(file_content)

        return tmp_file_path

    def _upload_key_incident_attachment(self, container_id: int, ki_attachment: KeyIncidentAttachment):
        file_path = self._create_tmp_attachment_file(ki_attachment)
        self.debug_print("UPLOAD KEY INCIDENT ATTACHMENT")

        success, message, _ = phantom_rules.vault_add(
            container=container_id, file_location=file_path, file_name=ki_attachment.name, metadata={"mime_type": ki_attachment.mime_type}
        )
        self.debug_print(f"success: {success}")
        self.debug_print(f"message: {message}")

    def _save_key_incident(self, key_incident):
        self.debug_print("PREPARE KEY INCIDENT CONTAINER")

        container = self.mapper.prepare_container(key_incident)
        self.debug_print(f"container: {container}")

        status, message, container_id = self.save_container(container.to_dict())

        if status == phantom.APP_SUCCESS and message != "Duplicate container found":
            self.save_progress("Created the key incident `successfully`")
            return status, message, container_id
        else:
            return status, message, container_id

    def _process_and_save_key_incident(self, ki, action_result, num_processed) -> tuple[bool, str, int]:
        ki_id = ki.incident_id

        self.debug_print(f"key incident id: {ki_id}")

        status, message, container_id = self._save_key_incident(ki)

        for ki_attachment in ki.attachments:
            ki_attachment_id = self._extract_attachment_id(ki_attachment["url"])
            ki_attachment = self._get_key_incident_attachment(action_result, ki_attachment_id)
            self.debug_print(f"ki_attachment file name: {ki_attachment.name}")
            self._upload_key_incident_attachment(container_id, ki_attachment)

        if status == phantom.APP_SUCCESS:
            num_processed = num_processed + 1
            self.save_progress(f"ZeroFOX Key Incident {ki_id} ingested ({num_processed})")
        else:
            self.error_print(f"Did not ingest key incident {ki_id}")
        return status, message, num_processed

    def _on_poll(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print("ON POLL CONNECTOR")

        start_time, end_time = self._get_ingestion_daterange(param)

        if start_time is None or end_time is None:
            return action_result.set_status(phantom.APP_ERROR, message="start time or end time not specified")

        if self.is_poll_now():
            self.save_progress("Starting Key Incident manual ingestion ")
            history_date = datetime.now(timezone.utc) - timedelta(int(self._key_incident_poll_interval))
            poll_start_time = history_date
            poll_end_time = datetime.now(timezone.utc)

        elif param.get("historical_poll"):
            self.save_progress("Starting Key Incident historical poll")
            poll_start_time = start_time
            poll_end_time = end_time

        else:
            self.save_progress("Starting Key Incident scheduled ingestion")
            poll_end_time = end_time
            try:
                last_polled = self._state.get("last_polled")
                if last_polled:
                    self.debug_print(f"Using last_polled time: {last_polled}")
                    poll_start_time = datetime.strptime(last_polled, "%Y-%m-%dT%H:%M:%S")
                else:
                    self.debug_print(f"Using fallback start_time: {start_time}")
                    poll_start_time = datetime.now(timezone.utc) - timedelta(int(self._key_incident_poll_interval))

            except (ValueError, TypeError, AttributeError) as e:
                self.debug_print(f"Error processing last_polled time: {e!s}")
                poll_start_time = start_time
                self.debug_print(f"Using fallback start_time: {start_time}")

        self.save_progress(f"Polling from {poll_start_time} to {poll_end_time}")
        ki_total = 0
        num_processed = 0
        for ki in self.get_key_incidents(action_result, poll_start_time, poll_end_time):
            ki_total += 1
            status, message, num_processed = self._process_and_save_key_incident(ki, action_result, num_processed)
            if status != phantom.APP_SUCCESS:
                action_result.set_status(phantom.APP_ERROR, message)
                self.add_action_result(action_result)
                return action_result.get_status()

        # Update last_polled time in state
        if ki_total > 0:
            self._state["last_polled"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            self.debug_print(f"Updated last_polled state to: {self._state['last_polled']}")

        if ki_total == 0:
            self.save_progress("No key incidents found")
            return action_result.set_status(phantom.APP_SUCCESS)

        self.debug_print(f"Total incidents processed: {ki_total}")
        return action_result.set_status(phantom.APP_SUCCESS)

    def initialize(self):
        self._state = self.load_state()

        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = ZEROFOX_API_URL

        self._username = config.get("zerofox_username")
        self._password = config.get("zerofox_password")
        self._key_incident_poll_interval = config.get("key_incident_poll_interval")
        self._container_label = config["ingest"]["container_label"]
        self.mapper = KeyIncidentsMapper(self.get_app_id(), self._container_label)

        self.debug_print("INITIALIZE")
        self.debug_print(f"username={self._username}")

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = f"{ZerofoxThreatIntelligenceConnector._get_phantom_base_url()}/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e}")
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ZerofoxThreatIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
