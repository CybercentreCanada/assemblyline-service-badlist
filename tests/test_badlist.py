import itertools

import pytest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline.odm.randomizer import random_model_obj
from assemblyline_v4_service.common.api import ServiceAPI
from assemblyline_v4_service.common.request import ServiceRequest, Task

from badlist.badlist import Badlist


class MockServiceAPI(ServiceAPI):
    def __init__(self):
        self.calls = []

    def lookup_badlist(self, qhash):
        self.calls.append(("lookup_badlist", qhash))
        return None

    def lookup_badlist_tags(self, tags):
        self.calls.append(("lookup_badlist_tags", tags))
        return []

    def lookup_badlist_ssdeep(self, ssdeep):
        self.calls.append(("lookup_badlist_ssdeep", ssdeep))
        return []

    def lookup_badlist_tlsh(self, tlsh):
        self.calls.append(("lookup_badlist_tlsh", tlsh))
        return []


class MockService(Badlist):
    # Override the api_interface property to return a mock API that records calls
    @property
    def api_interface(self):
        if not self._api_interface:
            self._api_interface = MockServiceAPI()
        return self._api_interface


@pytest.fixture
def service():
    return MockService()


@pytest.fixture
def service_request():
    task = Task(random_model_obj(ServiceTask))

    # Overwrite the task tags with specific network tags for testing
    task.tags = {
        "network.static.ip": ["0.0.0.0"],
        "network.dynamic.ip": ["0.0.0.0"],
        "network.static.domain": ["example.com"],
        "network.dynamic.domain": ["example.com"],
        "network.static.uri": ["http://example.com"],
        "network.dynamic.uri": ["http://example.com"],
    }

    return ServiceRequest(task)


filelookup_matrix = list(itertools.product(["md5", "sha1", "sha256"], [True, False]))


@pytest.mark.parametrize("hash_type, lookup", filelookup_matrix)
def test_filehash_lookup(service, service_request, hash_type, lookup):
    service.config = {
        f"lookup_{hash_type}": lookup,
    }

    service.execute(service_request)

    # Verify that the lookup_badlist method was called with the correct hash when lookup is enabled
    assert bool(("lookup_badlist", getattr(service_request.task, hash_type)) in service.api_interface.calls) == lookup


@pytest.mark.parametrize("lookup", [True, False], ids=["enabled", "disabled"])
def test_lookup_ssdeep(service, service_request, lookup):

    service.config = {
        "lookup_ssdeep": lookup,
    }

    service.execute(service_request)

    # Verify that the lookup_badlist_ssdeep method was called with the correct hash when lookup is enabled
    assert (
        bool(("lookup_badlist_ssdeep", service_request.task.fileinfo.ssdeep) in service.api_interface.calls) == lookup
    )


@pytest.mark.parametrize("lookup", [True, False], ids=["enabled", "disabled"])
def test_lookup_tlsh(service, service_request, lookup):

    service.config = {
        "lookup_tlsh": lookup,
    }

    service.execute(service_request)

    # Verify that the lookup_badlist_tlsh method was called with the correct hash when lookup is enabled
    assert bool(("lookup_badlist_tlsh", service_request.task.fileinfo.tlsh) in service.api_interface.calls) == lookup


LOOKUP_NETWORK_MATRIX = list(itertools.product(["ip", "domain", "url"], [True, False]))


@pytest.mark.parametrize("network_type, lookup", LOOKUP_NETWORK_MATRIX)
def test_lookup_network_tags(service, service_request, network_type, lookup):

    service.config = {
        f"lookup_{network_type}": lookup,
    }

    service.execute(service_request)

    # We expect the call to be made to perform tag-based lookups to occur only when lookup is enabled
    if lookup:
        call, data = service.api_interface.calls[0]
        assert call == "lookup_badlist_tags"

        # Verify that the correct tags were included in the lookup when lookup is enabled
        for tag_type in ["network.static", "network.dynamic"]:
            assert (
                bool(
                    service_request.task.tags.get(f"{tag_type}.{network_type}", [])
                    == data.get(f"{tag_type}.{network_type}", [])
                )
                == lookup
            )
    else:
        # When lookup is disabled, we expect no tags to be sent in the lookup
        assert service.api_interface.calls == []


@pytest.mark.parametrize("extract_uri", [True, False], ids=["extract", "no_extract"])
def test_extract_uri_param(service, service_request, extract_uri):
    badlisted_uri = "http://evil.example.com"

    # Make the mock API return a badlisted URI tag
    def lookup_badlist_tags(tags):
        service.api_interface.calls.append(("lookup_badlist_tags", tags))
        return [
            {
                "enabled": True,
                "type": "tag",
                "tag": {"type": "network.static.uri", "value": badlisted_uri},
                "added": "2024-01-01T00:00:00Z",
                "updated": "2024-01-01T00:00:00Z",
                "sources": [
                    {
                        "type": "external",
                        "name": "test_source",
                        "reason": ["test reason"],
                        "classification": None,
                    }
                ],
                "attribution": {},
                "classification": None,
            }
        ]

    service.api_interface.lookup_badlist_tags = lookup_badlist_tags

    # Create a task request for scanning a tagged URI that will match in Badlist
    service_request.task.tags = {
        "network.static.uri": [badlisted_uri],
    }
    service_request.task.service_config["extract_uri"] = extract_uri
    service.config = {"lookup_url": True}

    # Execute request
    service.execute(service_request)

    # Depending on the submission parameter, we should get an extracted URI task or none at all
    assert bool(service_request.task.extracted) == extract_uri


def test_email_domain_filter(service, service_request):
    service.config = {
        "lookup_domain": True,
    }

    # Add both email and domain tags to the task,
    # "evil.example" should be looked up
    # "user@example.com" should be looked up
    # "example.com" as a domain might've originated from parsing the email address so it's more likely to be a false positive and should be filtered out of the results
    service_request.task.tags = {
        "network.static.domain": ["example.com", "evil.example"],
        "network.dynamic.domain": ["example.com"],
        "network.email.address": ["user@example.com"],
    }

    service.execute(service_request)

    _, data = service.api_interface.calls[0]

    # "example.com" should be filtered out for domain lookups
    assert "example.com" not in data.get("network.static.domain", [])
    assert "example.com" not in data.get("network.dynamic.domain", [])

    # "evil.example" should be included in the domain lookups
    assert "evil.example" in data.get("network.static.domain", [])

    # "user@example.com" should be included in the email lookups
    assert "user@example.com" in data.get("network.email.address", [])
