import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from badlist.badlist import Badlist


class DummyApi:
    def __init__(self):
        self.tags = None

    def lookup_badlist(self, _):
        return None

    def lookup_badlist_tags(self, tags):
        self.tags = tags
        return []


def _make_service(config):
    service = Badlist.__new__(Badlist)
    service.config = config
    service._api = DummyApi()
    service.get_api_interface = lambda: service._api
    service.source_score_override = {}
    service.similar_api_map = {}
    return service


def _make_request(tags):
    uri_info = SimpleNamespace(uri="http://evil.example/path", hostname="evil.example")
    return SimpleNamespace(
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        file_type="uri/http",
        task=SimpleNamespace(tags=tags, fileinfo=SimpleNamespace(uri_info=uri_info)),
        add_extracted_uri=lambda *_: None,
    )


def test_lookup_flags_disable_ip_domain_url():
    service = _make_service(
        {
            "lookup_sha256": False,
            "lookup_sha1": False,
            "lookup_md5": False,
            "lookup_ssdeep": False,
            "lookup_tlsh": False,
            "lookup_ip": False,
            "lookup_domain": False,
            "lookup_url": False,
        }
    )
    request = _make_request(
        {
            "network.static.ip": ["1.1.1.1"],
            "network.dynamic.ip": ["2.2.2.2"],
            "network.static.domain": ["example.com"],
            "network.dynamic.domain": ["example.org"],
            "network.static.uri": ["http://example.com"],
            "network.dynamic.uri": ["http://example.org"],
            "network.email.address": ["user@example.com"],
        }
    )

    service.execute(request)

    assert "network.static.ip" not in service._api.tags
    assert "network.dynamic.ip" not in service._api.tags
    assert "network.static.domain" not in service._api.tags
    assert "network.dynamic.domain" not in service._api.tags
    assert "network.static.uri" not in service._api.tags
    assert "network.dynamic.uri" not in service._api.tags


def test_filtered_tags_are_used_for_lookup():
    service = _make_service(
        {
            "lookup_sha256": False,
            "lookup_sha1": False,
            "lookup_md5": False,
            "lookup_ssdeep": False,
            "lookup_tlsh": False,
            "lookup_ip": False,
            "lookup_domain": True,
            "lookup_url": False,
        }
    )
    request = _make_request(
        {
            "network.static.domain": ["example.com", "evil.example"],
            "network.dynamic.domain": ["example.com"],
            "network.email.address": ["user@example.com"],
        }
    )

    service.execute(request)

    assert sorted(service._api.tags["network.static.domain"]) == [
        "evil.example"
    ]
    assert service._api.tags["network.dynamic.domain"] == []
