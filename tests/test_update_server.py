import os
import threading
from collections import UserDict
from queue import Queue
from types import SimpleNamespace
from unittest import mock

import pytest

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

from assemblyline_v4_service.updater.updater import SOURCE_STATUS_KEY

from badlist.update_server import BadlistUpdateServer


class FakeHash(UserDict):
    def set(self, key, value):
        self[key] = value


@pytest.fixture
def updater():
    server = BadlistUpdateServer.__new__(BadlistUpdateServer)
    server.attributions = {"actor"}
    server.malware_families = {"family"}
    server.update_data_hash = FakeHash()
    server.update_queue = Queue()
    server.source_update_flag = threading.Event()
    server.datastore = mock.Mock()
    server.datastore.badlist.facet.return_value = {"present": 1}

    def configure(*sources):
        server._service = SimpleNamespace(
            update_config=SimpleNamespace(
                sources=[SimpleNamespace(name=name, enabled=enabled) for name, enabled in sources]
            ),
            config={"updater": {name: {"type": "blocklist"} for name, _ in sources}},
        )
        return server

    return configure


def set_state(server, source, state):
    server.update_data_hash.set(f"{source}.{SOURCE_STATUS_KEY}", {"state": state, "message": ""})


def queued(server):
    return [server.update_queue.get() for _ in range(server.update_queue.qsize())]


def test_inventory_check_passes_with_present_blocklist(updater):
    server = updater(("present", True))
    set_state(server, "present", "DONE")

    assert server._inventory_check()
    assert not queued(server) and not server.source_update_flag.is_set()


def test_inventory_check_retasks_missing_blocklists(updater):
    server = updater(("present", True), ("missing", True))
    set_state(server, "missing", "DONE")

    server._inventory_check()

    assert queued(server) == ["missing"]
    assert server.source_update_flag.is_set()


def test_inventory_check_queues_never_attempted_blocklists(updater):
    server = updater(("present", True), ("new", True))

    server._inventory_check()

    assert queued(server) == ["new"]
    assert server.source_update_flag.is_set()


def test_inventory_check_ignores_disabled_blocklists(updater):
    server = updater(("present", True), ("disabled", False))
    set_state(server, "disabled", "DONE")

    server._inventory_check()

    assert not queued(server) and not server.source_update_flag.is_set()


def test_inventory_check_ignores_errored_blocklists(updater):
    server = updater(("present", True), ("failing", True))
    set_state(server, "failing", "ERROR")

    server._inventory_check()

    assert not queued(server) and not server.source_update_flag.is_set()


def test_inventory_check_skips_when_update_already_pending(updater):
    server = updater(("present", True), ("missing", True))
    set_state(server, "missing", "DONE")
    server.source_update_flag.set()

    server._inventory_check()

    assert not queued(server)
