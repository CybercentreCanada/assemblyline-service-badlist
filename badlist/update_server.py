import csv
import json
import re
from copy import deepcopy
from typing import List, Set

from assemblyline.odm.base import (
    DOMAIN_ONLY_REGEX,
    FULL_URI,
    IP_ONLY_REGEX,
    MD5_REGEX,
    SHA1_REGEX,
    SHA256_REGEX,
    SSDEEP_REGEX,
    TLSH_REGEX,
)
from assemblyline_v4_service.updater.updater import ServiceUpdater

IOC_CHECK = {
    "ip": re.compile(IP_ONLY_REGEX).match,
    "domain": re.compile(DOMAIN_ONLY_REGEX).match,
    "uri": re.compile(FULL_URI).match,
    "sha256": re.compile(SHA256_REGEX).match,
    "sha1": re.compile(SHA1_REGEX).match,
    "md5": re.compile(MD5_REGEX).match,
    "ssdeep": re.compile(SSDEEP_REGEX).match,
    "tlsh": re.compile(TLSH_REGEX).match,
    "malware_family": lambda x: True,
}


NETWORK_IOC_TYPES = ["ip", "domain", "uri"]
FILEHASH_TYPES = ["sha256", "sha1", "md5", "ssdeep", "tlsh"]


class SetEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return json.JSONEncoder.default(self, o)


class BadlistUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.malware_families: Set[str] = set()
        self.attributions: Set[str] = set()

    def do_local_update(self):
        ...

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        success = True

        def _trigger_update(source):
            self._current_source = source
            self.set_source_update_time(0)
            self.trigger_update()

        if not self.attributions:
            # Trigger an update for any sources that contribute to attributions list
            [
                _trigger_update(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "attribution_list"
            ]

        if not self.malware_families:
            # Trigger an update for any sources that contribute to the malware families list
            [
                _trigger_update(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "malware_family_list"
            ]

        blocklist_sources = set(
            [
                _s.name
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "blocklist"
            ]
        )

        missing_blocklists = {
            s for s in blocklist_sources if self.datastore.badlist.search(f"sources.name:{s}", rows=0)["total"] == 0
        }

        if missing_blocklists != blocklist_sources:
            # We have at least one blocklist source to work with for the time being
            success = True

        # Trigger an update for the blocklists that are missing
        [_trigger_update(source) for source in missing_blocklists]

        return success

    def import_update(self, files_sha256, al_client, source_name, default_classification):
        def sanitize_data(data: str, type: str, validate=True) -> List[str]:
            if not data:
                return []

            # Normalize data (parsing based off Malpedia API output)
            data = data.split(".", 1)[-1]
            data = data.replace("-", "").replace("_", "").replace("#", "").replace('"', "").upper()
            data = data.split(",") if "," in data else [data]

            if not validate:
                return data

            if type == "malware_family":
                return [d for d in data if d in self.malware_families]
            elif type == "attribution":
                return [d for d in data if d in self.attributions]

        def update_blocklist(
            ioc_type: str,
            ioc_value: str,
            malware_family: List[str],
            attribution: List[str],
            references: List[str],
            bl_type: str,
        ):
            def prepare_item(bl_item):
                # See if there's any attribution details we can add to the item before adding to the list
                attr = source_cfg.get("default_attribution", {})
                if malware_family:
                    attr["family"] = list(set(malware_family))

                if attribution:
                    attr["actor"] = list(set(attribution))

                bl_item["attribution"] = attr

            references = [r for r in references if re.match(FULL_URI, r)]
            badlist_items = []

            # Normalize IOC values for when performing lookups
            ioc_value = ioc_value.lower()

            # Build item for badlist
            badlist_item_base = {
                "classification": default_classification,
                "sources": [
                    {
                        "classification": default_classification,
                        "name": source_name,
                        "reason": ["IOC was reported by source as malicious"] + references,
                        "type": "external",
                    }
                ],
            }

            if bl_type == "tag":
                if ioc_type in NETWORK_IOC_TYPES:
                    # Tag applies to both static and dynamic
                    for network_type in ["static", "dynamic"]:
                        badlist_item = deepcopy(badlist_item_base)
                        badlist_item.update(
                            {
                                "type": "tag",
                                "tag": {"type": f"network.{network_type}.{ioc_type}", "value": ioc_value},
                            }
                        )
                        badlist_items.append(badlist_item)
            elif bl_type == "file":
                # Set hash information
                badlist_item = deepcopy(badlist_item_base)
                badlist_item.update(
                    {
                        "type": "file",
                        "hashes": {ioc_type: ioc_value},
                    }
                )
                badlist_items.append(badlist_item)

            [prepare_item(bl_item) for bl_item in badlist_items]
            al_client.badlist.add_update_many(badlist_items)

        source_cfg = self._service.config["updater"][source_name]

        if source_cfg["type"] == "blocklist":
            # This source is meant to contribute to the blocklist
            ignore_terms = source_cfg.get("ignore_terms", [])
            if source_cfg["format"] == "csv":
                start_index = source_cfg.get("start", 0)
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        for row in list(csv.reader(fp, delimiter=","))[start_index:]:
                            if not row:
                                # If no data in row, skip
                                continue
                            row = [r.strip(' "') for r in row]
                            joined_row = ",".join(row)
                            if any(t in joined_row for t in ignore_terms) or joined_row.startswith("#"):
                                # Skip row
                                continue

                            references = [] if not source_cfg.get("reference") else [row[source_cfg["reference"]]]
                            # Get malware family
                            malware_family = (
                                sanitize_data(row[source_cfg["malware_family"]], type="malware_family")
                                if source_cfg.get("malware_family")
                                else []
                            )

                            # Get attribution
                            attribution = (
                                sanitize_data(row[source_cfg["attribution"]], type="attribution")
                                if source_cfg.get("attribution")
                                else []
                            )

                            # Iterate over all IOC types
                            for ioc_type in NETWORK_IOC_TYPES + FILEHASH_TYPES:
                                if source_cfg.get(ioc_type) is None:
                                    continue
                                ioc_value = row[source_cfg[ioc_type]]

                                if ioc_type == "ip":
                                    # Ensure port information is not included
                                    ioc_value = ioc_value.split(":", 1)[0]

                                # If there are multiple IOC types in the same column, verify the IOC type
                                if not IOC_CHECK[ioc_type](ioc_value):
                                    continue
                                update_blocklist(
                                    ioc_type,
                                    ioc_value,
                                    malware_family,
                                    attribution,
                                    references,
                                    bl_type="tag" if ioc_type in NETWORK_IOC_TYPES else "file",
                                )

            elif source_cfg["format"] == "json":
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        blocklist_data = json.load(fp)
                        if isinstance(blocklist_data, list):
                            for data in blocklist_data:
                                json_dump = json.dumps(data)
                                if any(t in json_dump for t in ignore_terms):
                                    # Skip block
                                    continue
                                references = (
                                    [] if not source_cfg.get("reference") else [data.get(source_cfg.get("reference"))]
                                )
                                malware_family = sanitize_data(
                                    data.get(source_cfg.get("malware_family")), type="malware_family"
                                )

                                # Get attribution
                                attribution = sanitize_data(data.get(source_cfg.get("attribution")), type="attribution")

                                for ioc_type in NETWORK_IOC_TYPES + FILEHASH_TYPES:
                                    ioc_value = data.get(source_cfg.get(ioc_type))
                                    if ioc_value:
                                        update_blocklist(
                                            ioc_type,
                                            ioc_value,
                                            malware_family,
                                            attribution,
                                            references,
                                            bl_type="tag" if ioc_type in NETWORK_IOC_TYPES else "file",
                                        )

        elif source_cfg["type"] == "malware_family_list":
            # This source is meant to contributes to the list of valid malware families
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series of malware family names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    with open(file, "r") as fp:
                        for malware_family in json.load(fp):
                            self.malware_families = self.malware_families.union(
                                set(
                                    sanitize_data(
                                        malware_family,
                                        type="malware_family",
                                        validate=False,
                                    )
                                )
                            )
        elif source_cfg["type"] == "attribution_list":
            # This source is meant to contributes to the list of valid attribution names
            if source_cfg["format"] == "list":
                # Expect a flat list containing a series of attribution names
                for file, _ in files_sha256:
                    # Add normalized family names to list
                    with open(file, "r") as fp:
                        # Let's assume no sanitization is required and just merge the set of names
                        self.attributions = self.attributions.union(
                            set(
                                sanitize_data(
                                    ",".join(json.load(fp)),
                                    type="attribution",
                                    validate=False,
                                )
                            )
                        )


if __name__ == "__main__":
    with BadlistUpdateServer() as server:
        server.serve_forever()
