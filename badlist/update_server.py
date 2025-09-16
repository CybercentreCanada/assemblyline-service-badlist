import csv
import json
import re
from copy import deepcopy
from queue import Queue
from typing import List, Set

from assemblyline.common.isotime import iso_to_epoch, now
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
HOSTS_FILE_REGEX = re.compile(r"0\.0\.0\.0\s(.+)")


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
        self.update_queue = Queue()

    def do_local_update(self): ...

    # A sanity check to make sure we do in fact have things to send to services
    def _inventory_check(self) -> bool:
        success = True
        if not self.attributions:
            # Queue an update for any sources that contribute to attributions list
            [
                self.update_queue.put(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"]
                == "attribution_list"
            ]

        if not self.malware_families:
            # Queue an update for any sources that contribute to the malware families list
            [
                self.update_queue.put(_s.name)
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"]
                == "malware_family_list"
            ]

        blocklist_sources = set(
            [
                _s.name
                for _s in self._service.update_config.sources
                if self._service.config["updater"][_s.name]["type"] == "blocklist"
            ]
        )

        missing_blocklists = blocklist_sources - set(
            self.datastore.badlist.facet(
                "sources.name",
                "sources.type:external",
                size=len(self._service.update_config.sources),
            ).keys()
        )

        if missing_blocklists != blocklist_sources:
            # We have at least one blocklist source to work with for the time being
            success = True

        # Trigger an update for the blocklists that are missing
        if missing_blocklists:
            [self.update_queue.put(source) for source in missing_blocklists]
            self.trigger_update()

        return success

    def import_update(
        self, files_sha256, source_name, default_classification, configuration
    ):
        blocklist_batch = []

        def sanitize_data(data: str, type: str, validate=True) -> List[str]:
            if not data:
                return []

            # Normalize data (parsing based off Malpedia API output)
            data = data.split(".", 1)[-1]
            data = (
                data.replace("-", "")
                .replace("_", "")
                .replace("#", "")
                .replace('"', "")
                .upper()
            )
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
            bl_type: str,
            malware_family: List[str] = [],
            attribution: List[str] = [],
            campaign: List[str] = [],
            references: List[str] = [],
        ):
            def prepare_item(bl_item):
                # See if there's any attribution details we can add to the item before adding to the list
                attr = source_cfg.get("default_attribution", {})
                if malware_family:
                    attr["family"] = list(set(malware_family))

                if attribution:
                    attr["actor"] = list(set(attribution))

                if campaign:
                    attr["campaign"] = list(set(campaign))

                bl_item["attribution"] = attr

                # Optionally set an expiration DTL based on the source
                if source_cfg.get("dtl"):
                    # Check if your computed expiry time will be greater than the one set already
                    new_expiry_ts = now(float(source_cfg["dtl"]) * 24 * 3600)
                    qhash = self.client.badlist._preprocess_object(bl_item)
                    ds_item = self.client.datastore.badlist.get_if_exists(
                        qhash, as_obj=False
                    )
                    # If the item doesn't exist, doesn't have an expiry, or will expire sooner than what's configured by the source
                    if (
                        not ds_item
                        or ds_item.get("expiry_ts") is None
                        or (
                            ds_item.get("expiry_ts")
                            and iso_to_epoch(ds_item["expiry_ts"]) < new_expiry_ts
                        )
                    ):
                        # Set the DTL based on the configured value for the source
                        bl_item["dtl"] = int(source_cfg["dtl"])

            references = [r for r in references if re.match(FULL_URI, r)]
            badlist_items = []

            # Build item for badlist
            badlist_item_base = {
                "classification": default_classification,
                "sources": [
                    {
                        "classification": default_classification,
                        "name": source_name,
                        "reason": ["IOC was reported by source as malicious"]
                        + references,
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
                                "tag": {
                                    "type": f"network.{network_type}.{ioc_type}",
                                    "value": ioc_value,
                                },
                            }
                        )
                        badlist_items.append(badlist_item)
            elif bl_type == "file":
                # Set hash information
                badlist_item = deepcopy(badlist_item_base)
                badlist_item.update(
                    {
                        "type": "file",
                        "hashes": {ioc_type: ioc_value.lower()},
                    }
                )
                badlist_items.append(badlist_item)

            [prepare_item(bl_item) for bl_item in badlist_items]
            blocklist_batch.extend(badlist_items)

        try:
            source_cfg = configuration
        except KeyError as exc:
            raise ValueError(
                f"Source '{source_name}' not found in the service configuration"
            ) from exc

        if source_cfg["type"] == "blocklist":
            # This source is meant to contribute to the blocklist
            ignore_terms = source_cfg.get("ignore_terms", [])
            if source_cfg["format"] == "hosts":
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        for match in re.finditer(HOSTS_FILE_REGEX, fp.read()):
                            update_blocklist("domain", match.group(1), bl_type="tag")
            elif source_cfg["format"] == "csv":
                start_index = source_cfg.get("start", 0)
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        for row in list(
                            csv.reader(fp, delimiter=source_cfg.get("delimiter", ","))
                        )[start_index:]:
                            if not row:
                                # If no data in row, skip
                                continue
                            row = [r.strip(' "') for r in row]
                            joined_row = ",".join(row)
                            if any(
                                t in joined_row for t in ignore_terms
                            ) or joined_row.startswith("#"):
                                # Skip row
                                continue

                            references = (
                                []
                                if source_cfg.get("reference") is None
                                or source_cfg["reference"] >= len(row)
                                else [row[source_cfg["reference"]]]
                            )
                            # Get malware family
                            malware_family = (
                                sanitize_data(
                                    row[source_cfg["malware_family"]],
                                    type="malware_family",
                                )
                                if source_cfg.get("malware_family") is not None
                                else []
                            )

                            # Get attribution
                            attribution = (
                                sanitize_data(
                                    row[source_cfg["attribution"]], type="attribution"
                                )
                                if source_cfg.get("attribution") is not None
                                else []
                            )

                            campaign = (
                                sanitize_data(
                                    row[source_cfg["campaign"]],
                                    type="campaign",
                                    validate=False,
                                )
                                if source_cfg.get("campaign") is not None
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

                                if ioc_type in NETWORK_IOC_TYPES:
                                    # Ensure IOC is defanged before performing validation checks
                                    ioc_value = ioc_value.replace("[.]", ".")

                                # If there are multiple IOC types in the same column, verify the IOC type
                                if not IOC_CHECK[ioc_type](ioc_value):
                                    continue
                                # Doubly make sure this isn't an IP
                                if ioc_type == "domain" and IOC_CHECK["ip"](ioc_value):
                                    continue

                                update_blocklist(
                                    ioc_type,
                                    ioc_value,
                                    "tag" if ioc_type in NETWORK_IOC_TYPES else "file",
                                    malware_family,
                                    attribution,
                                    campaign,
                                    references,
                                )
            elif source_cfg["format"] == "json":
                for file, _ in files_sha256:
                    with open(file, "r") as fp:
                        blocklist_data = json.load(fp)
                        if isinstance(blocklist_data, list):
                            for data in blocklist_data:
                                if isinstance(data, dict):
                                    # Structured data
                                    json_dump = json.dumps(data)
                                    if any(t in json_dump for t in ignore_terms):
                                        # Skip block
                                        continue
                                    references = (
                                        []
                                        if not source_cfg.get("reference")
                                        else [data.get(source_cfg.get("reference"))]
                                    )
                                    malware_family = sanitize_data(
                                        data.get(source_cfg.get("malware_family")),
                                        type="malware_family",
                                    )

                                    # Get attribution
                                    attribution = sanitize_data(
                                        data.get(source_cfg.get("attribution")),
                                        type="attribution",
                                    )

                                    campaign = sanitize_data(
                                        data.get(source_cfg.get("campaign")),
                                        type="campaign",
                                        validate=False,
                                    )

                                    for ioc_type in NETWORK_IOC_TYPES + FILEHASH_TYPES:
                                        ioc_value = data.get(source_cfg.get(ioc_type))
                                        if ioc_value:
                                            update_blocklist(
                                                ioc_type,
                                                ioc_value,
                                                "tag"
                                                if ioc_type in NETWORK_IOC_TYPES
                                                else "file",
                                                malware_family,
                                                attribution,
                                                campaign,
                                                references,
                                            )
                                elif isinstance(data, str):
                                    # Simple list of strings
                                    for ioc_type in NETWORK_IOC_TYPES + FILEHASH_TYPES:
                                        if IOC_CHECK[ioc_type](data):
                                            update_blocklist(
                                                ioc_type,
                                                data,
                                                "tag"
                                                if ioc_type in NETWORK_IOC_TYPES
                                                else "file",
                                            )

            if blocklist_batch:
                self.client.badlist.add_update_many(blocklist_batch)

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
