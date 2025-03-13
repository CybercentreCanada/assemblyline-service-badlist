from collections import defaultdict

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultOrderedKeyValueSection,
    ResultSection,
)

from assemblyline.common import forge
from assemblyline.common.isotime import epoch_to_iso, now
from assemblyline.common.net import is_valid_ip

classification = forge.get_classification()


class Badlist(ServiceBase):
    def __init__(self, config=None):
        super(Badlist, self).__init__(config)
        # Default cache timeout invalidates the cache every 30 minutes
        self.timeout = 1800
        self.similar_api_map = {
            "ssdeep": self.api_interface.lookup_badlist_ssdeep,
            "tlsh": self.api_interface.lookup_badlist_tlsh,
        }

        # This is a map that allows us to override the default badlist scoring by source
        self.source_score_override = {
            source_name: int(config["score"])
            for source_name, config in self.config.get("updater", {}).items()
            if config.get("type") == "blocklist" and config.get("score")
        }

    def start(self):
        self.timeout = self.config.get("cache_timeout_seconds", self.timeout)

    def get_tool_version(self):
        epoch = now()
        return epoch_to_iso(epoch - (epoch % self.timeout))

    # Utilizes the Badlist API, doesn't need to download files from updater
    def _download_rules(self):
        pass

    def execute(self, request):
        result = Result()

        similar_hash_types = []
        hashes = []
        if self.config.get("lookup_sha256", False):
            hashes.append(request.sha256)
        if self.config.get("lookup_sha1", False):
            hashes.append(request.sha1)
        if self.config.get("lookup_md5", False):
            hashes.append(request.md5)

        if self.config.get("lookup_ssdeep", False):
            similar_hash_types.append("ssdeep")
        if self.config.get("lookup_tlsh", False):
            similar_hash_types.append("tlsh")

        # For the list of hashes I'm supposed to check, check them individually
        for qhash in hashes:
            data = self.api_interface.lookup_badlist(qhash)
            if data and data["enabled"] and data["type"] == "file":
                # Create the bad section
                bad_file_section = ResultSection(
                    f"{qhash} hash was found in the list of bad files",
                    heuristic=Heuristic(1),
                    classification=data.get("classification", classification.UNRESTRICTED),
                )

                # Add attribution tags
                attributions = data.get("attribution", {}) or {}
                for tag_type, values in attributions.items():
                    if values:
                        for v in values:
                            bad_file_section.add_tag(f"attribution.{tag_type}", v)

                # Create a sub-section per source
                for source in data["sources"]:
                    if source["type"] == "user":
                        msg = f"User {source['name']} deemed this file as bad for the following reason(s):"
                    else:
                        msg = (
                            f"External badlist source {source['name']} deems this file as bad "
                            "for the following reason(s):"
                        )

                    bad_file_section.add_subsection(
                        ResultSection(
                            msg,
                            body="\n".join(source["reason"]),
                            classification=source.get("classification", classification.UNRESTRICTED),
                        )
                    )

                # Add the bad file section to the results
                result.add_section(bad_file_section)

        # Add the uri file type data as potential tags to check
        tags = request.task.tags
        for net_type in ["ip", "domain", "uri"]:
            tags.setdefault(f"network.static.{net_type}", [])
            tags.setdefault(f"network.dynamic.{net_type}", [])
        if request.file_type.startswith("uri/") and request.task.fileinfo.uri_info:
            tags["network.static.uri"].append(request.task.fileinfo.uri_info.uri)

            if is_valid_ip(request.task.fileinfo.uri_info.hostname):
                net_type = "ip"
            else:
                net_type = "domain"

            tags[f"network.static.{net_type}"].append(request.task.fileinfo.uri_info.hostname)

        # Filter out email domains from network domains before checking blocklist for hits
        email_domains = set([x.split("@", 1)[1] for x in tags.get("network.email.address", [])])
        tags["network.static.domain"] = list(set(tags["network.static.domain"]) - email_domains)
        tags["network.dynamic.domain"] = list(set(tags["network.dynamic.domain"]) - email_domains)

        # Check the list of tags as a batch
        badlisted_tags = self.api_interface.lookup_badlist_tags(request.task.tags)
        for badlisted in badlisted_tags:
            if badlisted and badlisted["enabled"] and badlisted["type"] == "tag" and \
                badlisted["tag"]["value"] in tags[badlisted["tag"]["type"]]:
                # Create the bad section
                bad_ioc_section = ResultSection(badlisted["tag"]["value"])

                # Create a metadata body
                metadata_body = {
                    "IOC Type": badlisted["tag"]["type"],
                    "IOC Value": badlisted["tag"]["value"],
                    "First added": badlisted["added"],
                    "Last updated": badlisted["updated"],
                }

                # Add attribution tags
                attributions = badlisted.get("attribution", {}) or {}
                for tag_type, values in attributions.items():
                    if values:
                        for v in values:
                            bad_ioc_section.add_tag(f"attribution.{tag_type}", v)
                        # Add any values that will be tagged in the metadata body
                        metadata_body[tag_type] = values

                # Add metadata section to parent
                bad_ioc_section.add_subsection(
                    ResultOrderedKeyValueSection(
                        title_text="Metadata",
                        body=metadata_body,
                        classification=badlisted.get("classification", classification.UNRESTRICTED),
                        tags={badlisted["tag"]["type"]: [badlisted["tag"]["value"]]},
                    )
                )

                # Create a sub-section per source
                for source in badlisted["sources"]:
                    signatures = {}
                    if source["type"] == "user":
                        msg = f"User '{source['name']}' deemed the tag as bad"
                    else:
                        signatures[source["name"]] = 1
                        msg = f"External source '{source['name']}' deems the tag as bad"

                    source_classfication = source.pop("classification", classification.UNRESTRICTED)
                    bad_ioc_section.add_subsection(
                        ResultOrderedKeyValueSection(
                            msg,
                            body=source,
                            classification=source_classfication,
                            heuristic=Heuristic(2, score_map=self.source_score_override, signatures=signatures),
                            tags={badlisted["tag"]["type"]: [badlisted["tag"]["value"]]},
                        )
                    )

                # Add the bad IOC section to the results
                result.add_section(bad_ioc_section)

                # If this is a URI and we have confidence that it is bad, extract as an extracted file
                if badlisted["tag"]["type"].endswith("uri"):
                    request.add_extracted_uri("URI found in badlist", badlisted["tag"]["value"])

        # Check for similarity hashes ssdeep
        for hash_type in similar_hash_types:
            similar_hashes = self.similar_api_map[hash_type](request.task.fileinfo[hash_type])
            for similar in similar_hashes:
                if (
                    similar
                    and similar["enabled"]
                    and similar["type"] == "file"
                    and similar["hashes"]["sha256"] != request.sha256
                ):

                    # Create the similar section
                    similar_section = ResultOrderedKeyValueSection(
                        f"{hash_type.upper()} similarity match: A similar file in the system matches this file",
                        heuristic=Heuristic(3),
                        classification=similar.get("classification", classification.UNRESTRICTED),
                    )
                    similar_section.add_item("md5", similar["hashes"].get("md5", None))
                    similar_section.add_item("sha1", similar["hashes"].get("sha1", None))
                    similar_section.add_item("sha256", similar["hashes"].get("sha256", None))
                    similar_section.add_item("ssdeep", similar["hashes"].get("ssdeep", None))
                    similar_section.add_item("tlsh", similar["hashes"].get("tlsh", None))
                    similar_section.add_item("size", similar["file"].get("size", None))
                    similar_section.add_item("type", similar["file"].get("type", None))

                    # Add attribution tags
                    attributions = similar.get("attribution", {}) or {}
                    for tag_type, values in attributions.items():
                        if values:
                            for v in values:
                                similar_section.add_tag(f"attribution.{tag_type}", v)

                    # Create a sub-section per source
                    for source in similar["sources"]:
                        if source["type"] == "user":
                            msg = f"User {source['name']} deemed a similar file as bad for the following reason(s):"
                        else:
                            msg = (
                                f"External badlist source {source['name']} deems a similar file as bad "
                                "for the following reason(s):"
                            )

                        similar_section.add_subsection(
                            ResultSection(
                                msg,
                                body="\n".join(source["reason"]),
                                classification=similar.get("classification", classification.UNRESTRICTED),
                            )
                        )

                    # Add similar section to the result
                    result.add_section(similar_section)

        request.result = result
