
from assemblyline.common import forge
from assemblyline.common.isotime import epoch_to_iso, now
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection

classification = forge.get_classification()


class Badlist(ServiceBase):
    def __init__(self, config=None):
        super(Badlist, self).__init__(config)
        # Default cache timeout invalidates the cache every 30 minutes
        self.timeout = 1800

    def start(self):
        self.timeout = self.config.get('cache_timeout_seconds', self.timeout)

    def get_tool_version(self):
        epoch = now()
        return epoch_to_iso(epoch - (epoch % self.timeout))

    # Utilizes the Badlist API, doesn't need to download files from updater
    def _download_rules(self):
        pass

    def execute(self, request):
        result = Result()

        hashes = []
        if self.config.get('lookup_sha256', False):
            hashes.append(request.sha256)
        if self.config.get('lookup_sha1', False):
            hashes.append(request.sha1)
        if self.config.get('lookup_md5', False):
            hashes.append(request.md5)

        # For the list of hashes I'm supposed to check, check them individually
        for qhash in hashes:
            data = self.api_interface.lookup_badlist(qhash)
            if data and data['enabled'] and data['type'] == "file":
                # Create a section per source
                for source in data['sources']:
                    if source['type'] == 'user':
                        msg = f"User {source['name']} deemed this file as bad for the following reason(s):"
                        heur_id = 2
                    else:
                        msg = f"External badlist source {source['name']} deems this file as bad " \
                            "for the following reason(s):"
                        heur_id = 1

                    result.add_section(
                        ResultSection(
                            msg, heuristic=Heuristic(heur_id, signature=f"BADLIST_{qhash}"),
                            body="\n".join(source['reason']),
                            classification=data.get('classification', classification.UNRESTRICTED)))

        # Check the list of tags as a batch
        badlisted_tags = self.api_interface.lookup_badlist_tags(request.task.tags)
        for badlisted in badlisted_tags:
            if badlisted and badlisted['enabled'] and badlisted['type'] == "tag":
                # Create a section per source
                for source in badlisted['sources']:
                    if source['type'] == 'user':
                        msg = f"User {source['name']} deemed tag '{badlisted['tag']['value']}' as bad " \
                            "for the following reason(s):"
                        heur_id = 4
                    else:
                        msg = f"External badlist source {source['name']} deems  tag '{badlisted['tag']['value']}' " \
                            "as bad for the following reason(s):"
                        heur_id = 3

                    result.add_section(
                        ResultSection(
                            msg, heuristic=Heuristic(heur_id),
                            body="\n".join(source['reason']),
                            classification=badlisted.get(
                                'classification', classification.UNRESTRICTED),
                            tags={badlisted['tag']['type']: badlisted['tag']['value']}))

        request.result = result
