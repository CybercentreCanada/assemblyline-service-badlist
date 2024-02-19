# Badlisting service

This service allow you to mark bad a set of files and tags so they always score as malicious in Assemblyline. The content of the badlist is driven by badlist sources or user marked files or IOCs strait from Assemblyline's UI.

## Sources

When adding sources to the service, there are two types of expected data formats

- csv
- json

There are also multiple types of sources for this service:

- blocklist
- malware_family_list
- attribution_list

### Blocklist Data Formats

In order for the service to pull the right IOCs and categorize them per source, you'll have to instruct it on how to using the `config.updater.<source>` key.

Within each `source` map, you'll specify the type of source this is (`blocklist`) as well as set the format (`json` | `csv`).

You'll also have to specify the different IOC types (`domain`, `ip`, `uri`, `md5`, `sha1`, `sha256`, `ssdeep`, `tlsh`) you expect to find in the data and where.

For example if dealing with a CSV file and you expect to find `uri`s in the 3rd column per row:

ie. "`<date>,<name>,https://google.com,...`"

Then your source configuration will look like:

```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: csv
      uri: 2
```

Similarly, if you're dealing with a JSON list (`[{}, {}, ...]`) and you know to find `uri`s under the key `bad_uri` in each record:

ie. `{"bad_uri": "https://google.com", "family": "bad_stuff", ...}`

```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: json
      uri: "bad_uri"
```

You can also override Assemblyline's default scoring of badlist matches (1000 points) by providing a `score` per source.
