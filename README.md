[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_badlist-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-badlist)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-badlist)](./LICENSE)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-badlist)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-badlist)

# Badlist Service

This service interfaces with Assemblyline's Badlist to mark tags or files as malicious.

## Service Details

### Sources

When adding sources to the service, there are two types of expected data formats

- csv
- json

There are also multiple types of sources for this service:

- blocklist
- malware_family_list
- attribution_list

#### Blocklist Data Formats

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

#### Automated Expiration

By default, we assume that all the items added to the Badlist will be valid forever but that's not always the cases.
You will also be able to set a DTL (Days to Live) period for items that belong to a source using `dtl`.

If there are multiple sources with DTLs configured that raise an item, then the expiry date will be extended by the sum of the DTL values at the time of importing.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Badlist \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-badlist

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Badlist

Ce service s'interface avec Badlist d'Assemblyline pour marquer les balises ou les fichiers comme malveillants.

## Détails du Service
### Sources
Lors de l'ajout de sources au service, il existe deux types de formats de données attendus
- csv
- json

Il existe également plusieurs types de sources pour ce service :
 - liste de blocage
 - liste de familles de logiciels malveillants
 - liste d'attribution

#### Formats de Données de la Liste de Blocage
Pour que le service puisse extraire les bons IOCs et les catégoriser par source, vous devrez lui indiquer comment le faire en utilisant la clé `config.updater.<source>`. 

Dans chaque carte `source`, vous spécifierez le type de source (blocklist) ainsi que le format (`json` | `csv`).

Vous devrez également spécifier les différents types d'IOC (`domain`, `ip`, `uri`, `md5`, `sha1`, `sha256`, `ssdeep`, `tlsh`) que vous vous attendez à trouver dans les données et où.

Par exemple, si vous traitez un fichier CSV et que vous vous attendez à trouver des `uri` dans la 3ème colonne par ligne: 

par exemple "`<date>,<nom>,https://google.com,...`"

Alors votre configuration de source ressemblera à ceci :
```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: csv
      uri: 2
```
De même, si vous traitez une liste JSON (`[{}, {}, ...]`) et que vous savez trouver des `uri` sous la clé `bad_uri` dans chaque enregistrement : 

par exemple `{"bad_uri": "https://google.com", "family": "bad_stuff", ...}`

```yaml
config:
  updater:
    my_source:
      type: blocklist
      format: json
      uri: "bad_uri"
```
Vous pouvez également remplacer le score par défaut d'Assemblyline pour les correspondances de la liste noire (1000 points) en fournissant un `score` par source.

#### Expiration Automatisée
Par défaut, nous supposons que tous les éléments ajoutés à la liste noire seront valides pour toujours, mais ce n'est pas toujours le cas. Vous pourrez également définir une période de DTL (jours à vivre) pour les éléments appartenant à une source en utilisant `dtl`. 

S'il y a plusieurs sources avec des DTL configurés qui élèvent un élément, alors la date d'expiration sera prolongée de la somme des valeurs de DTL au moment de l'importation.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Il s'agit d'un service d'Assemblyline. Il est optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Badlist \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-badlist

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
