# Analyst1

Publisher: Analyst1 <br>
Connector Version: 1.3.0 <br>
Product Vendor: Analyst1 <br>
Product Name: Analyst1 <br>
Minimum Product Version: 7.0.0

Interact with the Analyst1 API to power SOAR workflows, including indicator lookups, evidence management, and other supported Analyst1 operations.

[Analyst1](https://analyst1.com) is a threat intelligence platform that centralizes indicators,
threat actors, malware, evidence, and sensor taskings. This connector integrates Splunk SOAR with
the Analyst1 REST API so playbooks can enrich observables, manage evidence, and work with sensor
taskings directly from SOAR.

The connector provides:

- Indicator lookups (domain, email, hash, IP, IPv6, URL, mutex, HTTP request, and free-form
  string) against the Analyst1 indicator match API
- Batch checking of indicator values, with the indicator type auto-detected by the API
- Fetching indicators, threat actors, and malware records by their Analyst1 numeric ID
- Evidence management: upload a file from the vault as evidence, poll the upload status, and
  browse or fetch evidence resources
- Sensor support: browse sensors, fetch a sensor's current taskings, download a sensor's
  configuration file to the vault, and diff taskings between config versions

## Authentication

The connector supports two authentication modes, selected by which asset fields are populated:

- **OAuth2 client credentials** — set **client_id** and **client_secret**. The connector requests
  a bearer token from `<base_url>/oauth2/token` and calls the Analyst1 `1_1` REST API.
- **Basic authentication** — set **username** and **password** for a REST-enabled Analyst1
  account. The connector calls the Analyst1 `1_0` REST API.

If both credential pairs are configured, OAuth2 client credentials take precedence.

### Configuration variables

This table lists the configuration variables required to operate Analyst1. These variables are specified when configuring a Analyst1 asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL with no trailing slash (e.g. https://analyst1.customer.com) |
**verify_ssl** | optional | boolean | Require SSL verification |
**client_id** | optional | string | Analyst1 Client ID (Oauth2 authentication) |
**client_secret** | optional | password | Analyst1 Client Secret (Oauth2 authentication) |
**username** | optional | string | Analyst1 Username (Basic authentication for REST-enabled account) |
**password** | optional | password | Analyst1 Password (Basic authentication for REST-enabled account) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Test connectivity to the Analyst1 platform. <br>
[lookup domain](#action-lookup-domain) - Check for the presence of a domain in the Analyst1 platform <br>
[lookup email](#action-lookup-email) - Check for the presence of an email in the Analyst1 platform <br>
[lookup hash](#action-lookup-hash) - Check for the presence of a hash in the Analyst1 platform <br>
[lookup string](#action-lookup-string) - Check for the presence of a string in the Analyst1 platform <br>
[lookup ip](#action-lookup-ip) - Check for the presence of an IP in the Analyst1 platform <br>
[lookup ipv6](#action-lookup-ipv6) - Check for the presence of an IPv6 in the Analyst1 platform <br>
[lookup url](#action-lookup-url) - Check for the presence of a URL in the Analyst1 platform <br>
[lookup mutex](#action-lookup-mutex) - Check for the presence of a mutex in the Analyst1 platform <br>
[lookup http request](#action-lookup-http-request) - Check for the presence of an HTTP request in the Analyst1 platform <br>
[batch check](#action-batch-check) - Check a batch of indicator values (type auto-detected) against the Analyst1 platform <br>
[get indicator by id](#action-get-indicator-by-id) - Fetch an indicator from the Analyst1 platform by its Analyst1 ID <br>
[get actor by id](#action-get-actor-by-id) - Fetch an actor from the Analyst1 platform by its Analyst1 ID <br>
[get malware by id](#action-get-malware-by-id) - Fetch a malware family from the Analyst1 platform by its Analyst1 ID <br>
[upload evidence file](#action-upload-evidence-file) - Upload file from vault to Analyst1 as evidence file <br>
[check evidence status](#action-check-evidence-status) - Check the status of an evidence file upload <br>
[get evidence](#action-get-evidence) - Browse and fetch evidence resources. <br>
[get sensors](#action-get-sensors) - Browse and fetch sensors from the Analyst1 platform <br>
[get sensor taskings](#action-get-sensor-taskings) - Fetch the indicators and rules currently tasked to an Analyst1 sensor <br>
[get sensor config](#action-get-sensor-config) - Fetch an Analyst1 sensor's current configuration file and store it in the vault <br>
[get sensor diff](#action-get-sensor-diff) - Fetch the tasking differences between an Analyst1 sensor config version and the latest version

## action: 'test connectivity'

Test connectivity to the Analyst1 platform.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup domain'

Check for the presence of a domain in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to lookup | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `domain` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup email'

Check for the presence of an email in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | Email to lookup | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email | string | `email` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `email` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup hash'

Check for the presence of a hash in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash to lookup | string | `hash` `sha256` `sha1` `md5` `string` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` `string` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `hash` `sha256` `sha1` `md5` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup string'

Check for the presence of a string in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**string** | required | String to lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.string | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `ip` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ip'

Check for the presence of an IP in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to lookup | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `ip` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup ipv6'

Check for the presence of an IPv6 in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ipv6** | required | IPv6 to lookup | string | `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ipv6 | string | `ipv6` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup url'

Check for the presence of a URL in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to lookup | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | `url` | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup mutex'

Check for the presence of a mutex in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mutex** | required | Mutex to lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.mutex | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup http request'

Check for the presence of an HTTP request in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_request** | required | HTTP request to lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_request | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'batch check'

Check a batch of indicator values (type auto-detected) against the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**values** | required | Comma- or newline-separated indicator values to check; the indicator type of each value is auto-detected. The combined length is limited to 6000 characters (URL length limit); split larger inputs. | string | `ip` `domain` `url` `hash` `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.values | string | `ip` `domain` `url` `hash` `email` | |
action_result.data.\*.searchedValue | string | | |
action_result.data.\*.matchedValue | string | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.entity.key | string | | |
action_result.data.\*.entity.title | string | | |
action_result.data.\*.type.key | string | | |
action_result.data.\*.type.title | string | | |
action_result.data.\*.benign | boolean | | True False |
action_result.data.\*.indicatorRiskScore.key | string | | |
action_result.data.\*.indicatorRiskScore.title | string | | |
action_result.data.\*.actor.\*.id | numeric | | |
action_result.data.\*.actor.\*.title | string | | |
action_result.data.\*.actor.\*.akas.\* | string | | |
action_result.data.\*.malware.\*.id | numeric | | |
action_result.data.\*.malware.\*.title | string | | |
action_result.data.\*.malware.\*.akas.\* | string | | |
action_result.data.\*.system.\*.id | numeric | | |
action_result.data.\*.system.\*.title | string | | |
action_result.data.\*.system.\*.akas.\* | string | | |
action_result.summary.total_values | numeric | | |
action_result.summary.total_results | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get indicator by id'

Fetch an indicator from the Analyst1 platform by its Analyst1 ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator_id** | required | Analyst1 indicator ID (hash indicator IDs may carry a type suffix, e.g. 14131-md5; the suffix is stripped) | string | `analyst1 indicator id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.indicator_id | string | `analyst1 indicator id` | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.activityDates.\*.classification | string | | |
action_result.data.\*.activityDates.\*.date | string | | |
action_result.data.\*.actors.\*.classification | string | | |
action_result.data.\*.actors.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.actors.\*.name | string | | |
action_result.data.\*.actors.\*.link | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.benign.classification | string | | |
action_result.data.\*.benign.value | boolean | | True False |
action_result.data.\*.confidenceLevel.classification | string | | |
action_result.data.\*.confidenceLevel.value | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.domainRegistration.classification | string | | |
action_result.data.\*.domainRegistration.name | string | | |
action_result.data.\*.enrichmentFields.\*.type | string | | |
action_result.data.\*.enrichmentFields.\*.value | string | | |
action_result.data.\*.enrichmentFields.\*.name | string | | |
action_result.data.\*.enrichmentFields.\*.numeric | string | | |
action_result.data.\*.enrichmentFields.\*.classification | string | | |
action_result.data.\*.enrichmentResults.\*.date | string | | |
action_result.data.\*.enrichmentResults.\*.format | string | | |
action_result.data.\*.enrichmentResults.\*.type | string | | |
action_result.data.\*.enrichmentResults.\*.result | string | | |
action_result.data.\*.enrichmentResults.\*.name | string | | |
action_result.data.\*.exploitStage.classification | string | | |
action_result.data.\*.exploitStage.id | numeric | | |
action_result.data.\*.exploitStage.name | string | | |
action_result.data.\*.fileNames.\*.classification | string | | |
action_result.data.\*.fileNames.\*.name | string | | |
action_result.data.\*.fileSize.value | numeric | | |
action_result.data.\*.fileSize.classification | string | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.hashes.\*.type | string | | |
action_result.data.\*.hashes.\*.value | string | | |
action_result.data.\*.hashes.\*.classification | string | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.ipRegistration.classification | string | | |
action_result.data.\*.ipRegistration.name | string | | |
action_result.data.\*.ipResolution.classification | string | | |
action_result.data.\*.ipResolution.name | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.malwares.\*.classification | string | | |
action_result.data.\*.malwares.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malwares.\*.name | string | | |
action_result.data.\*.originatingIps.\*.classification | string | | |
action_result.data.\*.originatingIps.\*.name | string | | |
action_result.data.\*.path.classification | string | | |
action_result.data.\*.path.name | string | | |
action_result.data.\*.ports.\*.value | numeric | | |
action_result.data.\*.ports.\*.classification | string | | |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.reportedDates.\*.classification | string | | |
action_result.data.\*.reportedDates.\*.date | string | | |
action_result.data.\*.requestMethods.\*.classification | string | | |
action_result.data.\*.requestMethods.\*.name | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.subjects.\*.classification | string | | |
action_result.data.\*.subjects.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.tlp | string | | |
action_result.data.\*.tlpCaveats | string | | |
action_result.data.\*.tlpHighestAssociated | string | | |
action_result.data.\*.tlpJustification | string | | |
action_result.data.\*.tlpLowestAssociated | string | | |
action_result.data.\*.tlpResolution | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.value.classification | string | | |
action_result.data.\*.value.name | string | | |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.base_url | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.indicatorRiskScore.classification | string | | |
action_result.data.\*.indicatorRiskScore.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.reportedRange.classification | string | | |
action_result.data.\*.reportedRange.startDate | string | | |
action_result.data.\*.reportedRange.endDate | string | | |
action_result.data.\*.verifiedDateRange.classification | string | | |
action_result.data.\*.verifiedDateRange.startDate | string | | |
action_result.data.\*.verifiedDateRange.endDate | string | | |
action_result.data.\*.sources.\*.id | numeric | | |
action_result.data.\*.sources.\*.type | string | | |
action_result.data.\*.sources.\*.title | string | | |
action_result.data.\*.sources.\*.url | string | | |
action_result.data.\*.sources.\*.category | string | | |
action_result.data.\*.sources.\*.enabled | boolean | | True False |
action_result.data.\*.tags.\*.id | numeric | | |
action_result.data.\*.tags.\*.name | string | | |
action_result.data.\*.externalhitCount | numeric | | |
action_result.data.\*.firstExternalHit | string | | |
action_result.data.\*.lastExternalHit | string | | |
action_result.data.\*.expand | string | | |
action_result.data.\*.indicatorDerivation | string | | |
action_result.data.\*.integrationSources.\* | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.data.\*.verifications.\*.verifier | string | | |
action_result.data.\*.verifications.\*.verifierOrg | string | | |
action_result.data.\*.verifications.\*.verificationDate | string | | |
action_result.data.\*.verifications.\*.evidenceId | numeric | | |
action_result.data.\*.verifications.\*.evidenceTitle | string | | |
action_result.data.\*.hitStatDetails.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.external | boolean | | True False |
action_result.data.\*.hitStatDetails.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimension | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.totalHits | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.id | numeric | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.label | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.firstHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.lastHit | string | | |
action_result.data.\*.hitStatDetails.\*.dimensions.\*.dimensionValues.\*.totalHits | numeric | | |
action_result.summary.id | numeric | | |
action_result.summary.total_objects | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get actor by id'

Fetch an actor from the Analyst1 platform by its Analyst1 ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**actor_id** | required | Analyst1 actor ID | numeric | `analyst1 actor id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.actor_id | numeric | `analyst1 actor id` | |
action_result.data.\*.id | numeric | `analyst1 actor id` | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.title.classification | string | | |
action_result.data.\*.title.name | string | | |
action_result.data.\*.country.classification | string | | |
action_result.data.\*.country.id | numeric | | |
action_result.data.\*.country.name | string | | |
action_result.data.\*.sponsor.classification | string | | |
action_result.data.\*.sponsor.id | numeric | | |
action_result.data.\*.sponsor.name | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.primaryMotivation.classification | string | | |
action_result.data.\*.primaryMotivation.id | numeric | | |
action_result.data.\*.primaryMotivation.name | string | | |
action_result.data.\*.activityRange.classification | string | | |
action_result.data.\*.activityRange.startDate | string | | |
action_result.data.\*.activityRange.endDate | string | | |
action_result.data.\*.campaigns.\*.classification | string | | |
action_result.data.\*.campaigns.\*.id | numeric | | |
action_result.data.\*.campaigns.\*.name | string | | |
action_result.data.\*.attackPatterns.\*.classification | string | | |
action_result.data.\*.attackPatterns.\*.id | numeric | | |
action_result.data.\*.attackPatterns.\*.name | string | | |
action_result.data.\*.targets.\*.classification | string | | |
action_result.data.\*.targets.\*.id | numeric | | |
action_result.data.\*.targets.\*.name | string | | |
action_result.data.\*.akas.\*.classification | string | | |
action_result.data.\*.akas.\*.id | numeric | | |
action_result.data.\*.akas.\*.name | string | | |
action_result.data.\*.malware.\*.classification | string | | |
action_result.data.\*.malware.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.malware.\*.name | string | | |
action_result.data.\*.cves.\*.classification | string | | |
action_result.data.\*.cves.\*.id | numeric | | |
action_result.data.\*.cves.\*.name | string | | |
action_result.data.\*.secondaryMotivations.\*.classification | string | | |
action_result.data.\*.secondaryMotivations.\*.id | numeric | | |
action_result.data.\*.secondaryMotivations.\*.name | string | | |
action_result.data.\*.personalMotivations.\*.classification | string | | |
action_result.data.\*.personalMotivations.\*.id | numeric | | |
action_result.data.\*.personalMotivations.\*.name | string | | |
action_result.summary.id | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get malware by id'

Fetch a malware family from the Analyst1 platform by its Analyst1 ID

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**malware_id** | required | Analyst1 malware ID | numeric | `analyst1 malware id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.malware_id | numeric | `analyst1 malware id` | |
action_result.data.\*.id | numeric | `analyst1 malware id` | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.data.\*.title.classification | string | | |
action_result.data.\*.title.name | string | | |
action_result.data.\*.category.classification | string | | |
action_result.data.\*.category.id | numeric | | |
action_result.data.\*.category.name | string | | |
action_result.data.\*.stage.classification | string | | |
action_result.data.\*.stage.id | numeric | | |
action_result.data.\*.stage.name | string | | |
action_result.data.\*.description.classification | string | | |
action_result.data.\*.description.name | string | | |
action_result.data.\*.akas.\*.classification | string | | |
action_result.data.\*.akas.\*.id | numeric | | |
action_result.data.\*.akas.\*.name | string | | |
action_result.data.\*.stixObjects.\*.id | string | | |
action_result.data.\*.stixObjects.\*.reportingSourceId | numeric | | |
action_result.data.\*.stixObjects.\*.type | string | | |
action_result.summary.id | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'upload evidence file'

Upload file from vault to Analyst1 as evidence file

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Phantom vault ID of file | string | `vault id` |
**evidence_file_classification** | required | The evidence file's classification. Only used if a classification can not be determined during extraction. | string | |
**tlp** | required | The evidence file's traffic light protocol (TLP) designation. Only used if a TLP can not be determined during extraction. | string | |
**source_id** | required | The evidence file's source ID number. | numeric | |
**source_title** | optional | The evidence file's source name. If included, an exact match search will run against Analyst1's Evidence Sources. If a match is found that Source will be assigned this created Evidence. The Name is used second (2nd) in Source discovery order. If no Source discovery method is provided (ID, Name, or URL) then the Source will be 'Unknown' on the Evidence created. | string | |
**source_url** | optional | The evidence file's source URL. If included, all REGEX values defined for Evidence Sources will be compared. If a match is found the Source will be assgined this created Evidence. The URL is used third (3rd) in Source discovery order. If no Source discovery method is provided (ID, Name, or URL) then the Source will be 'Unknown' on the Evidence created. | string | |
**disable_indicator_auto_enrichment** | optional | Influences Indicator automated enrichment during ingest. Default (false) is to allow enrichment. Caller may override and disable automated enrichment. Value ignored if Indicator Auto Enrichment is not enabled in this Analyst1's Admin Controls. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.vault_id | string | `vault id` | |
action_result.parameter.evidence_file_classification | string | | |
action_result.parameter.tlp | string | | |
action_result.parameter.source_id | numeric | | |
action_result.parameter.source_title | string | | |
action_result.parameter.source_url | string | | |
action_result.parameter.disable_indicator_auto_enrichment | boolean | | |
action_result.data.\*.uuid | string | `analyst1 evidence upload key` | |
action_result.summary.uuid | string | `analyst1 evidence upload key` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'check evidence status'

Check the status of an evidence file upload

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**uuid** | required | Evidence upload key | string | `analyst1 evidence upload key` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.uuid | string | `analyst1 evidence upload key` | |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.summary.message | string | | |
action_result.summary.evidence_id | numeric | | |
action_result.summary.id | numeric | `analyst1 evidence id` | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get evidence'

Browse and fetch evidence resources.

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page** | optional | The specific page number to retrieve (1-indexed). If provided, only that single page will be returned. If not provided, all pages will be retrieved up to the specified limit. | numeric | |
**desc_sort** | optional | The sort direction. True for a descending sort, false for a ascending sort. | boolean | |
**sort_by** | optional | The value to sort results on. Allowed values are 'id', 'analyzed', 'indicatorsStatus', 'title', 'tlp', 'type', 'exploitStage', 'attackPattern', 'activityDate', 'reportedDate', & 'assignedTo'. | string | |
**type** | optional | Filter results based on evidence type. Allowed values are 'pcap', 'image', 'pdf', 'txt', 'web', 'incident_04', 'stix', 'caseType', 'spreadsheet', 'doc', 'ppt', 'xml', & 'other'. | string | |
**indicators_verified_date_from** | optional | Filter results based on indicators verified date after (including) this provided date in ISO-8601 format. | string | |
**indicators_verified_date_to** | optional | Filter results based on indicators verified date before (including) this provided date in ISO-8601 format. | string | |
**analyzed_date_from** | optional | Filter results based on analyzed date after (including) this provided date in ISO-8601 format. | string | |
**analyzed_date_to** | optional | Filter results based on analyzed date before (including) this provided date in ISO-8601 format. | string | |
**nominated_for_incident** | optional | Filter results based on Nominated for Incident Response State. | boolean | |
**nominated_for_report** | optional | Filter results based on Nominated for Report State. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.page | numeric | | |
action_result.parameter.desc_sort | boolean | | |
action_result.parameter.sort_by | string | | |
action_result.parameter.type | string | | |
action_result.parameter.indicators_verified_date_from | string | | |
action_result.parameter.indicators_verified_date_to | string | | |
action_result.parameter.analyzed_date_from | string | | |
action_result.parameter.analyzed_date_to | string | | |
action_result.parameter.nominated_for_incident | boolean | | |
action_result.parameter.nominated_for_report | boolean | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get sensors'

Browse and fetch sensors from the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page** | optional | The specific page number to retrieve (1-indexed). If provided, only that single page will be returned. If not provided, all pages will be retrieved up to a 10 page limit. | numeric | |
**page_size** | optional | The number of sensors to return per page. | numeric | |
**type** | optional | Filter results based on sensor type. | string | |
**org** | optional | Filter results based on the sensor's organization ID. | numeric | |
**logical_location** | optional | Filter results based on the sensor's logical location. | string | |
**desc_sort** | optional | The sort direction. True for a descending sort, false for a ascending sort. | boolean | |
**sort_by** | optional | The value to sort results on. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.page | numeric | | |
action_result.parameter.page_size | numeric | | |
action_result.parameter.type | string | | |
action_result.parameter.org | numeric | | |
action_result.parameter.logical_location | string | | |
action_result.parameter.desc_sort | boolean | | |
action_result.parameter.sort_by | string | | |
action_result.data.\*.id | numeric | `analyst1 sensor id` | |
action_result.data.\*.name | string | | |
action_result.data.\*.logicalLocation | string | | |
action_result.data.\*.org.id | numeric | | |
action_result.data.\*.org.name | string | | |
action_result.data.\*.type | string | | |
action_result.data.\*.currentVersionNumber | numeric | | |
action_result.data.\*.latestConfigVersionNumber | numeric | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.summary.total_sensors | numeric | | |
action_result.summary.pages_processed | numeric | | |
action_result.summary.total_pages | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get sensor taskings'

Fetch the indicators and rules currently tasked to an Analyst1 sensor

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor_id** | required | Analyst1 sensor ID | numeric | `analyst1 sensor id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.sensor_id | numeric | `analyst1 sensor id` | |
action_result.data.\*.id | numeric | `analyst1 sensor id` | |
action_result.data.\*.version | numeric | | |
action_result.data.\*.indicators.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.indicators.\*.type | string | | |
action_result.data.\*.indicators.\*.value | string | | |
action_result.data.\*.indicators.\*.classification | string | | |
action_result.data.\*.indicators.\*.fileHashes | string | | |
action_result.data.\*.indicators.\*.links.\*.href | string | `url` | |
action_result.data.\*.indicators.\*.links.\*.rel | string | | |
action_result.data.\*.rules.\*.id | numeric | | |
action_result.data.\*.rules.\*.versionNumber | numeric | | |
action_result.data.\*.rules.\*.signature | string | | |
action_result.data.\*.rules.\*.classification | string | | |
action_result.data.\*.rules.\*.links.\*.href | string | `url` | |
action_result.data.\*.rules.\*.links.\*.rel | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.summary.version | numeric | | |
action_result.summary.indicator_count | numeric | | |
action_result.summary.rule_count | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get sensor config'

Fetch an Analyst1 sensor's current configuration file and store it in the vault

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor_id** | required | Analyst1 sensor ID | numeric | `analyst1 sensor id` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.sensor_id | numeric | `analyst1 sensor id` | |
action_result.data.\*.sensor_id | numeric | `analyst1 sensor id` | |
action_result.data.\*.vault_id | string | `vault id` | |
action_result.data.\*.file_name | string | | |
action_result.data.\*.config_text | string | | |
action_result.summary.vault_id | string | | |
action_result.summary.file_name | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get sensor diff'

Fetch the tasking differences between an Analyst1 sensor config version and the latest version

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor_id** | required | Analyst1 sensor ID | numeric | `analyst1 sensor id` |
**version** | required | The sensor config version to diff against the latest version | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.sensor_id | numeric | `analyst1 sensor id` | |
action_result.parameter.version | numeric | | |
action_result.data.\*.id | numeric | `analyst1 sensor id` | |
action_result.data.\*.version | numeric | | |
action_result.data.\*.latestVersion | numeric | | |
action_result.data.\*.indicatorsAdded.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.indicatorsAdded.\*.type | string | | |
action_result.data.\*.indicatorsAdded.\*.value | string | | |
action_result.data.\*.indicatorsAdded.\*.classification | string | | |
action_result.data.\*.indicatorsAdded.\*.fileHashes | string | | |
action_result.data.\*.indicatorsAdded.\*.links.\*.href | string | `url` | |
action_result.data.\*.indicatorsAdded.\*.links.\*.rel | string | | |
action_result.data.\*.indicatorsRemoved.\*.id | numeric | `analyst1 indicator id` | |
action_result.data.\*.indicatorsRemoved.\*.type | string | | |
action_result.data.\*.indicatorsRemoved.\*.value | string | | |
action_result.data.\*.indicatorsRemoved.\*.classification | string | | |
action_result.data.\*.indicatorsRemoved.\*.fileHashes | string | | |
action_result.data.\*.indicatorsRemoved.\*.links.\*.href | string | `url` | |
action_result.data.\*.indicatorsRemoved.\*.links.\*.rel | string | | |
action_result.data.\*.rulesAdded.\*.id | numeric | | |
action_result.data.\*.rulesAdded.\*.versionNumber | numeric | | |
action_result.data.\*.rulesAdded.\*.signature | string | | |
action_result.data.\*.rulesAdded.\*.classification | string | | |
action_result.data.\*.rulesAdded.\*.links.\*.href | string | `url` | |
action_result.data.\*.rulesAdded.\*.links.\*.rel | string | | |
action_result.data.\*.rulesRemoved.\*.id | numeric | | |
action_result.data.\*.rulesRemoved.\*.versionNumber | numeric | | |
action_result.data.\*.rulesRemoved.\*.signature | string | | |
action_result.data.\*.rulesRemoved.\*.classification | string | | |
action_result.data.\*.rulesRemoved.\*.links.\*.href | string | `url` | |
action_result.data.\*.rulesRemoved.\*.links.\*.rel | string | | |
action_result.data.\*.links.\*.href | string | `url` | |
action_result.data.\*.links.\*.rel | string | | |
action_result.summary.version | numeric | | |
action_result.summary.latest_version | numeric | | |
action_result.summary.indicators_added | numeric | | |
action_result.summary.indicators_removed | numeric | | |
action_result.summary.rules_added | numeric | | |
action_result.summary.rules_removed | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
