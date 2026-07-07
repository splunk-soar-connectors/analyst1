# Analyst1

Publisher: Analyst1 <br>
Connector Version: 2.0.0 <br>
Product Vendor: Analyst1 <br>
Product Name: Analyst1 <br>
Minimum Product Version: 7.0.0

This app implements investigative actions on the Analyst1 platform

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
[upload evidence file](#action-upload-evidence-file) - Upload file from vault to Analyst1 as evidence file <br>
[check evidence status](#action-check-evidence-status) - Check the status of an evidence file upload <br>
[get evidence](#action-get-evidence) - Browse and fetch evidence resources.

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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup hash'

Check for the presence of a hash in the Analyst1 platform

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash to lookup | string | `hash` `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.hash | string | `hash` `sha256` `sha1` `md5` | |
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
action_result.data.\*.found | boolean | | True False |
action_result.data.\*.message | string | | |
action_result.data.\*.id | numeric | | |
action_result.data.\*.type | string | | |
action_result.data.\*.active | boolean | | True False |
action_result.data.\*.verified | boolean | | True False |
action_result.data.\*.tasked | boolean | | True False |
action_result.data.\*.reportCount | numeric | | |
action_result.data.\*.hitCount | numeric | | |
action_result.data.\*.firstHit | string | | |
action_result.data.\*.lastHit | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.tlp | string | | |
action_result.data.\*.base_url | string | | |
action_result.data.\*.indicator_value | string | | |
action_result.data.\*.raw_data | string | | |
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
**evidence_file_classification** | required | The evidence file's classification. | string | |
**tlp** | required | The evidence file's TLP designation. | string | |
**source_id** | optional | The evidence file's source ID number. | numeric | |
**source_title** | optional | The evidence file's source name. | string | |
**source_url** | optional | The evidence file's source URL. | string | |
**disable_indicator_auto_enrichment** | optional | Disable automated enrichment during ingest. | boolean | |

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
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get evidence'

Browse and fetch evidence resources.

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**page** | optional | The specific page number to retrieve (1-indexed). Use 0 for all pages. | numeric | |
**desc_sort** | optional | Sort direction. True for descending, false for ascending. | boolean | |
**sort_by** | optional | The value to sort results on. | string | |
**evidence_type** | optional | Filter results based on evidence type. Leave empty for all types. | string | |
**indicators_verified_date_from** | optional | Filter by indicators verified date from (ISO-8601). | string | |
**indicators_verified_date_to** | optional | Filter by indicators verified date to (ISO-8601). | string | |
**analyzed_date_from** | optional | Filter by analyzed date from (ISO-8601). | string | |
**analyzed_date_to** | optional | Filter by analyzed date to (ISO-8601). | string | |
**nominated_for_incident** | optional | Filter by Nominated for Incident Response State. | boolean | |
**nominated_for_report** | optional | Filter by Nominated for Report State. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.page | numeric | | |
action_result.parameter.desc_sort | boolean | | |
action_result.parameter.sort_by | string | | |
action_result.parameter.evidence_type | string | | |
action_result.parameter.indicators_verified_date_from | string | | |
action_result.parameter.indicators_verified_date_to | string | | |
action_result.parameter.analyzed_date_from | string | | |
action_result.parameter.analyzed_date_to | string | | |
action_result.parameter.nominated_for_incident | boolean | | |
action_result.parameter.nominated_for_report | boolean | | |
action_result.data.\*.evidence_json | string | | |
action_result.data.\*.total_retrieved | numeric | | |
action_result.data.\*.pages_processed | numeric | | |
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
