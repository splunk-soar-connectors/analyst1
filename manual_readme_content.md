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
