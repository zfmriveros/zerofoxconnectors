# ZeroFox Threat Intelligence

Publisher: ZeroFox <br>
Connector Version: 1.2.1 <br>
Product Vendor: ZeroFox <br>
Product Name: ZeroFox Threat Intelligence <br>
Minimum Product Version: 6.1.0

ZeroFox Threat Intelligence

### Configuration variables

This table lists the configuration variables required to operate ZeroFox Threat Intelligence. These variables are specified when configuring a ZeroFox Threat Intelligence asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**zerofox_username** | optional | string | ZeroFox CTI Username |
**zerofox_password** | optional | password | ZeroFox CTI Password |
**key_incident_poll_interval** | optional | string | Initial historical alert poll interval (in days) |
**verify_server_cert** | optional | boolean | Verify Sever Certificate |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[lookup domain](#action-lookup-domain) - Check for the presence of a domain in the ZeroFox Threat Intelligence Feed <br>
[lookup ip](#action-lookup-ip) - Check for the presence of an IP in the ZeroFox Threat Intelligence Feed <br>
[lookup exploit](#action-lookup-exploit) - Check for the presence of a exploit in the ZeroFox Threat Intelligence Feed <br>
[lookup hash](#action-lookup-hash) - Check for the presence of a hash in the ZeroFox Threat Intelligence Feed <br>
[lookup email](#action-lookup-email) - Lookup Email Address <br>
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup domain'

Check for the presence of a domain in the ZeroFox Threat Intelligence Feed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to lookup | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string | `domain` | test.com |
action_result.data.\*.ip | string | `ip` | |
action_result.data.\*.url | string | `url` | |
action_result.data.\*.details | string | | |
action_result.data.\*.created_at | string | | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup ip'

Check for the presence of an IP in the ZeroFox Threat Intelligence Feed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to lookup | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string | `ip` | 8.8.8.8 |
action_result.data.\*.url | string | `url` | |
action_result.data.\*.threat_type | string | | |
action_result.data.\*.created_at | string | | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup exploit'

Check for the presence of a exploit in the ZeroFox Threat Intelligence Feed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve** | required | CVE to lookup | string | `cve` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.cve | string | `cve` | |
action_result.data.\*.url | string | `url` | |
action_result.data.\*.created_at | string | | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup hash'

Check for the presence of a hash in the ZeroFox Threat Intelligence Feed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** | required | Hash to lookup | string | `sha256` `sha1` `md5` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.hash | string | `sha256` `sha1` `md5` | |
action_result.data.\*.family | string | | |
action_result.data.\*.created_at | string | | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup email'

Lookup Email Address

Type: **investigate** <br>
Read only: **True**

Check for the presence of an email address in the ZeroFox Threat Intelligence Feed.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** | required | Email Address | string | `email` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.email_address | string | `email` | |
action_result.data.\*.domain | string | `domain` | |
action_result.data.\*.breach_name | string | | |
action_result.data.\*.created_at | string | | |
action_result.status | string | | success failed |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'on poll'

Callback action for the on_poll ingest functionality

Type: **ingest** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds) | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds) | numeric | |
**historical_poll** | optional | Historical poll | boolean | |

#### Action Output

No Output

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
