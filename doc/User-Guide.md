# Input Settings

Each Input defined in OverSight is used to generate knowledge objects and a scheduled save search.  This save search then populates a KV Store with the details you define.

If you use the checkbox to indicate the Input is an `Inventory Source`, then the records from the KV Store are aggregated into the aggregation lookup.

The latest version of this document can always be found at https://github.com/nasa/Oversight


# App Configuration Settings

Below are the settings available within the OverSight Technical Add-on.

### Logging Options

#### Log level

*Default value: INFO*

This is used by the custom python scripts to set the logging verbosity:

input_module_oversight - modular input custom script
update_inventory - custom alert action
expire_inventory - custom alert action

### Add-on Settings

You may wish to adjust these names to better reflect the type of information you wish to produce aggregated inventory lookups for.  The defaults are designed for IT asset inventory information.

#### Aggregated lookup name

*Default value: hosts_lookup*

Name of the transform knowledge object tied to the aggregated collection.
This lookup is used to provide a summary view of inventory data across all user defined inputs.

#### Aggregated collection name

*Default value: hosts_collection*

Name of the KV Store collection used for summary inventory records.

#### Time Format String 

*Default value: %Y-%m-%d %H:%M*

The desired time format to normalize records with.
This format string is used for the `eval_last_inventoried` macro.
It is also used to compare time strings and determine which is most recent.

#### Unique ID Fieldname 

*Default value: ip*

This fieldname is used in the `aggregated lookup` as the key field.

#### Multi-value ID Fieldname 

*Default value: ip_addresses*

This fieldname is used in the `aggregated lookup` as a related, multi-value ID field.

#### Last Inventoried Fieldname 

*Default value: last_inventoried*

This fieldname is used in the `aggregated lookup` as well as the `lookup` for each input defined.

#### First Inventoried Fieldname

*Default value: first_inventoried*

This fieldname is used in the `aggregated_lookup` to track when an inventory item has first been observed.

#### Expiration Expression

*Default value: None*

You may provide a search term to be applied against the `aggregated_lookup`; matching records will be automatically expired.  Remember to use the `search` term in your expression, i.e.:
`search ip=10.*`
will automatically expire any records with IP address of 10.*

### Asset Groups

Asset Groups are used to calculate the Gap Analysis of assets, indicating which input event sources defined a particular inventory item is expected to be observed in.

As an example, if you are tracking counts of items in stock across numerous stores, you might not expect clothing items to be observed from the systems at a grocery store.

An Asset Group also defines the set of Inputs which must have the same unique ID value to identify a host.
In example, you cannot mix an input with a unique ID field of IP and other input with a unique ID field of MAC address, and expect them to correlate as a single asset.

For each asset group you can set the number of days after which any unseen records are expired.

You can provide the names of up to three asset groups.
Asset groups are then used when defining Inputs.
If an Input does not specify an asset group, it uses `default`.


# Additional FAQ

## The multi-value key features or Asset Group don't apply to me, can I disable them?

You can remove the `ip_addresses` or `asset_group` field manually from the `aggregated lookup` definition.

## How can I define an Input that uses a multi-value ID field correctly?

OverSight expects one event per unique identifier.  If an event has two multi-value keys, there should be two records populated in the lookup table.  Both records would be identical except for the Unique ID field.

## How does the multi-value ID feature work?

OverSight understands that events defined as using a multi-value key may have either the full listing of all possible keys, or only a partial listing.

As an example, consider a typical IT on-premise data center.

A host typically forwards syslog information using only a single management IP address.
An agent installed on a system may be capable of detecting the interface IP addresses configured on the host.
A management system may have manual notes of associated IP addresses which are not configured directly on the host.

OverSight can manage this scenario both as records are aggregated into the aggregation lookup.
As records are expired, those entries are removed from the set of multi-value keys for the host.

### Multi-Value ID example

`| inputlookup mgmt_lookup`
| ip | ip_addresses | agent_version | last_inventoried | expired |
|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-01-01 01:00 | false |
| 2.2.2.2 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-01-01 01:00 | false |
| 3.3.3.3 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-01-01 01:00 | false |
| 4.4.4.4 | | 2.1 | 2021-01-01 | false

`| inputlookup hosts_lookup`
| ip | ip_addresses | first_inventoried | last_inventoried | mgmt_last_inventoried | expired | asset_group |
|---|---|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-01-01 01:00 | 2021-01-01 01:00 | false | default |
| 2.2.2.2 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-01-01 01:00 | 2021-01-01 01:00 | false | default |
| 3.3.3.3 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-01-01 01:00 | 2021-01-01 01:00 | false | default |
| 4.4.4.4 | | 2021-01-01 01:00 | 2021-01-01 01:00 | 2021-01-01 01:00 | false | default |


*Fast Forward 31 Days*
IP address 2.2.2.2 has not been observed within the past 31 days ... perhaps it was disabled in preparation for re-assignment.

`| inputlookup mgmt_lookup`
| ip | ip_addresses | agent_version | last_inventoried | expired |
|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-02-01 06:00 | false |
| 2.2.2.2 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-01-01 01:00 | false |
| 3.3.3.3 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-02-01 06:00 | false |
| 4.4.4.4 | | 2.1 | 2021-02-01 04:28 | false


`| inputlookup hosts_lookup`
| ip | ip_addresses | first_inventoried | last_inventoried | mgmt_last_inventoried | expired | asset_group |
|---|---|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-02-01 06:00 | 2021-02-01 06:00 | false | default |
| 2.2.2.2 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-01-01 01:00 | 2021-01-01 01:00 | false | default |
| 3.3.3.3 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2021-01-01 01:00 | 2021-02-01 06:00 | 2021-02-01 06:00 | false | default |
| 4.4.4.4 | | 2021-01-01 01:00 | 2021-02-01 04:28 | 2021-02-01 04:28 | false | default |

*Fast Forward until next execution of `expire_inventory` saved search*


`| inputlookup mgmt_lookup`
| ip | ip_addresses | agent_version | last_inventoried | expired |
|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-02-01 06:00 | false |
| 3.3.3.3 | 1.1.1.1 2.2.2.2 3.3.3.3 | 2.3 | 2021-02-01 06:00 | false |
| 4.4.4.4 | | 2.1 | 2021-02-01 04:28 | false


`| inputlookup hosts_lookup`
| ip | ip_addresses | first_inventoried | last_inventoried | mgmt_last_inventoried | expired | asset_group |
|---|---|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 3.3.3.3 | 2021-01-01 01:00 | 2021-02-01 06:00 | 2021-02-01 06:00 | false | default |
| 3.3.3.3 | 1.1.1.1 3.3.3.3 | 2021-01-01 01:00 | 2021-02-01 06:00 | 2021-02-01 06:00 | false | default |
| 4.4.4.4 | | 2021-01-01 01:00 | 2021-02-01 04:28 | 2021-02-01 04:28 | false | default |

The expired key of `2.2.2.2` was removed from the `ip_addresses` field on the `hosts_lookup` but not the `mgmt_lookup`


### OverSight aggregated invalid or test data, how can I clear the lookups?

To clear all data from a lookup table, use the `| outputlookup <lookup_name>`.

To expire one or more records, you can use `param.force=true` with the records in the search pipeline.
Example:
```
| inputlookup hosts_lookup
| search ip=10.25.*
| sendalert expire_inventory param.force=true
```
This will force these records expired where ip=10.25.*

To hard delete records:
```
| inputlookup hosts_lookup
| search ip!=10.25.*
| `set_key(ip)`
| outputlookup hosts_lookup
```

OverSight will also hard delete records in the individual input lookup tables if it detects a key value being re-used for a previously expired record.

### Alert Action Parameters Available

#### update_inventory
param.source_name: match the source name of the input name the events derive from
param.log_level: override the app-wide log_level setting

#### expire_inventory
param.force=true: use to hard force all events in the search pipeline to expire
param.log_level: override the app-wide log_level setting

Copyright © 2020 United States Government as represented by the Administrator of the National Aeronautics and Space Administration.  All Other Rights Reserved.