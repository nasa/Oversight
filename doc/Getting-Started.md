# Configuration Walk-through

Let's walk through how to configure Oversight to create inventory lookups based on data already in Splunk.

Given the following events exist in index=main sourcetype=syslog:
```
{"ip": "3.3.3.3", "syslog_server": "syslog2","loglevel": "ERROR", "message": "watchdog detected hang", "time": "2021-08-01 02:22:00.000"}
{"ip": "1.1.1.1", "syslog_server": "syslog1","loglevel": "INFO", "message": "system power off", "time": "2021-08-01 02:20:00.000"}
{"ip": "2.2.2.2", "syslog_server": "syslog2","loglevel": "INFO", "message": "user logged in", "userid":123, "time": "2021-08-01 02:05:00.000"}
{"ip": "1.1.1.1", "syslog_server": "syslog1", "loglevel": "DEBUG", "message": "system rebooting", "time": "2021-08-01 02:00:00.000"}
```

Create the following Input:
```
Name: syslog
Source Expression: index=main sourcetype=syslog
Source Expression Fields: syslog_server
Unique ID Field: ip
Inventory Source: [leave box checked]
Cron Schedule: [update to execute daily a few minutes from now]

Click <Save>
```

The custom script will now execute in the background, creating the collection, transforms, macros, 
and the scheduled savedsearches necessary to collect and aggregate inventory information from this set of events.

The savedsearch will execute on the cron schedule you specified.  Check the contents using the `| inputlookup syslog_lookup ` or `| inputlookup hosts_lookup ` in the search bar.

Also be sure to enable the `expire_inventory` saved search as it is disabled by default.

## Walk-through Lookup Table Contents
With the above Input defined and data present, we would get the lookup table output below after the saved search executes for the first time:

`| inputlookup syslog_lookup`

| ip | last_inventoried | syslog_server| expired |
|---|---|---|---|
| 3.3.3.3 | 2021-08-01 02:22 | syslog2 | false |
| 1.1.1.1 | 2021-08-01 02:20 | syslog1 | false
| 2.2.2.2 | 2021-08-01 02:05 | syslog2 | false

`| inputlookup hosts_lookup`

| ip | ip_addresses | last_inventoried | first_inventoried | syslog_last_inventoried |asset_group | expired |
|---|---|---|---|---|----|---|
| 3.3.3.3 | 3.3.3.3 | 2021-08-01 02:22 | 2021-08-01 02:22 | 2021-08-01 02:22 | default | false |
| 1.1.1.1 | 1.1.1.1 | 2021-08-01 02:20 | 2021-08-01 02:20 | 2021-08-01 02:20 | default | false |
| 2.2.2.2 | 2.2.2.2 | 2021-08-01 02:05 | 2021-08-01 02:05 | 2021-08-01 02:05 | default | false |


The `_key` field is hidden by Splunk but used as the lookup table key for the record.

If over the next day, only ip `3.3.3.3` forwards syslog entries to the syslog server, this would be the updated lookup table contents:

`| inputlookup syslog_lookup`

| ip | last_inventoried | syslog_server| expired |
|---|---|---|---|
| 3.3.3.3 | 2021-08-02 07:11 | syslog2 | false |
| 1.1.1.1 | 2021-08-01 02:20 | syslog1 | false
| 2.2.2.2 | 2021-08-01 02:05 | syslog2 | false

`| inputlookup hosts_lookup`

| ip | ip_addresses | last_inventoried | first_inventoried | syslog_last_inventoried |asset_group | expired |
|---|---|---|---|---|----|---|
| 3.3.3.3 | 3.3.3.3 | 2021-08-02 07:11 | 2021-08-01 02:22 | 2021-08-02 07:11 | default | false |
| 1.1.1.1 | 1.1.1.1 | 2021-08-01 02:20 | 2021-08-01 02:20 | 2021-08-01 02:20 | default | false |
| 2.2.2.2 | 2.2.2.2 | 2021-08-01 02:05 | 2021-08-01 02:05 | 2021-08-01 02:05 | default | false |

The  `last_inventoried` field is more meaningful when more then one Input is defined.

## Walk-through Custom Script Output

Lookups:
```
hosts_lookup - kvstore - _key,asset_group,expired,ip,ip_addresses,last_inventoried,first_inventoried,syslog_last_inventoried
host_lookup_all - kvstore -_key,asset_group,expired,ip,ip_addresses,  last_inventoried,first_inventoried,syslog_last_inventoried
syslog_lookup - kvstore - _key,ip,last_inventoried,syslog_server,expired
syslog_lookup_all - kvstore - _key,ip,last_inventoried,syslog_server,expired
```

Collections:
```
hosts_collection
syslog_collection
```

Macros (excluding OverSight built-ins):
```
`syslog_fields`
`syslog_source`
```

Schedule Saved Searches:
```
syslog_hosts - owner: splunk-system-user - Next Schedule Time: per cron settings - Enabled: Yes
```



The top level directory 'OverSight' is the repo root, with configuration templates, test files, build files, etc.
The 'TA-Oversight' folder holds the core app code, installed in the $SPLUNK_HOME/etc/apps directory.

The repo is hosted at <a href="https://code.nasa.gov/Oversight.git">https://code.nasa.gov/Oversight.git</a>



## Caveats

    * Inventory sources within the same asset group must use the same unique field type.
      IE: You cannot have one source key on mac and another key on IP within an asset group.

## Configuring Inputs (event sets)

To add a new Oversight data input, navigate to the Input Tab, and click Add New Input.
See the wiki for further details.

## Monitoring the App

The custom script logs with sourcetype `oversight:log` to `index=_internal`.
You can adjust the log detail in the App Configuration Page.

* Searches can be found at http://splunkserver:8000/en-US/manager/TA-oversight/saved/searches?app=TA-oversight&count=10&offset=0&itemType=&owner=&search=
* Collections can be found at
    * https://splunkserver:8089/servicesNS/nobody/TA-oversight/storage/collections/data/hosts_collection
    * https://splunkserver:8089/servicesNS/nobody/TA-oversight/storage/collections/config/hosts_collection

    * https://splunkserver:8089/servicesNS/nobody/TA-oversight/storage/collections/data/<collection_name>
* Macros can be found at http://splunkserver:8000/en-US/manager/launcher/admin/macros/?ns=TA-oversight&pwnr=-&app_only=1&search=&count=25
* Lookup table views of the kvstore collections can be searched using `inputlookup <lookup_name>` e.g. `inputlookup hosts_lookup`

## A Note on Searches built on Oversight Lookups with Multi-Value fields

If you are using TA-oversight to track hosts and inputs by IP address or another identifier that is multivalue, remember you'll need to dedup any 
fields produced by the `| lookup` command, if you are matching against a field that is common across all identifiers.

Given test_lookup:

| ip |  ips |  host_id | status | last_inventoried |
|---|---|---|---|---|
| 1.1.1.1 | 1.1.1.1 <br />2.2.2.2 | 101 | green | today |
| 2.2.2.2 | 1.1.1.1 <br />2.2.2.2 | 101 | green | today 


The following command will produce a multivalue field which will need to be deduped.

>
| makeresults <br/>
| eval host_id=101 <br/>
| lookup test_lookup host_id output status

| host_id | status | 
|---|---|
| 101 | green<br />green| 




to correct, update the query as per below:

>
| makeresults <br/>
| eval host_id=101<br />
| lookup test_lookup host_id output status
**| eval host_id=mvdedup(host_id)** <br/>


| host_id | status | 
|---|---|
| 101 | green | 

## Cleanup

If you disable the `Input` you created, the saved search will be disabled as well.
If you delete the `Input` you created, the `syslog_*` knowledge objects will be deleted.

## Permission

Assign the `edit_modinput_oversight` capability to any user or role you wish to be able to create, modify, or delete Oversight input definitions.  By default this capability is granted to the `admin` role.


## Troubleshooting

All scripts are logged to `index=_internal sourcetype=oversight:log`.
You can adjust the log level in the App Configuration page.

## Support

This is an open source project hosted at https://github.com/nasa/Oversight
Members of the public are encouraged to report any issues to the repository.
Pull Requests are welcome but please open an issue to discuss your feature first.


Copyright © 2020 United States Government as represented by the Administrator of the National Aeronautics and Space Administration.  All Other Rights Reserved.