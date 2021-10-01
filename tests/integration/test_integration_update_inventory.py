# -*- coding: utf-8 -*-
import inspect
import os
import sys
import time
from datetime import datetime, timedelta
import copy

import pytest
from pprint import pprint as pp

rootdir = os.getcwd()
sys.path.insert(0, rootdir)
import tests

TEST_DIR = tests.TEST_DIR
APP_NAME = tests.APP_NAME
BUILD_BIN = tests.BUILD_OUTPUT_BIN

sys.path.insert(0, BUILD_BIN)
sys.path.insert(0, os.path.join(BUILD_BIN, "/TA-oversight"))
sys.path.insert(0, os.path.join(BUILD_BIN, "/TA-oversight/bin"))
sys.path.insert(0, os.path.join(BUILD_BIN, "/TA-oversight/bin/TA-oversight"))

import splunklib.binding as binding
import splunklib.client as client
import splunklib.results as results

# import import_declare_test
from splunklib.binding import AuthenticationError, HTTPError


# https://pytest-splunk-addon.readthedocs.io/en/latest/how_to_use.html
class TASetup(object):
    def __init__(self, splunk):
        self.splunk = splunk
        self.service = client.connect(**splunk)

    def wait_for_lookup(self, lookup):
        splunk_client = client.connect(**self.splunk)
        for _ in range(120):
            job_result = splunk_client.jobs.oneshot("inputlookup {}".format(lookup))
            for _ in results.ResultsReader(job_result):
                return
            time.sleep(1)

    def print_searchlog(self, job):
        pp([item for item in job.searchlog()])

    def get_oneshot_results(self, search_query, key_field=None):
        # https://docs.splunk.com/DocumentationStatic/PythonSDK/1.6.13/client.html
        output_list = []
        output_dict = {}
        service = client.connect(**self.splunk)
        for _ in range(30):
            rr = results.ResultsReader(service.jobs.oneshot(search_query))
            for result in rr:
                if isinstance(result, results.Message):
                    print("{}: {}".format(str(result.type), str(result.message)))
                elif isinstance(result, dict):
                    output_list.append(result)
            # assert rr.is_preview == False
            if output_list:
                return output_list
        return output_list

    def get_blocking_search_results(
        self, search_query, key_field=None, debug=None, **search_kwargs
    ):
        # https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython
        output_list = []
        output_dict = {}
        kwargs = {"exec_mode": "blocking"}

        if search_kwargs:
            kwargs.update(search_kwargs)
        service = client.connect(**self.splunk)
        print("searching with args:{},  {}".format(str(kwargs), search_query))
        job = service.jobs.create(search_query, **kwargs)
        if debug:
            self.print_searchlog(job)

        print("search job completed")

        if key_field:
            for result in results.ResultsReader(job.results()):
                key = result[key_field]
                output_dict[key] = result
            return output_dict
        else:
            for result in results.ResultsReader(job.results()):
                output_list.append(result)
            return output_list

    def wait_for_oversight_setup(self):
        search = """ search index=_internal sourcetype=oversight:log name=mgmt2 status=completed earliest=-5m@m """
        result = self.get_blocking_search_results(search)
        assert result is not None

    def clean_lookup(self, *lookup_names):
        for lookup in lookup_names:
            self.get_oneshot_results(" | outputlookup {}".format(lookup))

    def update_app_setting(self, filename, stanza, **kwargs):
        service = client.connect(**self.splunk)
        if stanza:
            service.confs[filename][stanza].post(**kwargs)
        else:
            service.confs[filename].post(**kwargs)

    def get_app_settings(self, filename, stanza):
        service = client.connect(**self.splunk)
        if stanza:
            return service.confs[filename][stanza].content()
        else:
            return service.confs[filename].content()

    def add_input_stanza(self, kind, name, **settings):
        service = client.connect(**self.splunk)
        service.inputs.create(name=name, kind=kind, **settings)
        assert name in service.inputs

    def get_stanza(self, filename, name):
        service = client.connect(**self.splunk)
        conf = service.confs[filename]
        return conf.get(name) or None


@pytest.fixture(scope="session")
def splunk_setup(splunk):
    splunk["app"] = tests.APP_NAME
    print("Connecting with splunk settings: {}".format(str(splunk)))

    ta_setup = TASetup(splunk)
    ta_setup.wait_for_oversight_setup()
    time.sleep(10)

    ## setup global app settings
    settings = {
        "time_format": "%Y-%m-%d %H:%M",
        "last_inventoried_fieldname": "last_inventoried",
        "first_inventoried_fieldname": "first_inventoried",
        "aggregation_collection_name": "hosts_collection",
        "aggregation_lookup_name": "hosts_lookup",
        "primary_id_field": "ip",
        "primary_mv_id_field": "ip_addresses",
    }
    asset_group_settings = {"asset_group_1_max_age": "7"}
    ta_setup.update_app_setting(
        filename="ta_oversight_settings", stanza="additional_parameters", **settings
    )
    ta_setup.update_app_setting(
        filename="ta_oversight_settings", stanza="asset_groups", **asset_group_settings
    )
    ta_setup.update_app_setting(
        "ta_oversight_settings", "logging", **{"loglevel": "DEBUG"}
    )

    # setup needed inputs for tests

    syslog_settings = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "inventory_filter": "search ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "log_level",
        "aggregation_fields": "log_level",
    }
    mgmt2_settings = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "mv_id_field": "ip_addresses",
        "inventory_filter": "search ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "computer_name, dns_name",
        "aggregation_fields": "computer_name, dns_name",
    }

    test_source_settings = {
        "cron": "0 23 * * *",
        "id_field": "test_ip",
        "mv_id_field": "test_ip_addresses",
        "inventory_filter": "search test_ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "computer_name, dns_name",
        "aggregation_fields": "computer_name, dns_name",
    }

    mgmt_settings = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "mv_id_field": "ips",
        "inventory_filter": "search ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "agent_version",
    }

    if "mgmt" in ta_setup.service.inputs:
        ta_setup.service.inputs["mgmt"].update(**mgmt_settings)
    else:
        ta_setup.service.inputs.create(
            name="mgmt", kind="oversight", **mgmt_settings
        )

    if "test_source" in ta_setup.service.inputs:
        ta_setup.service.inputs["test_source"].update(**test_source_settings)
    else:
        ta_setup.service.inputs.create(
            name="test_source", kind="oversight", **test_source_settings
        )

    if "syslog" in ta_setup.service.inputs:
        ta_setup.service.inputs["syslog"].update(**syslog_settings)
    else:
        ta_setup.service.inputs.create(
            name="syslog", kind="oversight", **syslog_settings
        )

    if "mgmt2" in ta_setup.service.inputs:
        ta_setup.service.inputs["mgmt2"].update(**mgmt2_settings)
    else:
        ta_setup.service.inputs.create(
            name="mgmt2", kind="oversight", **mgmt2_settings
        )
    time.sleep(10)

    # if "hosts_lookup" not in ta_setup.service.kvstore:

    # ta_setup.service.kvstore.create("hosts_lookup")

    assert "mgmt2" in ta_setup.service.inputs
    assert ta_setup.service.inputs["mgmt2"]["id_field"] == "ip"
    assert "mgmt2_lookup" in ta_setup.service.confs["transforms"]
    assert "mgmt2_collection" in ta_setup.service.kvstore
    print("Returning splunk setup to test...")
    return ta_setup


def test_index_internal(splunk_setup):
    search = """ search index=_internal | stats count by sourcetype """
    result = splunk_setup.get_blocking_search_results(search)
    # print(result)
    assert result is not None


def test_multi_key_single_record_update_doesnt_change_recordcount(splunk_setup):
    # test that updating a record with all mvkeys existing doesn't create additional records
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
                ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1" ]
    | eval expired="false"
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp1, timestamp1
    )
    load_dataset1 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")
    assert len(result) == 2

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
                ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1" ]
    | eval expired="false"        
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp2, timestamp2
    )

    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")
    assert len(result) == 2
    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup")


def test_single_key_after_multi_key_doesnt_change_recordcount(splunk_setup):
    # test that aggregating a source with single-key, after a multi-key source, doesnt change record count
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
                ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1" ]
    | eval expired="false"            
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp1, timestamp1
    )
    load_dataset1 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 2

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}"]
    | eval expired="false"
    | table _key,ip,last_inventoried expired
    | outputlookup syslog_lookup key_field=_key
    | sendalert update_inventory param.source_name=syslog""".format(
        timestamp2, timestamp2
    )
    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")
    assert len(result) == 2
    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup", "syslog_lookup")


def test_multi_key_after_two_single_keys_combines_records(splunk_setup):
    # given individual records for key 1.1.1.1 and 2.2.2.2 from single sources,
    # followed by mv_key from 2nd source with 1.1.1.1,2.2.2.2 -> 2 aggregated records
    # and -> | dedup ip_addresses == 1 aggregated unique host

    # teardown prior
    splunk_setup.clean_lookup("syslog_lookup", "mgmt2_lookup", "hosts_lookup")

    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}"]
    | eval expired="false"
    | table _key,ip,last_inventoried expired
    | outputlookup syslog_lookup key_field=_key
    | sendalert update_inventory param.source_name=syslog""".format(
        timestamp1, timestamp1
    )
    load_dataset1 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")
    assert len(result) == 2
    unique_hosts_results = splunk_setup.get_blocking_search_results(
        "|inputlookup hosts_lookup | dedup ip_addresses", "ip"
    )
    assert len(unique_hosts_results) == 2

    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
                ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1" ]
    | eval expired="false"
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp2, timestamp2
    )
    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")
    assert len(result) == 2
    unique_hosts_results = splunk_setup.get_blocking_search_results(
        "|inputlookup hosts_lookup | dedup ip_addresses",
    )
    print(unique_hosts_results)
    assert len(unique_hosts_results) == 1

    splunk_setup.clean_lookup("syslog_lookup", "mgmt2_lookup", "hosts_lookup")


def test_single_key_single_record_update(splunk_setup):
    # test that updating a record doesn't produce a second record
    # test that default value of _key is automatically assigned when mv_key is None

    # teardown prior
    splunk_setup.clean_lookup("syslog_lookup", "mgmt2_lookup", "hosts_lookup")

    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1", dns_name="system1.test.to", expired="false" 
    | table _key, ip, last_inventoried, computer_name, dns_name, ip_addresses expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp1
    )

    load_dataset1 = splunk_setup.get_blocking_search_results(search, debug=True)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 1
    result = result[0]
    tested_result = {
        "_key": "1.1.1.1",
        "ip": "1.1.1.1",
        "last_inventoried": timestamp1,
        "first_inventoried": timestamp1,
        "computer_name": "system1",
        "dns_name": "system1.test.to",
        "ip_addresses": "1.1.1.1",  # because ip_addresses is mv_key it gets a default value!
        "mgmt2_last_inventoried": timestamp1,
    }
    for item in tested_result:
        assert tested_result[item] == result.get(item)

    ## Load 2nd dataset
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1.5", ip_addresses=split("1.1.1.1,2.2.2.2", ","), expired="false"
    | table _key, ip, last_inventoried, computer_name, dns_name, ip_addresses expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp2
    )

    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 1
    result = result[0]
    tested_result = {
        "_key": "1.1.1.1",
        "ip": "1.1.1.1",
        "last_inventoried": timestamp2,
        "first_inventoried": timestamp1,
        "computer_name": "system1.5",
        "dns_name": None,  # currently failiing TODO
        "ip_addresses": ["1.1.1.1", "2.2.2.2"],
        "mgmt2_last_inventoried": timestamp2,
        "expired": "false",
    }
    print(result)
    for item in tested_result:
        if isinstance(tested_result[item], list):
            assert set(tested_result[item]) == set(result.get(item))
        else:
            assert tested_result[item] == result.get(item)
    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup")


def test_single_key_aggregation_fields_correct(splunk_setup):
    # test that missing aggregation fields are updated to None
    # test that present aggregation fields are updated

    # teardown any prior
    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup")

    # Load dataset1
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M")
    timestamp3 = (datetime.now() + timedelta(minutes=6)).strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1", dns_name="system1.test.to", expired="false"
    | table _key, ip, last_inventoried, computer_name, dns_name, ip_addresses expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp1
    )

    load_dataset1 = splunk_setup.get_blocking_search_results(search)

    # Validate dataset1 aggregation
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 1
    result = result[0]
    tested_result = {"computer_name": "system1", "dns_name": "system1.test.to"}
    for item in tested_result:
        assert tested_result[item] == result.get(item)

    ## Load 2nd dataset
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1.5", ip_addresses=split("1.1.1.1,2.2.2.2", ","), expired="false"
    | table _key, ip, last_inventoried, computer_name, dns_name, ip_addresses expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp2
    )

    ignore = splunk_setup.get_blocking_search_results(search)

    # Validate 2nd dataset aggregation
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 1
    result = result[0]
    tested_result = {"computer_name": "system1.5", "dns_name": None}
    print(result)
    for item in tested_result:
        assert tested_result[item] == result.get(item)

    # Load 3rd dataset and aggregate
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1.5", ip_addresses=split("1.1.1.1,2.2.2.2", ","),
            dns_name="system1.5.test.io", expired="false"
    | table _key, ip, last_inventoried, computer_name, dns_name, ip_addresses, expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2""".format(
        timestamp3
    )

    ignore = splunk_setup.get_blocking_search_results(search)

    # Validate 3nd dataset aggregation
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")
    assert len(result) == 1
    result = result[0]
    tested_result = {"computer_name": "system1.5", "dns_name": "system1.5.test.io"}
    for item in tested_result:
        assert tested_result[item] == result.get(item)

    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup")


def test_aggregation_field_from_different_source_not_overwritten(splunk_setup):
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=-3)).strftime("%Y-%m-%d %H:%M")

    # teardown from prior
    splunk_setup.clean_lookup("mgmt2_lookup", "hosts_lookup")

    # Load and aggregate first dataset
    record1 = """
        | makeresults 
        | eval _key="1.1.1.1", asset_group="default", ip="1.1.1.1", last_inventoried="{}",
            computer_name="system1.6", expired="false"
        | outputlookup mgmt2_lookup key_field=_key
        | sendalert update_inventory param.source_name=mgmt2
        """.format(
        timestamp1
    )
    aggregation1 = splunk_setup.get_blocking_search_results(record1)

    # validate aggregation results
    results = splunk_setup.get_blocking_search_results(" | inputlookup hosts_lookup")
    tested_result = {"dns_name": None, "computer_name": "system1.6"}
    ## assert app_setting last_inventoried_fieldname == "last_inventoried"
    assert len(results) == 1
    results = results[0]
    assert "mgmt2_last_inventoried" in results
    for item in tested_result:
        assert tested_result[item] == results.get(item)

    # Load and aggregate 2nd dataset
    record2 = """
        | makeresults 
        | eval _key="1.1.1.1", asset_group="default", ip="1.1.1.1", last_inventoried="{}",
            log_level="verbose", expired="false"
        | outputlookup syslog_lookup key_field=_key
        | sendalert update_inventory param.source_name=syslog
        """.format(
        timestamp1
    )
    aggregation2 = splunk_setup.get_blocking_search_results(record2)

    ## Validate aggregation results: computer_name should not be overwritten with none
    results = splunk_setup.get_blocking_search_results(" | inputlookup hosts_lookup")
    tested_result = {
        "dns_name": None,
        "computer_name": "system1.6",
        "log_level": "verbose",
    }
    ## assert app_setting last_inventoried_fieldname == "last_inventoried"
    assert len(results) == 1
    results = results[0]
    assert "mgmt2_last_inventoried" in results and "syslog_last_inventoried" in results
    for item in tested_result:
        assert tested_result[item] == results.get(item)

    ## Load and aggregate 3rd dataset
    record3 = """
        | makeresults 
        | eval _key="1.1.1.1", asset_group="default", ip="1.1.1.1", last_inventoried="{}",
            log_level="INFO", expired="false"
        | outputlookup syslog_lookup key_field=_key
        | sendalert update_inventory param.source_name=syslog
        """.format(
        timestamp1
    )
    aggregation2 = splunk_setup.get_blocking_search_results(record3)

    ## Validate aggregation results: computer_name should not be overwritten with none
    results = splunk_setup.get_blocking_search_results(" | inputlookup hosts_lookup")
    tested_result = {
        "dns_name": None,
        "computer_name": "system1.6",
        "log_level": "INFO",
    }
    ## assert app_setting last_inventoried_fieldname == "last_inventoried"
    assert len(results) == 1
    results = results[0]
    assert "mgmt2_last_inventoried" in results and "syslog_last_inventoried" in results

    for item in tested_result:
        assert tested_result[item] == results.get(item)

    splunk_setup.clean_lookup("syslog_lookup", "mgmt2_lookup", "hosts_lookup")


def test_dont_update_last_inventoried(splunk_setup):
    # we provide an update to hosts_lookup for a different data source, but give an earlier timestamp.
    # source_last_inventoried will be updated but not last_inventoried because the new value would be older than the current value

    # teardown from prior
    splunk_setup.clean_lookup("syslog_lookup", "mgmt2_lookup", "hosts_lookup")

    # init test data and run alert action
    now = datetime.now()
    timestamp1 = now.strftime("%Y-%m-%d %H:%M")
    timestamp2 = (now + timedelta(minutes=-3)).strftime("%Y-%m-%d %H:%M")

    submit_prior_record = splunk_setup.get_blocking_search_results(
        """| makeresults 
        | eval _key="1.1.1.1", asset_group="default", ip="1.1.1.1", last_inventoried="{}", expired="false"
        | outputlookup mgmt2_lookup key_field=_key
        | sendalert update_inventory param.source_name=mgmt2
        """.format(
            timestamp1
        )
    )

    ## get alert action results
    prior_results = splunk_setup.get_blocking_search_results(
        " |inputlookup hosts_lookup "
    )

    assert len(prior_results) == 1
    prior_data = prior_results[0]

    ## run 2nd data update with an older event , and alert action
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
            log_level="verbose", expired="false"
    | table _key, ip, last_inventoried, log_level, expired
    | outputlookup syslog_lookup key_field=_key
    | sendalert update_inventory param.source_name=syslog """.format(
        timestamp2
    )
    ignore = splunk_setup.get_blocking_search_results(search)

    # get results
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup")

    # validate
    assert len(result) == 1
    result = result[0]

    assert prior_data["last_inventoried"] == result["last_inventoried"]
    assert result["first_inventoried"] == timestamp2
    assert result["syslog_last_inventoried"] == timestamp2
    assert prior_data.get("syslog_last_inventoried") == None

    # cleanup
    splunk_setup.clean_lookup("hosts_lookup", "syslog_lookup", "mgmt2_lookup")


def test_update_inventory_sucessive_calls_aggregation(splunk_setup):
    # add an initial dataset to mgmt2_lookup, then call update_inventory to aggregate it

    # prior test teardown cleanup
    splunk_setup.clean_lookup(
        "mgmt2_lookup", "syslog_lookup", "hosts_lookup", "mgmt2_lookup"
    )

    dt = datetime.now()
    inventoried_mgmt21 = dt.strftime("%Y-%m-%d %H:%M")
    search = """ | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
                ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1"
    | append 
        [| makeresults
        | eval _key="2.2.2.2", ip="2.2.2.2", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,2.2.2.2", ","), computer_name="system1" ]
    | append 
        [| makeresults 
        | eval _key="3.3.3.3", ip="3.3.3.3", last_inventoried="{}", 
            ip_addresses=split("3.3.3.3", ","), computer_name="system3" ]
    | eval expired="false"
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup 
    | sendalert update_inventory param.source_name=mgmt2""".format(
        inventoried_mgmt21, inventoried_mgmt21, inventoried_mgmt21
    )
    load_dataset1 = splunk_setup.get_blocking_search_results(search)
    result = splunk_setup.get_blocking_search_results("|inputlookup hosts_lookup", "ip")

    # print(str(result))
    assert result is not None
    assert len(result) == 3
    pp(copy.deepcopy(result))
    assert result["1.1.1.1"]["last_inventoried"] == inventoried_mgmt21
    assert result["1.1.1.1"]["first_inventoried"] == inventoried_mgmt21

    assert result["2.2.2.2"]["last_inventoried"] == inventoried_mgmt21
    assert result["2.2.2.2"]["first_inventoried"] == inventoried_mgmt21

    assert result["3.3.3.3"]["last_inventoried"] == inventoried_mgmt21
    assert result["3.3.3.3"]["first_inventoried"] == inventoried_mgmt21

    # add 2nd dataset to mgmt2_lookup, then call update_inventory to aggregate new results
    dt = datetime.now() + timedelta(minutes=3)
    inventoried_mgmt22 = dt.strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults 
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
        ip_addresses=split("1.1.1.1,4.4.4.4", ","), computer_name="system1" 
    | append
        [| makeresults
        | eval _key="4.4.4.4", ip="4.4.4.4", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,4.4.4.4", ","), computer_name="system1" ]
    | append
        [| makeresults 
        | eval _key="3.3.3.3", ip="3.3.3.3", last_inventoried="{}", 
            ip_addresses="3.3.3.3", computer_name="system3" ]
    | eval expired="false"
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    | outputlookup mgmt2_lookup key_field=_key
    | sendalert update_inventory param.source_name=mgmt2 """.format(
        inventoried_mgmt22, inventoried_mgmt22, inventoried_mgmt22
    )
    result = splunk_setup.get_blocking_search_results(search)
    assert len(result) == 3

    # validate aggregation lookup contents
    result = splunk_setup.get_blocking_search_results(
        "| inputlookup hosts_lookup", "ip"
    )
    print(str(result))
    assert result is not None
    assert len(result) == 4
    pp(
        {
            "inventoried_mgmt21": inventoried_mgmt21,
            "inventoried_mgmt22": inventoried_mgmt22,
        }
    )
    assert result["1.1.1.1"]["last_inventoried"] == inventoried_mgmt22
    assert result["1.1.1.1"]["first_inventoried"] == inventoried_mgmt21

    assert result["2.2.2.2"]["last_inventoried"] == inventoried_mgmt21
    assert result["2.2.2.2"]["first_inventoried"] == inventoried_mgmt21

    assert result["3.3.3.3"]["last_inventoried"] == inventoried_mgmt22
    assert result["3.3.3.3"]["first_inventoried"] == inventoried_mgmt21

    assert result["4.4.4.4"]["last_inventoried"] == inventoried_mgmt22
    assert result["4.4.4.4"]["first_inventoried"] == inventoried_mgmt22

    # aggregate from syslog source
    dt = datetime.now() + timedelta(minutes=6)
    inventoried_syslog1 = dt.strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", log_level="info"
    | append
        [| makeresults
        | eval _key="3.3.3.3", ip="3.3.3.3", last_inventoried="{}", log_level="verbose"]
    | eval expired="false"
    | table _key,ip,last_inventoried,log_level expired
    | outputlookup syslog_lookup
    | sendalert update_inventory param.source_name=syslog""".format(
        inventoried_syslog1, inventoried_syslog1
    )
    result = splunk_setup.get_blocking_search_results(search)
    assert len(result) == 2

    result = splunk_setup.get_blocking_search_results(
        "| inputlookup hosts_lookup", "ip"
    )
    assert result is not None
    assert len(result) == 4
    pp(
        {
            "inventoried_mgmt21": inventoried_mgmt21,
            "inventoried_mgmt22": inventoried_mgmt22,
            "inventoried_syslog1": inventoried_syslog1,
        }
    )

    assert result["1.1.1.1"]["last_inventoried"] == inventoried_syslog1
    assert result["1.1.1.1"]["first_inventoried"] == inventoried_mgmt21

    assert result["2.2.2.2"]["last_inventoried"] == inventoried_mgmt21
    assert result["2.2.2.2"]["first_inventoried"] == inventoried_mgmt21

    assert result["3.3.3.3"]["last_inventoried"] == inventoried_syslog1
    assert result["3.3.3.3"]["first_inventoried"] == inventoried_mgmt21

    assert result["4.4.4.4"]["last_inventoried"] == inventoried_mgmt22
    assert result["4.4.4.4"]["first_inventoried"] == inventoried_mgmt22

    # aggregate another mgmt2_lookup dataset in
    dt = datetime.now() + timedelta(minutes=9)
    inventoried_mgmt23 = dt.strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults
    | eval _key="1.1.1.1", ip="1.1.1.1", last_inventoried="{}", 
        ip_addresses=split("1.1.1.1,4.4.4.4,5.5.5.5", ","), computer_name="system1"
    | append
        [| makeresults 
        | eval _key="4.4.4.4", ip="4.4.4.4", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,4.4.4.4,5.5.5.5", ","), computer_name="system1" ]
    | append
        [| makeresults
        | eval _key="5.5.5.5", ip="5.5.5.5", last_inventoried="{}", 
            ip_addresses=split("1.1.1.1,4.4.4.4,5.5.5.5", ","), computer_name="system1" ]
    | append
        [| makeresults
        | eval _key="3.3.3.3", ip="3.3.3.3", last_inventoried="{}", 
            ip_addresses="3.3.3.3", computer_name="system3" ]
    | eval expired="false"
    | table _key,ip,last_inventoried,ip_addresses computer_name expired
    |outputlookup mgmt2_lookup
    |sendalert update_inventory param.source_name=mgmt2""".format(
        inventoried_mgmt23,
        inventoried_mgmt23,
        inventoried_mgmt23,
        inventoried_mgmt23,
    )
    result = splunk_setup.get_blocking_search_results(search, "_key")
    assert len(result) == 4
    result = splunk_setup.get_blocking_search_results(
        "| inputlookup hosts_lookup", "ip"
    )
    assert len(result) == 5
    pp(
        {
            "inventoried_mgmt21": inventoried_mgmt21,
            "inventoried_mgmt22": inventoried_mgmt22,
            "inventoried_syslog1": inventoried_syslog1,
            "inventoried_mgmt23": inventoried_mgmt23,
        }
    )

    assert result["1.1.1.1"]["last_inventoried"] == inventoried_mgmt23
    assert result["1.1.1.1"]["first_inventoried"] == inventoried_mgmt21

    assert result["2.2.2.2"]["last_inventoried"] == inventoried_mgmt21
    assert result["2.2.2.2"]["first_inventoried"] == inventoried_mgmt21

    assert result["3.3.3.3"]["last_inventoried"] == inventoried_mgmt23
    assert result["3.3.3.3"]["first_inventoried"] == inventoried_mgmt21

    assert result["4.4.4.4"]["last_inventoried"] == inventoried_mgmt23
    assert result["4.4.4.4"]["first_inventoried"] == inventoried_mgmt22

    assert result["5.5.5.5"]["last_inventoried"] == inventoried_mgmt23
    assert result["5.5.5.5"]["first_inventoried"] == inventoried_mgmt23

    splunk_setup.clean_lookup("mgmt2_lookup", "syslog_lookup", "hosts_lookup")


def test_cleanup(splunk_setup):
    """can be manually invoked if needed to clean up test data after failures"""
    splunk_setup.clean_lookup("mgmt2_lookup", "syslog_lookup", "hosts_lookup")
    pass


def test_required_fields_created(splunk_setup):
    """assert that required fields are present in a aggregated record"""

    # cleanup from any prior tests
    splunk_setup.clean_lookup("test_lookup", "hosts_lookup", "syslog_lookup")

    service = client.connect(**splunk_setup.splunk)
    test_source_settings = {
        "cron": "0 23 * * *",
        "id_field": "test_ip",
        "mv_id_field": "test_ip_addresses",
        "inventory_filter": "test_ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "computer_name, dns_name",
        "aggregation_fields": "computer_name, dns_name",
    }

    if "test_source" in service.inputs:
        service.inputs["test_source"].update(**test_source_settings)
    else:
        service.inputs.create(
            name="test_source", kind="oversight", **test_source_settings
        )
    time.sleep(10)
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    search = """
    | makeresults
    | eval _key="1.1.1.1", test_ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1", dns_name="system1.test.io", color="blue", expired="false"
    | table _key, test_ip, last_inventoried, computer_name, dns_name, test_ip_addresses, expired
    | outputlookup test_source_lookup key_field=_key
    | sendalert update_inventory param.source_name=test_source """.format(
        timestamp1
    )

    load_dataset1 = splunk_setup.get_blocking_search_results(search)

    results = splunk_setup.get_blocking_search_results(" | inputlookup hosts_lookup")

    assert len(results) == 1
    assert results[0]["ip"] == "1.1.1.1"
    assert "color" not in results[0]
    assert results[0]["dns_name"] == "system1.test.io"
    assert results[0]["computer_name"] == "system1"
    assert results[0]["_key"] == "1.1.1.1"
    assert results[0]["ip_addresses"] == "1.1.1.1"
    assert results[0]["test_source_last_inventoried"] == timestamp1

    service.kvstore["test_source_collection"].data.delete()
    # service.inputs.delete(name="test_source")
    # service.kvstore.delete("test_source_collection")
    service.kvstore["hosts_collection"].data.delete()


def test_required_fields_updated(splunk_setup):
    """assert that required fields are updated on subsequent calls"""

    # cleanup from prior tests
    splunk_setup.clean_lookup("test_lookup", "hosts_lookup")

    # load new input definition and initial data set for aggregation
    service = client.connect(**splunk_setup.splunk)
    test_source_settings = {
        "cron": "0 23 * * *",
        "id_field": "test_ip",
        "mv_id_field": "test_ip_addresses",
        "inventory_filter": "test_ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "computer_name, dns_name",
        "aggregation_fields": "computer_name, dns_name",
    }

    if "test_source" in service.inputs:
        service.inputs["test_source"].update(**test_source_settings)
    else:
        service.inputs.create(
            name="test_source", kind="oversight", **test_source_settings
        )
    time.sleep(20)
    if (
        splunk_setup.get_blocking_search_results(
            "search index=_internal sourcetype=oversight:log input=test_source"
        )
        == []
    ):
        raise IOError("test source did not initialize correctly, aborting.")
    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M")

    search = """
    | makeresults
    | eval _key="1.1.1.1", test_ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1", dns_name="system1.test.to", color="blue", expired="false"
    | table _key, test_ip, last_inventoried, computer_name, dns_name, ip_addresses, expired
    | outputlookup test_source_lookup key_field=_key
    | sendalert update_inventory param.source_name=test_source """.format(
        timestamp1
    )

    load_dataset1 = splunk_setup.get_blocking_search_results(search)

    ## perform subsequent update_inventory
    search = """
    | makeresults
    | eval _key="1.1.1.1", test_ip="1.1.1.1", last_inventoried="{}", 
            computer_name="system1.5", dns_name="system1.test.too", color="green", expired="false"
    | table _key, test_ip, last_inventoried, computer_name, dns_name, ip_addresses, expired
    | outputlookup test_source_lookup key_field=_key
    | sendalert update_inventory param.source_name=test_source """.format(
        timestamp2
    )

    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    results = splunk_setup.get_blocking_search_results(" | inputlookup hosts_lookup")
    assert len(results) == 1
    assert results[0]["ip"] == "1.1.1.1"
    assert "color" not in results[0]
    assert results[0]["dns_name"] == "system1.test.too"
    assert results[0]["computer_name"] == "system1.5"

    assert results[0]["ip_addresses"] == "1.1.1.1"
    assert results[0]["test_source_last_inventoried"] == timestamp2

    service.kvstore["test_source_collection"].data.delete()
    service.inputs.delete(name="test_source")
    service.kvstore["hosts_collection"].data.delete()


def test_aggregated_mvkey_isnt_overwritten_by_update_from_other_source_without_mvkey(
    splunk_setup,
):
    """aggregated lookup: {'_key':'1.1.1.1', 'ip_addresses':[1.1.1.1,2.2.2.2]} retains 'ip_addresses' even
    when updated from a data source without a mvkey field present"""

    # cleanup from any prior tests
    splunk_setup.clean_lookup("test_lookup", "hosts_lookup", "syslog_lookup")

    # load new input definition and initial data set for aggregation
    # remember update_inventory requires an oversight modular input defined
    # time.sleep(90)
    test_source_settings = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "mv_id_field": "ip_addresses",
        "inventory_filter": "search ip!=192*",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "computer_name, dns_name",
        "aggregation_fields": "computer_name, dns_name",
    }
    time.sleep(10)
    if "test_source" in splunk_setup.service.inputs:
        splunk_setup.service.inputs["test_source"].update(**test_source_settings)
    else:
        splunk_setup.service.inputs.create(
            name="test_source", kind="oversight", **test_source_settings
        )

    if "test_source_collection" not in splunk_setup.service.kvstore:
        splunk_setup.service.kvstore.create("test_source_collection")

    if "test_source_lookup" not in splunk_setup.service.confs["transforms"]:
        transform_args = {
            "external_type": ["kvstore"],
            "collection": ["test_source_collection"],
            "case_sensitive_match": ["false"],
            "fields_list": "ip,ip_addresses,last_inventoried",
        }
        splunk_setup.service.confs["transforms"].create(
            "test_source_lookup", **transform_args
        )

    timestamp1 = datetime.now().strftime("%Y-%m-%d %H:%M")
    timestamp2 = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M")

    search = """
    | makeresults
    | eval _key="1.1.1.1", ip=_key, ip_addresses=split("1.1.1.1,2.2.2.2,3.3.3.3",","), last_inventoried="{}"             
    | append [
        | makeresults | eval _key="2.2.2.2", ip=_key, ip_addresses=split("1.1.1.1,2.2.2.2,3.3.3.3",","), last_inventoried="{}"   
    ]
    | append [
        | makeresults | eval _key="3.3.3.3", ip=_key, ip_addresses=split("1.1.1.1,2.2.2.2,3.3.3.3",","), last_inventoried="{}"   
    ]
    | eval expired="false"
    | table _key, ip, last_inventoried, ip_addresses, expired
    | outputlookup test_source_lookup key_field=_key
    | sendalert update_inventory param.source_name=test_source param.log_level=DEBUG""".format(
        timestamp1, timestamp1, timestamp1
    )

    load_dataset1 = splunk_setup.get_blocking_search_results(search)
    results = splunk_setup.service.kvstore["hosts_collection"].data.query()
    assert len(results) == 3
    # validate dataset1 loaded
    assert results != []
    for item in results:
        assert item.get("ip_addresses") == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    search = """
    | makeresults | eval _key="2.2.2.2", ip=_key, log_level="INFO", expired="false", last_inventoried="{}"
    | eval expired="false"
    | table ip, _key, expired, log_level, last_inventoried expired
    | outputlookup syslog_lookup key_field=_key
    |sendalert update_inventory param.source_name=syslog param.log_level=DEBUG""".format(
        timestamp2
    )

    load_dataset2 = splunk_setup.get_blocking_search_results(search)
    results = splunk_setup.service.kvstore["hosts_collection"].data.query()
    assert len(results) == 3

    print("results:")
    pp(results)

    for item in results:
        if item.get("_key") == "2.2.2.2":
            assert set(item.get("ip_addresses")) == set(
                ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
            )

    # cleanup
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()
    splunk_setup.service.kvstore["test_source_collection"].data.delete()


def test_record_purged_when_key_reused(splunk_setup):
    """see issue #38 for more details"""

    # test setup

    old_timestamp = "2020-01-01 01:00"
    new_timestamp = "2021-10-10 05:00"
    search = """
    | makeresults 
    | eval ip="1.1.1.1", loglevel="DEBUG", last_inventoried="{}"
    | `sort_dedup(ip)` 
    | `set_key(ip)` 
    | `set_not_expired` 
    | table `syslog_fields` 
    | `outputlookup(syslog_lookup)`
    | sendalert update_inventory param.source_name=syslog""".format(
        old_timestamp
    )
    load_dataset1 = splunk_setup.get_blocking_search_results(search)

    search = """
    | inputlookup hosts_lookup
    | sendalert expire_inventory param.force=true"""
    expire_dataset1 = splunk_setup.get_blocking_search_results(search)

    # method under test
    search = """
    | makeresults 
    | eval ip="1.1.1.1", ips=split("1.1.1.1,2.2.2.2",","), agent_version="3.2" 
    | append 
        [| makeresults 
        | eval ip="2.2.2.2", ips=split("1.1.1.1,2.2.2.2",","), agent_version="3.2" ] 
    | eval last_inventoried="{}"
    | `sort_dedup(ip)` 
    | `set_key(ip)` 
    | `set_not_expired` 
    | table `mgmt_fields` 
    | `outputlookup(mgmt_lookup)`
    | sendalert update_inventory param.source_name=mgmt""".format(
        new_timestamp
    )
    load_dataset2 = splunk_setup.get_blocking_search_results(search)

    ## verify that syslog_lookup_all does not contain a record for ip="1.1.1.1"
    syslog_collection_output = splunk_setup.service.kvstore[
        "syslog_collection"
    ].data.query()
    assert syslog_collection_output == []

    # verify that host_collection entry for re-used key is re-initialized
    hosts_collection_output = splunk_setup.service.kvstore[
        "hosts_collection"
    ].data.query_by_id("1.1.1.1")
    assert hosts_collection_output["last_inventoried"] == new_timestamp
    assert hosts_collection_output["first_inventoried"] == new_timestamp

    # teardown
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()
    splunk_setup.service.kvstore["mgmt_collection"].data.delete()
