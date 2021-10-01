# -*- coding: utf-8 -*-
import copy
import glob
import inspect
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pprint import pprint as pp

import pytest

bindir = glob.glob("**/bin", recursive=True)
# hack for making sure we load the ucc-gen build dir
bindir = [i for i in bindir if "output" in i][0]
sys.path.insert(0, bindir)
print(sys.path)

import expire_inventory as lib
import splunklib.binding as binding
import splunklib.client as client
import splunklib.results as results
import tests

pp(sys.path)
# import import_declare_test
from splunklib.binding import AuthenticationError, HTTPError


# https://pytest-splunk-addon.readthedocs.io/en/latest/how_to_use.html
class TASetup(object):
    def __init__(self, splunk):
        self.splunk = splunk
        self.service = client.connect(**self.splunk)

    def wait_for_lookup(self, lookup):
        for _ in range(120):
            job_result = self.service.jobs.oneshot("inputlookup {}".format(lookup))
            for _ in results.ResultsReader(job_result):
                return
            time.sleep(1)

    def print_searchlog(self, job):
        pp([item for item in job.searchlog()])

    def get_oneshot_results(self, search_query, key_field=None):
        # https://docs.splunk.com/DocumentationStatic/PythonSDK/1.6.13/client.html
        output_list = []
        output_dict = {}
        for _ in range(30):
            rr = results.ResultsReader(self.service.jobs.oneshot(search_query))
            for result in rr:
                if isinstance(result, results.Message):
                    print("{}: {}".format(str(result.type), str(result.message)))
                elif isinstance(result, dict):
                    output_list.append(result)
            assert rr.is_preview == False
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
        print("searching with args:{},  {}".format(str(kwargs), search_query))
        job = self.service.jobs.create(search_query, **kwargs)
        print("search job completed")
        if debug:
            self.print_searchlog(job)

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
        search = """ search index=_internal sourcetype=oversight:log name=mgmt1 status=completed earliest=-5m@m """
        result = self.get_blocking_search_results(search)
        assert result is not None

    def clean_lookup(self, *lookup_names):
        for lookup in lookup_names:
            self.get_oneshot_results(" | outputlookup {}".format(lookup))

    def update_app_setting(self, filename, stanza, **kwargs):
        if stanza:
            self.service.confs[filename][stanza].post(**kwargs)
        else:
            self.service.confs[filename].post(**kwargs)

    def get_app_settings(self, filename, stanza):
        if stanza:
            return self.service.confs[filename][stanza].content()
        else:
            return self.service.confs[filename].content()

    def add_input_stanza(self, kind, name, **settings):
        self.service.inputs.create(name=name, kind=kind, **settings)
        assert name in self.service.inputs

    def get_stanza(self, filename, name):
        conf = self.service.confs[filename]
        return conf.get(name) or None


@pytest.fixture(scope="session")
def splunk_setup(splunk):

    # setup logging
    # fs.create_file("/opt/splunk/var/log/splunk/TA-oversight.log")
    # assert os.path.exists("/opt/splunk/var/log/splunk/TA-oversight.log")

    splunk["app"] = tests.APP_NAME
    print("Connecting with splunk settings: {}".format(str(splunk)))
    ta_setup = TASetup(splunk)

    ## allow any existing input definitions to be setup
    ta_setup.wait_for_oversight_setup()
    time.sleep(10)

    ## setup global add-on settings
    settings = {
        "time_format": "%Y-%m-%d %H:%M",
        "last_inventoried_fieldname": "last_inventoried",
        "first_inventoried_fieldname": "first_inventoried",
        "aggregated_collection_name": "hosts_collection",
        "aggregated_lookup_name": "hosts_lookup",
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

    ## ensure syslog source is setup for testing and has aggregation_fields set as needed for tests
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
    mgmt1_settings = {
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

    if "syslog" in ta_setup.service.inputs:
        ta_setup.service.inputs["syslog"].update(**syslog_settings)
    else:
        ta_setup.service.inputs.create(
            name="syslog", kind="oversight", **syslog_settings
        )

    if "mgmt1" in ta_setup.service.inputs:
        ta_setup.service.inputs["mgmt1"].update(**mgmt1_settings)
    else:
        ta_setup.service.inputs.create(
            name="mgmt1", kind="oversight", **mgmt1_settings
        )
    time.sleep(15)

    if "hosts_lookup" not in ta_setup.service.kvstore:
        ta_setup.service.kvstore.create("hosts_lookup")

    return ta_setup


def test_index_internal(splunk_setup):
    search = """ search index=_internal | stats count by sourcetype """
    result = splunk_setup.get_blocking_search_results(search)
    # print(result)
    assert result is not None
    for item in result:
        pp(item)


# test mark expired if over max_age
def test_mark_expired_if_over_max_age(splunk_setup):
    # Note: because we aren't running update_inventory first, must manually set initial state of expired=false
    # we assue timeformat is in format %Y-%m-%d %H:%M to get the expired_date
    max_age = int(
        splunk_setup.get_app_settings("ta_oversight_settings", "asset_groups")[
            "asset_group_1_max_age"
        ]
    )
    timeformat = splunk_setup.get_app_settings(
        "ta_oversight_settings", "additional_parameters"
    )["time_format"]

    expired_timestamp = (datetime.now() - timedelta(days=max_age - 1)).strftime(
        timeformat
    )
    search = """
    | makeresults
    | eval ip="1.1.1.1", asset_group="default", last_inventoried="{}", expired="false"
    | eval key=ip
    | table ip, key, asset_group, last_inventoried, expired
    | outputlookup hosts_lookup key_field=key
    | sendalert expire_inventory """.format(
        expired_timestamp
    )
    data_load = splunk_setup.get_blocking_search_results(search, debug=True)

    service = client.connect(**splunk_setup.splunk)
    pp(service.kvstore["hosts_lookup"].data.query)
    result = splunk_setup.get_blocking_search_results(
        "|inputlookup hosts_lookup_all", "ip"
    )
    assert len(result) == 1

    assert result["1.1.1.1"]["expired"] != "true"
    assert (
        result["1.1.1.1"]["expired"] > expired_timestamp
    )  ## expired time should be when script executes

    splunk_setup.clean_lookup("hosts_lookup")


def test_dont_mark_expired_if_under_max_age(splunk_setup):
    # Note: because we aren't running update_inventory first, must manually set initial state of expired=false
    # remdiner while running for splunk on python2, cant get tz so off by ~5hrs could be if server is UTC

    max_age = int(
        splunk_setup.get_app_settings("ta_oversight_settings", "asset_groups")[
            "asset_group_1_max_age"
        ]
    )
    timeformat = splunk_setup.get_app_settings(
        "ta_oversight_settings", "additional_parameters"
    )["time_format"]

    not_expired_timestamp = (datetime.now() - timedelta(days=max_age - 1)).strftime(
        timeformat
    )
    search = """
    | makeresults
    | eval ip="1.1.1.1", asset_group="default", last_inventoried="{}", expired="false"
    | eval key=ip
    | table key ip asset_group last_inventoried expired
    | outputlookup hosts_lookup  key_field=key
    | sendalert expire_inventory """.format(
        not_expired_timestamp
    )
    data_load = splunk_setup.get_blocking_search_results(search, debug=True)
    result = splunk_setup.get_blocking_search_results(
        "|inputlookup hosts_lookup_all", "ip"
    )
    assert len(result) == 1
    assert result["1.1.1.1"]["expired"] == "false"

    splunk_setup.clean_lookup("hosts_lookup")


# test delete component source lookup rows if mark expired
def test_delete_source_lookup_records_if_expired(splunk_setup):
    ## teardown any prior dirty tests
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()

    # test setup , populate source lookup
    max_age = int(
        splunk_setup.get_app_settings("ta_oversight_settings", "asset_groups")[
            "asset_group_1_max_age"
        ]
    )
    timeformat = splunk_setup.get_app_settings(
        "ta_oversight_settings", "additional_parameters"
    )["time_format"]

    timestamp = (datetime.now() - timedelta(days=max_age) + timedelta(days=1)).strftime(
        timeformat
    )
    expired_timestamp = (
        datetime.now() - timedelta(days=max_age) - timedelta(days=1)
    ).strftime(timeformat)
    active_timestamp = (datetime.now() - timedelta(days=max_age - 1)).strftime(
        timeformat
    )
    print("max_age={} expired_timestamp={} active_timestamp={} now={}".format(
        str(max_age), str(expired_timestamp), str(active_timestamp), str(datetime.now())
    ))

    data = {
        "ip": "1.1.1.1",
        "log_level": "debug",
        "_key": "1.1.1.1",
        "last_inventoried": expired_timestamp,
        "expired": "false",
    }
    data_payload = json.dumps(data)

    # test setup mock alert action update_inventory
    splunk_setup.service.kvstore["syslog_collection"].data.insert(data=data_payload)
    hosts_data = {
        "ip": "1.1.1.1",
        "last_inventoried": expired_timestamp,
        "first_inventoried": expired_timestamp,
        "syslog_last_inventoried": expired_timestamp,
        "expired": "false",
        "_key": "1.1.1.1",
    }
    hosts_payload = json.dumps(hosts_data)
    col = splunk_setup.service.kvstore["hosts_collection"].data
    col.insert(data=hosts_payload)

    ## test execution
    ## update timestamp on record in aggregated hosts_lookup, to trigger expiration
    search = """
    | inputlookup hosts_lookup 
    | sendalert expire_inventory param.log_level=DEBUG"""
    time.sleep(5)
    data_update = splunk_setup.get_blocking_search_results(search, debug=True)
    pp(data_update)
    get_log = "search index=_internal sourcetype=oversight:log script=expire_inventory earliest=-60m@m | eventstats max(run_id) as most_recent_run | where run_id==most_recent_run"
    get_log_results = splunk_setup.get_blocking_search_results(get_log)
    pp(get_log_results)

    # get alert action results
    expired_aggregation = splunk_setup.get_blocking_search_results(
        " |inputlookup hosts_lookup_all"
    )

    # validate test results
    pp(expired_aggregation)
    assert len(expired_aggregation) == 1
    assert expired_aggregation[0]["expired"] != "false"
    assert expired_aggregation[0]["syslog_last_inventoried"] is not None
    time.sleep(5)
    source_results = splunk_setup.get_blocking_search_results(
        " | inputlookup syslog_lookup"
    )
    assert len(source_results) == 0

    # test teardown
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()


# test dont delete componenet source lookup rows if not marked expired
def test_dont_delete_source_lookup_records_if_not_expired(splunk_setup):

    ## teardown any prior dirty tests
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()

    # test setup , populate source lookup
    max_age = int(
        splunk_setup.get_app_settings("ta_oversight_settings", "asset_groups")[
            "asset_group_1_max_age"
        ]
    )
    timeformat = splunk_setup.get_app_settings(
        "ta_oversight_settings", "additional_parameters"
    )["time_format"]

    timestamp = (datetime.now() - timedelta(days=max_age) + timedelta(days=1)).strftime(
        timeformat
    )
    expired_timestamp = (
        datetime.now() - timedelta(days=max_age) - timedelta(days=1)
    ).strftime(timeformat)
    active_timestamp = (datetime.now() - timedelta(days=max_age - 1)).strftime(
        timeformat
    )

    data = {
        "ip": "1.1.1.1",
        "log_level": "debug",
        "_key": "1.1.1.1",
        "last_inventoried": expired_timestamp,
        "expired": "false",
    }
    data_payload = json.dumps(data)

    # test setup mock alert action update_inventory
    splunk_setup.service.kvstore["syslog_collection"].data.insert(data=data_payload)
    hosts_data = {
        "ip": "1.1.1.1",
        "last_inventoried": active_timestamp,
        "first_inventoried": active_timestamp,
        "syslog_last_inventoried": active_timestamp,
        "expired": "false",
        "_key": "1.1.1.1",
    }
    hosts_payload = json.dumps(hosts_data)
    col = splunk_setup.service.kvstore["hosts_collection"].data
    col.insert(data=hosts_payload)

    search = """
    | inputlookup hosts_lookup_all
    | sendalert expire_inventory """
    expire_inventory_job = splunk_setup.get_blocking_search_results(search)

    time.sleep(1)
    search = """ | inputlookup hosts_lookup_all """
    aggregation_collection = splunk_setup.get_blocking_search_results(search)

    assert len(aggregation_collection) == 1
    assert aggregation_collection[0]["expired"] == "false"
    assert aggregation_collection[0]["syslog_last_inventoried"] is not None

    source_results = splunk_setup.get_blocking_search_results(
        " | inputlookup syslog_lookup"
    )
    assert len(source_results) == 1

    # teardown
    splunk_setup.service.kvstore["hosts_collection"].data.delete()
    splunk_setup.service.kvstore["syslog_collection"].data.delete()
