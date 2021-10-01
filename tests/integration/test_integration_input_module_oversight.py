# -*- coding: utf-8 -*-
import inspect
import os
import re
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
        service = client.connect(**self.splunk)
        for _ in range(30):
            rr = results.ResultsReader(service.jobs.oneshot(search_query))
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
        self, search_query, key_field=None, **search_kwargs
    ):
        # https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython
        output_list = []
        output_dict = {}
        kwargs = {"exec_mode": "blocking", "count": "0"}

        if search_kwargs:
            kwargs.update(search_kwargs)
        service = client.connect(**self.splunk)
        print("searching with args:{},  {}".format(str(kwargs), search_query))
        job = service.jobs.create(search_query, **kwargs)
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
        search = """ search index=_internal sourcetype=oversight:log name=* status=completed earliest=-5m@m """
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

    def delete_input_kos(self, name):
        service = client.connect(**self.splunk)
        if name in service.inputs:
            service.inputs.delete(name=name)

        if "{}_lookup".format(name) in service.confs["transforms"]:
            n = "{}_lookup".format(name)
            service.confs["transforms"][n].delete()

        if "{}_collection".format(name) in service.kvstore:
            service.kvstore.delete("{}_collection".format(name))

        if "{}_hosts".format(name) in service.saved_searches:
            service.saved_searches.delete("{}_hosts".format(name))


@pytest.fixture(scope="session")
def splunk_setup(splunk):
    splunk["app"] = tests.APP_NAME
    print("Connecting with splunk settings: {}".format(str(splunk)))
    ta_setup = TASetup(splunk)
    # this lookup is shipped by default, great use case
    ta_setup.wait_for_lookup("geo_attr_countries")
    # ta_setup.wait_for_oversight_setup()
    ta_setup.update_app_setting(
        "ta_oversight_settings", "logging", **{"loglevel": "DEBUG"}
    )
    time.sleep(10)
    return ta_setup


def test_integration_input_module_index_internal(splunk_setup):
    search = """ search index=_internal | stats count by sourcetype """
    result = splunk_setup.get_blocking_search_results(search)
    # print(result)
    assert result is not None


def test_simple_changed_app_settings(splunk_setup):
    """test that changing app settings updates knowledge objects correctly"""

    # Test setup
    aggregated_collection_name = "students_collection"
    aggregated_lookup_name = "students_lookup"
    first_inventoried_fieldname = "first_seen"
    last_inventoried_fieldname = "last_seen"
    primary_id_field = "studentID"
    new_settings = {
        "aggregated_collection_name": aggregated_collection_name,
        "aggregated_lookup_name": aggregated_lookup_name,
        "last_inventoried_fieldname": last_inventoried_fieldname,
        "first_inventoried_fieldname": first_inventoried_fieldname,
        "primary_id_field": primary_id_field,
    }
    pp(new_settings)
    # Test setup - update app settings
    splunk_setup.update_app_setting(
        "ta_oversight_settings", "additional_parameters", **new_settings
    )

    time.sleep(5)
    service = client.connect(**splunk_setup.splunk)
    if (
        "ta_oversight_settings" in service.confs
        and "aggregated_lookup_name" in service.confs["ta_oversight_settings"]
    ):
        assert (
            service.confs["ta_oversight_settings"]["aggregated_lookup_name"]
            == aggregated_lookup_name
        )
    elif "ta_oversight_settings" in service.confs:
        pp(str(service.confs["ta_oversight_settings"]))
    else:
        print(" no ta_oversight_settings file could be found")
        assert False

    input_parameters = {
        "cron": "0 23 * * *",
        "id_field": "student_id",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "first_name, last_name, classroom, teacher_name",
    }
    input_name = "attendence"
    pp(input_parameters)
    # test setup - add new input
    if input_name not in service.inputs:
        print("creating input={}".format(input_name))
        splunk_setup.add_input_stanza(
            name=input_name, kind="oversight", **input_parameters
        )
    else:
        print("existing {} found, updating".format(input_name))
        service.inputs[input_name].post(**input_parameters)
    time.sleep(20)

    # validation
    lookup_name = "{}_lookup".format(input_name)
    aggregation_lookup_name = "{}_lookup".format(aggregated_lookup_name)

    if lookup_name not in service.confs["transforms"]:
        pp([i.name for i in service.confs["transforms"]])
        audit_log = splunk_setup.get_blocking_search_results(
            "search index=_internal (ERROR sourcetype=splunkd oversight) OR sourcetype=oversight:log | eventstats max(run_id) as most_recent_runid |fillnull value=0 run_id| where run_id == most_recent_runid  OR run_id==0 | table _time _raw| sort _time desc"
        )
        pp(audit_log)
    assert "{}_lookup".format(input_name) in service.confs["transforms"]
    assert "{}_lookup_all".format(input_name) in service.confs["transforms"]
    assert aggregated_collection_name in service.kvstore
    assert aggregated_lookup_name in service.confs["transforms"]
    assert "{}_all".format(aggregated_lookup_name) in service.confs["transforms"]

    assert (
        primary_id_field
        in service.confs["transforms"][aggregated_lookup_name].content()["fields_list"]
    )
    assert (
        primary_id_field
        in service.confs["transforms"][
            "{}_all".format(aggregated_lookup_name)
        ].content()["fields_list"]
    )

    ## teardown
    service.inputs.delete(input_name, kind="oversight")

    new_settings = {
        "aggregated_collection_name": "hosts_collection",
        "aggregated_lookup_name": "hosts_lookup",
        "last_inventoried_fieldname": "last_inventoried",
        "first_inventoried_fieldname": "first_inventoried",
        "primary_id_field": "ip",
    }
    # Test setup - update app settings
    splunk_setup.update_app_setting(
        "ta_oversight_settings", "additional_parameters", **new_settings
    )
    current_settings = splunk_setup.get_app_settings(
        "ta_oversight_settings", "additional_parameters"
    )
    pp(current_settings)
    assert current_settings["aggregated_lookup_name"] == "hosts_lookup"


def test_simple_input_example(splunk_setup):

    # load required configurations
    input_parameters = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
        "source_fields": "log_level",
        "aggregation_fields": "log_level",
    }
    service = client.connect(**splunk_setup.splunk)
    print(service.inputs.kinds)
    if "syslog2" not in service.inputs:
        splunk_setup.add_input_stanza(
            name="syslog2", kind="oversight", **input_parameters
        )
    else:
        service.inputs["syslog2"].post(**input_parameters)

    time.sleep(20)
    search = """ search index=_internal input=syslog2 sourcetype=oversight:log earliest=-5m@m | table _time _raw"""
    wait_for_completion = splunk_setup.get_blocking_search_results(search)
    assert wait_for_completion is not None
    print("oversight log")
    pp(wait_for_completion)

    # search_definition = splunk_setup.get_stanza("savedsearches", "syslog2_hosts")
    # print(search_definition)
    print("search names")

    print("audit log")
    audit_log = splunk_setup.get_blocking_search_results(
        "search index=_internal (ERROR sourcetype=splunkd oversight) OR sourcetype=oversight:log | eventstats max(run_id) as most_recent_runid |fillnull value=0 run_id| where run_id == most_recent_runid  OR run_id==0 | table _time _raw"
    )
    pp(audit_log)

    ## validate results
    assert "syslog2_lookup" in service.confs["transforms"]
    assert "syslog2_collection" in service.kvstore
    assert (
        "syslog2_last_inventoried"
        in service.confs["transforms"]["hosts_lookup"].content()["fields_list"]
    )
    assert (
        "syslog2_last_inventoried"
        in service.confs["transforms"]["hosts_lookup_all"].content()["fields_list"]
    )
    assert "syslog2_hosts" in service.saved_searches
    splunk_setup.delete_input_kos("syslog2")


def test_generating_input_example(splunk_setup):

    # load required configurations
    input_name = "tstats_foo"
    input_parameters = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "|tstats count by sourcetype",
        "source_fields": "log_level",
        "aggregation_fields": "log_level",
    }
    service = client.connect(**splunk_setup.splunk)
    print(service.inputs.kinds)
    if "input_name" not in service.inputs:
        splunk_setup.add_input_stanza(
            name=input_name, kind="oversight", **input_parameters
        )
    else:
        service.inputs[input_name].post(**input_parameters)

    time.sleep(20)
    search = """ search index=_internal input={} sourcetype=oversight:log earliest=-5m@m | table _time _raw""".format(input_name)
    wait_for_completion = splunk_setup.get_blocking_search_results(search)
    assert wait_for_completion is not None
    pp(wait_for_completion)

    print("audit log")
    audit_log = splunk_setup.get_blocking_search_results(
        "search index=_internal (ERROR sourcetype=splunkd oversight) OR sourcetype=oversight:log | eventstats max(run_id) as most_recent_runid |fillnull value=0 run_id| where run_id == most_recent_runid  OR run_id==0 | table _time _raw"
    )
    pp(audit_log)

    ## validate results
    assert "{}_lookup".format(input_name) in service.confs["transforms"]
    assert "{}_collection".format(input_name) in service.kvstore
    assert (
        "{}_last_inventoried".format(input_name)
        in service.confs["transforms"]["hosts_lookup"].content()["fields_list"]
    )
    assert (
        "{}_last_inventoried".format(input_name)
        in service.confs["transforms"]["hosts_lookup_all"].content()["fields_list"]
    )
    assert "{}_hosts".format(input_name) in service.saved_searches
    splunk_setup.delete_input_kos(input_name)



test_data = [
    (
        {
            "cron": "0 23 * * *",
            "id_field": "ip",
            "inventory_source": "1",
            "source_filter": "search ip!=192* and ip!=10.*",
            "inventory_filter": "search computer_name!=system1",
            "id_field_rename": "key",
            "enrichment_expression": "lookup foo test_lookup OUTPUT bar",
            "enrichment_fields": "bar",
            "replicate": "0",
            "source_expression": "index=foo",
            "source_fields": "log_level, computer_name",
            "aggregation_fields": "log_level",
        },
        "test",
        "index=foo",
        [
            "_key",
            "last_inventoried",
            "key",
            "bar",
            "log_level",
            "computer_name",
            "expired",
        ],
        "lookup foo test_lookup OUTPUT bar",
        "search ip!=192* and ip!=10.*",
        "search computer_name!=system1",
    ),
    (  # test case no optional settings
        {
            "cron": "0 23 * * *",
            "id_field": "ip",
            "inventory_source": "1",
            "replicate": "0",
            "source_expression": "index=foo",
        },
        "test_thing",
        "index=foo",
        ["_key", "last_inventoried", "ip", "expired"],
        None,
        None,
        None,
    ),
]


@pytest.mark.parametrize(
    "input_parameters, input_name, expected_source, expected_fields, expected_enrichment, expected_source_filter, expected_inventory_filter",
    test_data,
)
def test_simple_macro_definitions(
    input_parameters,
    input_name,
    expected_source,
    expected_fields,
    expected_enrichment,
    expected_source_filter,
    expected_inventory_filter,
    splunk_setup,
):
    service = client.connect(**splunk_setup.splunk)
    print(service.inputs.kinds)
    if input_name not in service.inputs:
        service.inputs.create(name=input_name, kind="oversight", **input_parameters)
    else:
        service.inputs[input_name].post(**input_parameters)

    time.sleep(20)
    search = """ search index=_internal sourcetype=oversight:log earliest=-5m@m | table _time _raw"""
    wait_for_completion = splunk_setup.get_blocking_search_results(search)
    assert wait_for_completion is not None
    print("oversight log")
    time.sleep(5)
    pp(wait_for_completion)

    # check test_source
    if expected_source:
        macro_name = "{}_source".format(input_name)
        assert (
            expected_source
            == service.confs["macros"][macro_name].content()["definition"]
        )

    # check test_fields; convert to set because order doesnt matter in splunk
    if expected_fields:
        macro_name = "{}_fields".format(input_name)
        assert set(expected_fields) == set(
            service.confs["macros"][macro_name].content()["definition"].split(",")
        )

    # check enrichment_expression
    if expected_enrichment:
        macro_name = "{}_enrichment_expression".format(input_name)
        assert (
            expected_enrichment
            == service.confs["macros"][macro_name].content()["definition"]
        )

    # check test_source_filter
    if expected_source_filter:
        macro_name = "{}_source_filter".format(input_name)

        assert (
            expected_source_filter
            == service.confs["macros"]["test_source_filter"].content()["definition"]
        )

    # check test_inventory_filter
    if expected_inventory_filter:
        macro_name = "{}_inventory_filter".format(input_name)
        assert (
            expected_inventory_filter
            == service.confs["macros"]["test_inventory_filter"].content()["definition"]
        )

    # check kvstore created
    collection_name = "{}_collection".format(input_name)
    assert collection_name in service.kvstore

    # check saved search created
    search_name = "{}_hosts".format(input_name)
    assert search_name in service.saved_searches

    # check 'test_last_inventoried' added to hosts_lookup fieldlist
    field_name = "{}_last_inventoried".format(input_name)
    assert field_name in service.confs["transforms"]["hosts_lookup"]["fields_list"]
    assert field_name in service.confs["transforms"]["hosts_lookup_all"]["fields_list"]
    splunk_setup.delete_input_kos(input_name)


test_data = [
    ("test_\thing"),
    ("test_:thing"),
    ("test_-thing"),
    ("test_/thing"),
    ("test_.thing"),
    ("test_^thing"),
    ("test_%thing"),
    ("test_#thing"),
    ("test_!thing"),
    ("test_(thing"),
]


@pytest.mark.parametrize("input_name", test_data)
def test_escape_input_names_safely(input_name, splunk_setup):

    payload = {
        "cron": "0 23 * * *",
        "id_field": "ip",
        "inventory_source": "1",
        "replicate": "0",
        "source_expression": "index=foo",
    }

    input_name = (
        input_name.replace(" ", "_")
        .replace("-", "_")
        .replace(".", "_")
        .replace("/", "_")
    )

    service = client.connect(**splunk_setup.splunk)
    print(service.inputs.kinds)
    if input_name not in service.inputs:
        service.inputs.create(name=input_name, kind="oversight", **payload)
    else:
        service.inputs[input_name].post(**payload)

    time.sleep(10)

    assert input_name in service.inputs

    service.inputs[input_name].update(**payload)
    assert input_name in service.inputs

    time.sleep(10)
    service.inputs.delete(input_name)
