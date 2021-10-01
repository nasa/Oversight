# -*- coding: utf-8 -*-
import copy
import glob
import logging
import operator
import os
import re
import sys
import uuid
import json
from datetime import datetime, timedelta
from pprint import pprint as pp

import pyfakefs
import pytest
import pytest_mock

import tests
from tests import mock_splunk_service, mock_scheme, mock_arg

bindir = glob.glob("**/bin", recursive=True)
# hack for making sure we load the ucc-gen build dir
bindir = [i for i in bindir if "output" in i][0]
sys.path.insert(0, bindir)
print(sys.path)

TEST_DIR = tests.TEST_DIR
APP_NAME = tests.APP_NAME

APP_DIR = os.path.join(TEST_DIR, APP_NAME)
BIN_DIR = os.path.join(TEST_DIR, APP_NAME, "bin")

sys.path.insert(0, BIN_DIR)

print(sys.path)


import oversight_utils
import update_inventory
from update_inventory import InventoryUpdater

from tests import mock_splunk_service

ARN_PATTERN = re.compile(
    r"arn:aws:(?P<ResourceType>[^:]+):(?P<Region>[^:]+):(?P<Account>[^:]+)"
)


@pytest.fixture(scope="function")
@pytest.mark.no_cover
def test_obj(fs):
    fs.create_dir("/opt/splunk/var/log/splunk")
    test_obj = InventoryUpdater()
    settings = {
        "additional_parameters": {
            "primary_id_field": "ip",
            "primary_mv_id_field": "ips",
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "aggregated_lookup_name": "hosts_lookup",
            "aggregated_collection_name": "hosts_collection",
        },
        "logging": {"loglevel": "DEBUG"},
    }
    test_obj.app_settings = settings
    test_obj.HIDDEN_MVKEY_FIELD = "__mv_key"
    test_obj.kvstore_max_batch = int(1000)
    test_obj.run_id = "1"
    test_obj.source_name = "test"
    test_obj.service = mock_splunk_service(
        test_obj.APP_NAME,
        *[settings["additional_parameters"]["aggregated_collection_name"]]
    )

    test_obj.setup(test_obj.service, settings)
    return test_obj


test_data = [
    (  # test no input_event
        "%Y",
        {"first_seen": "1990", "last_seen": "2000"},
        None,
        {},
    ),
    (  # test input_event > last_seen
        "%m-%d-%Y",
        {"first_seen": "12-01-2015", "last_seen": "02-01-2020"},
        {"last_seen": "01-31-2021"},
        {
            "last_seen": "01-31-2021",
            "test_last_seen": "01-31-2021",
        },
    ),
    (  # test different timestamp format
        "%Y-%m-%d",
        {"first_seen": "2020-01-01", "last_seen": "2020-01-10"},
        {"last_seen": "2020-01-08"},
        {
            "test_last_seen": "2020-01-08",
        },
    ),
    (  # test no existing_record
        "%Y-%m",
        None,
        {"last_seen": "2020-01-01"},
        {
            "first_seen": "2020-01-01",
            "last_seen": "2020-01-01",
            "test_last_seen": "2020-01-01",
        },
    ),
    (  # test update test_last_seen but not last_seen
        "%d/%m/%Y",
        {
            "first_seen": "20/01/2021",
            "test_last_seen": "30/04/2021",
            "last_seen": "05/05/2021",
        },
        {"last_seen": "01/05/2021"},
        {"test_last_seen": "01/05/2021"},
    ),
    (  # test update everything but first_seen
        "%d-%m-%Y",
        {
            "first_seen": "28-01-2021",
            "test_last_seen": "25-05-2021",
            "last_seen": "20-06-2021",
        },
        {"last_seen": "01-07-2021"},
        {
            "test_last_seen": "01-07-2021",
            "last_seen": "01-07-2021",
        },
    ),
    ("%Y-%m-%d", {}, {}, {}),  # case all input null
]


@pytest.mark.parametrize(
    "time_format, existing_record, input_event, expected_output", test_data
)
def test_aggregate_timestamps(
    time_format, existing_record, input_event, expected_output, test_obj
):
    test_obj.TIME_FORMAT = time_format
    test_obj.last_checkin_source_field = "test_last_seen"
    output = test_obj.aggregate_timestamps(existing_record, input_event)
    assert output == expected_output


test_data = [
    (  # test input_event has no self.LAST_INVENTORIED_FIELD
        "%Y-%m",
        None,
        {"invalid_input_event": "foo", "status": "bad"},
    ),
    (  # existing record self.FIRST_INVENTORIED_FIELD not in self.TIME_FORMAT
        "%Y-%m",
        {"first_seen": "2020-01-01 00:01"},
        {"invalid_input_event": "foo", "status": "bad"},
    ),
    (  # existing record self.LAST_INVENTORIED_FIELD not in self.TIME_FORMAT
        "%Y-%m",
        {"last_seen": "2020-01-01 00:01"},
        {"invalid_input_event": "foo", "status": "bad"},
    ),
    (  # existing record self.last_checkin_source_field not in self.TIME_FORMAT
        "%Y-%m",
        {"test_last_seen": "2020-01-01 00:01"},
        {"invalid_input_event": "foo", "status": "bad"},
    ),
]


@pytest.mark.parametrize("time_format, existing_record, input_event", test_data)
def test_aggregate_timestamps_exceptions(
    time_format, existing_record, input_event, test_obj
):
    test_obj.TIME_FORMAT = time_format
    test_obj.last_checkin_source_field = "test_last_seen"
    with pytest.raises((SystemExit, ValueError)):
        test_obj.aggregate_timestamps(existing_record, input_event)


test_data = [("foo/boo", "fooboo"), ("fooboo", "fooboo"), (None, None)]


@pytest.mark.parametrize("input, expected_output", test_data)
def test_make_key_safe(input, expected_output, test_obj):
    output = test_obj.make_key_safe(input)
    assert output == expected_output


test_data = [
    ({"foo": "foo", "bar": "bar", "baz": "baz"}, ["foo"], {"foo": "foo"}),
    (
        {"foo": "foo", "bar": "barr", "baz": "baz"},
        ["foo", "bar"],
        {"foo": "foo", "bar": "barr"},
    ),
    ({"ip": "1.1.1.1"}, [], {}),
    ({"ip": "1.1.1.1", "status": "good"}, ["status"], {"status": "good"}),
    (
        {"ip": "1.1.1.1", "status": "good\nbad", "__mv_status": "$good$;$bad$"},
        ["status"],
        {"status": ["good", "bad"]},
    ),
    (  # test one of the aggregation fields is not present
        {"ip": "1.1.1.1", "status": "good"},
        ["status", "color"],
        {"status": "good", "color": None},
    ),
]


@pytest.mark.parametrize("input, aggregation_fields, expected_output", test_data)
def test_extract_aggregation_fields(
    input, aggregation_fields, expected_output, test_obj
):
    test_obj.aggregation_fields = aggregation_fields
    output = test_obj.extract_aggregation_fields(input)
    assert output == expected_output


test_data = [
    ("foo", ["foo"]),
    ("$one$", ["one"]),
    ("$one$;$two$;$three$", ["one", "two", "three"]),
    (None, None),
    ("", None),
]


@pytest.mark.parametrize("input_str, expected_output", test_data)
def test_parse_mvkey_string(input_str, expected_output, test_obj):
    output = test_obj.parse_mvkey_string(input_str)
    assert output == expected_output


test_data = [
    (None, None),
    ("one", ["one"]),
    ("one,two,  three", ["one", "two", "three"]),
]


@pytest.mark.parametrize("input_str, expected_output", test_data)
def test_get_normalized_fieldlist(input_str, expected_output, test_obj):
    output = test_obj.get_normalized_fieldlist(input_str)
    assert output == expected_output


def test_validate_alert_arguments(test_obj):
    """nothing should happen if required input parameters are included"""
    valid_input = {"configuration": {"source_name": "foo"}}

    result = test_obj.validate_alert_arguments(valid_input)
    assert result == None


def test_validate_alert_arguments_raises_exception(test_obj):
    """invalid input should raise ValueError"""
    invalid_input = {"configuration": {"foo": "bar"}}

    with pytest.raises(ValueError):
        result = test_obj.validate_alert_arguments(invalid_input)


def test_get_base_fields(test_obj):

    test_obj.id_field = "ip"
    test_obj.mv_id_field = None
    expected_output = {
        "_key": None,
        "ip": None,
        "test_last_seen": None,
        "first_seen": None,
        "last_seen": None,
        "ips": None,
    }
    test_obj.last_checkin_source_field = "test_last_seen"

    output = test_obj.get_base_fields()
    assert output == expected_output


test_data = [
    (  # test non-mv with no prior aggregated data
        {
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
        },
        {},
        None,
        None,
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "ip": "1.1.1.1",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-10-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
        },
        "1.1.1.1",
    ),
    (  # test non-mv with no prior aggregated data and aggregated_field
        {
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
        },
        {},
        None,
        ["foo"],
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "ip": "1.1.1.1",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-10-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
            "foo": "bar",
        },
        "1.1.1.1",
    ),
    (  # test non-mv with no prior aggregated data and many aggregated_fields
        {
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
            "zed": "led",
            "ignored": "dummy",
        },
        {},
        None,
        ["foo", "zed"],
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "ip": "1.1.1.1",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-10-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
            "foo": "bar",
            "zed": "led",
        },
        "1.1.1.1",
    ),
    (  # test non-mv with prior aggregated data
        {
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
        },
        {
            "1.1.1.1": {
                "_key": "1.1.1.1",
                "ips": ["1.1.1.1"],
                "ip": "1.1.1.1",
                "syslog_last_seen": "2021-05-01 00:01",
                "test_last_seen": "2021-06-01 00:01",
                "first_seen": "2021-05-01 00:01",
                "last_seen": "2021-06-01 00:01",
                "expired": "false",
                "asset_group": "default",
            }
        },
        None,
        None,
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "ip": "1.1.1.1",
            "syslog_last_seen": "2021-05-01 00:01",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-05-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
        },
        "1.1.1.1",
    ),
    (  # test mv without prior aggregated data
        {
            "_key": "1.1.1.1",
            "__mv_key": "$1.1.1.1$;$2.2.2.2$",
            "ips": ["1.1.1.1", "2.2.2.2"],
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
        },
        {},
        "__mv_key",
        None,
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1", "2.2.2.2"],
            "ip": "1.1.1.1",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-10-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
        },
        "1.1.1.1",
    ),
    (  # test mv with prior aggregated data
        {
            "_key": "1.1.1.1",
            "__mv_key": "$1.1.1.1$;$2.2.2.2$",
            "ip": "1.1.1.1",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "foo": "bar",
        },
        {
            "1.1.1.1": {
                "_key": "1.1.1.1",
                "ips": ["1.1.1.1", "2.2.2.2"],
                "ip": "1.1.1.1",
                "syslog_last_seen": "2021-05-01 00:01",
                "test_last_seen": "2021-06-01 00:01",
                "first_seen": "2021-05-01 00:01",
                "last_seen": "2021-06-01 00:01",
                "expired": "false",
                "asset_group": "default",
            }
        },
        "__mv_key",
        None,
        "test_last_seen",
        {
            "_key": "1.1.1.1",
            "ips": ["1.1.1.1", "2.2.2.2"],
            "ip": "1.1.1.1",
            "syslog_last_seen": "2021-05-01 00:01",
            "test_last_seen": "2021-10-01 00:01",
            "first_seen": "2021-05-01 00:01",
            "last_seen": "2021-10-01 00:01",
            "expired": "false",
            "asset_group": "default",
        },
        "1.1.1.1",
    ),
]


@pytest.mark.parametrize(
    "input_event, prior_aggregated, line_mv_key_field, aggregated_fields, output_timestamp_fieldname, expected_output_event, expected_output_key",
    test_data,
)
def test_aggregate_event(
    test_obj,
    input_event,
    prior_aggregated,
    line_mv_key_field,
    aggregated_fields,
    output_timestamp_fieldname,
    expected_output_event,
    expected_output_key,
):

    # test setup - input specific
    test_obj.last_checkin_source_field = output_timestamp_fieldname
    test_obj.id_field = "ip"  # key field in incomming data
    test_obj.mv_id_field = "ips" if line_mv_key_field else None
    test_obj.mv_key_field = line_mv_key_field
    test_obj.aggregation_fields = aggregated_fields
    test_obj.asset_group = "default"
    test_obj.TIME_FORMAT = "%Y-%m-%d %H:%M"

    base_fields = test_obj.get_base_fields()

    # test setup - object state
    test_obj.aggregation_cache = copy.deepcopy(prior_aggregated)
    output_key, output_event = test_obj.initialize_output_event(
        input_event, base_fields
    )
    print("output_event:{}".format(str(output_event)))

    # method under test
    output_event, output_key = test_obj.aggregate_event(
        input_event, output_event, output_key
    )
    if not output_event == expected_output_event:
        print("input_event:")
        pp(input_event)
        print("prior_aggregated cache:")
        pp(prior_aggregated)
        print("expected output_event")
        pp(expected_output_event)

    assert output_event == expected_output_event
    assert output_key == expected_output_key


test_data = [
    (  # default test case
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
                "time_format": "%Y-%m-%d",
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": None,
            "id_field": "ip",
            "mv_id_field": None,
        },
        {
            "write_cache": {},
            "kvstore_max_batch": 3,
            "mv_key_field": [],
            "mv_id_field": None,
            "id_field": "ip",
            "aggregation_fields": None,
            "asset_group": "default",
            "FIRST_INVENTORIED_FIELD": "first_seen",
            "HIDDEN_MVKEY_FIELD": "__mv_key",
            "AGGREGATED_COLLECTION_NAME": "hosts_collection",
            "AGGREGATED_LOOKUP_NAME": "hosts_lookup",
            "LAST_INVENTORIED_FIELD": "last_seen",
            "EXPIRATION_EXPRESSION": None,
            "aggregation_cache": {},
            "params": {},
            "VISIBLE_KEY_FIELD": "ip",
            "VISIBLE_MVKEY_FIELD": None,
            "last_checkin_source_field": "test_last_seen",
            "source_name": "test",
            "TIME_FORMAT": "%Y-%m-%d",
        },
    ),
    (  # validate self.id_field becomes id_field_rename when present in input_settings
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
                "time_format": "%Y-%m-%d",
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": "renamed_ip",
            "id_field": "ip",
            "mv_id_field": None,
        },
        {
            "write_cache": {},
            "kvstore_max_batch": 3,
            "mv_key_field": [],
            "mv_id_field": None,
            "id_field": "renamed_ip",
            "aggregation_fields": None,
            "asset_group": "default",
            "FIRST_INVENTORIED_FIELD": "first_seen",
            "HIDDEN_MVKEY_FIELD": "__mv_key",
            "AGGREGATED_COLLECTION_NAME": "hosts_collection",
            "AGGREGATED_LOOKUP_NAME": "hosts_lookup",
            "LAST_INVENTORIED_FIELD": "last_seen",
            "EXPIRATION_EXPRESSION": None,
            "aggregation_cache": {},
            "params": {},
            "VISIBLE_KEY_FIELD": "ip",
            "VISIBLE_MVKEY_FIELD": None,
            "last_checkin_source_field": "test_last_seen",
            "source_name": "test",
            "TIME_FORMAT": "%Y-%m-%d",
        },
    ),
]


@pytest.mark.parametrize(
    "app_settings, input_settings, expected_attribute_values", test_data
)
def test_setup_attributes(test_obj, app_settings, input_settings, expected_attribute_values):
    payload = {"configuration": {"source_name": "test", "log_level": "DEBUG"}}

    # test setup
    del test_obj.app_settings
    test_obj.service.inputs.add(payload["configuration"].get("source_name"))
    test_obj.setup_attributes(test_obj.service, payload, app_settings, input_settings)
    configured_log_level = logging.getLevelName(test_obj.logger.root.level)
    assert configured_log_level == "DEBUG"

    obj_locals = test_obj.__dict__
    del obj_locals["run_id"]
    del obj_locals["service"]
    del obj_locals["aggregated_collection"]
    del obj_locals["logger"]

    print(obj_locals)
    if not obj_locals == expected_attribute_values:
        print("input_settings:")
        pp(input_settings)  
    assert obj_locals == expected_attribute_values


test_data = [
    (  # case source_name param specified is incorrect (doesn't match any of the input definitions created already)
        {"configuration": {"source_name": "invalid_test"}},
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": None,
            "id_field": "ip",
            "mv_id_field": None,
        },
        "test",
    ),
    (  # case loglevel not definied anywhere
        {"configuration": {"source_name": "test"}},
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
            },
            "logging": {},
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": None,
            "id_field": "ip",
            "mv_id_field": None,
        },
        "test",
    ),
    (  # case no source name supplied
        {"configuration": {}},
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": None,
            "id_field": "ip",
            "mv_id_field": None,
        },
        "test",
    ),
    (  # case logging app setting stanza missing
        {"configuration": {"source_name": "test"}},
        {
            "additional_parameters": {
                "first_inventoried_fieldname": "first_seen",
                "last_inventoried_fieldname": "last_seen",
                "aggregated_collection_name": "hosts_collection",
                "aggregated_lookup_name": "hosts_lookup",
                "id_field_rename": None,
                "primary_id_field": "ip",
                "primary_mv_id_field": None,
            }
        },
        {
            "asset_group": None,
            "aggregation_fields": None,
            "id_field_rename": None,
            "id_field": "ip",
            "mv_id_field": None,
        },
        "test",
    ),
]


@pytest.mark.parametrize(
    "payload, app_settings, input_definition_name, input_settings", test_data
)
def test_setup_attributes_with_exceptions(
    payload, app_settings, input_settings, input_definition_name, test_obj
):

    # test setup
    test_obj.source_name = payload["configuration"].get("source_name")
    test_obj.service.inputs.add(input_definition_name)

    with pytest.raises(ValueError):
        # method under test
        test_obj.setup_attributes(
            test_obj.service, payload, app_settings, input_settings
        )


test_data = [
    (
        {
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
            "expired": "false",
            "last_seen": "2020-01-01",
        },
        "ip",
        True,
    ),
    ({"ip": "1.1.1.1", "last_seen": "2020-01-01", "expired": "false"}, "ip", False),
    ({"_key": "1.1.1.1", "expired": "false", "last_seen": "2020-01-01"}, "ip", False),
    ({"_key": "1.1.1.1", "ip": "1.1.1.1", "last_seen": "2020-01-01"}, "ip", False),
    ({"_key": "1.1.1.1", "ip": "1.1.1.1", "expired": "false"}, "ip", False),
    ({}, "ip", False),
]


@pytest.mark.parametrize("event, id_field_name, expected_output", test_data)
def test_validate_input_event(test_obj, event, id_field_name, expected_output):
    # test_obj.service.inputs.add(test_input)
    test_obj.id_field = id_field_name
    output = test_obj.validate_input_event(event)
    assert output == expected_output


test_data = [
    (  # case no pre-cached data , no mv_id_field
        {
            "ip": "1.1.1.1",
            "_key": "1.1.1.1",
            "expired": "false",
            "last_seen": "2021-01-01",
        },
        dict.fromkeys(
            list(
                set(["ip", "ips", "_key", "test_last_seen", "first_seen", "last_seen"])
            )
        ),
        {},
        {
            "ip": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "_key": "1.1.1.1",
            "first_seen": None,
            "last_seen": None,
            "test_last_seen": None,
        },
        "1.1.1.1",
    ),
    (  # case pre-cached data with aggregation field from another input source, no mv_id_field
        {
            "ip": "1.1.1.1",
            "_key": "1.1.1.1",
            "expired": "false",
            "last_seen": "2021-01-01",
        },
        dict.fromkeys(
            list(
                set(["ip", "ips", "_key", "test_last_seen", "first_seen", "last_seen"])
            )
        ),
        {
            "1.1.1.1": {
                "_key": "1.1.1.1",
                "ip": "1.1.1.1",
                "ips": ["1.1.1.1"],
                "first_seen": "2019-10-10",
                "last_seen": "2020-12-12",
                "test_last_seen": "2020-12-12",
                "status": "good",
                "expired": "false",
            }
        },
        {
            "ip": "1.1.1.1",
            "ips": ["1.1.1.1"],
            "_key": "1.1.1.1",
            "first_seen": "2019-10-10",
            "last_seen": "2020-12-12",
            "test_last_seen": "2020-12-12",
            "status": "good",
            "expired": "false",
        },
        "1.1.1.1",
    ),
]


@pytest.mark.parametrize(
    "input_event, base_fields, collection_cache, expected_output_key, expected_output_event",
    test_data,
)
def test_initialize_output_event(
    test_obj,
    input_event,
    base_fields,
    collection_cache,
    expected_output_key,
    expected_output_event,
):
    # test setup
    test_obj.aggregation_cache = copy.deepcopy(collection_cache)
    test_obj.id_field = "ip"
    test_obj.mv_id_field = None
    test_obj.mv_key_field = []
    assert test_obj.validate_input_event(input_event)

    output_event, output_key = test_obj.initialize_output_event(
        input_event, base_fields
    )
    assert output_key == expected_output_key

    if not output_event == expected_output_event:
        print("output_event:")
        pp(output_event)
        print("expected_output_event:")
        pp(expected_output_event)
    assert output_event == expected_output_event


test_data = [
    ({1, 2}, {1, 2}, None),
    ({1, 2, 3}, {4}, [1, 2, 3, 4]),
    ({5}, {6, 7, 8}, [5, 6, 7, 8]),
    ({1, 2, 3}, {1, 2}, [1, 2, 3]),
    (None, None, None),
    ({1}, None, [1]),
    (None, {1, 2}, [1, 2]),
]


@pytest.mark.parametrize("current_mvkey, incoming_mvkey, expected_output", test_data)
def test_caculate_new_mvkeys(current_mvkey, incoming_mvkey, expected_output, test_obj):
    output = test_obj.calculate_new_mvkeys(current_mvkey, incoming_mvkey)
    assert output == expected_output


test_data = [
    ([], {}, [], []),  # case null-input-null-output
    (  # case null-records-to-review-null-output
        [],
        {"1.1.1.1": {"_key": "1.1.1.1", "status": "ok"}},
        [],
        [],
    ),
    (  # case all records ok
        ["1", "2"],
        {"1": {"_key": "1", "ips": ["1", "2"]}, "2": {"_key": "2", "ips": ["1", "2"]}},
        {"1": {"_key": "1", "ips": ["1", "2"]}, "2": {"_key": "2", "ips": ["1", "2"]}},
        [],
    ),
    (  # case cached record needs updating
        ["1", "2"],
        {"1": {"_key": "1", "ips": ["1", "2"]}, "2": {"_key": "2", "ips": ["1", "2"]}},
        {"1": {"_key": "1", "ips": ["1"]}, "2": {"_key": "2", "ips": ["2"]}},
        ["1", "2"],
    ),
    (  # case phase_one  record needs updating
        ["1", "2"],
        {"1": {"_key": "1", "ips": ["1"]}, "2": {"_key": "2", "ips": ["2"]}},
        {"1": {"_key": "1", "ips": ["1", "2"]}, "2": {"_key": "2", "ips": ["1", "2"]}},
        ["1", "2"],
    ),
]


@pytest.mark.parametrize(
    "records_to_review, phase_one_records, aggregation_cache, expected_output",
    test_data,
)
def test_identify_records_with_outdated_mvkeys(
    aggregation_cache, records_to_review, phase_one_records, expected_output, test_obj
):
    test_obj.aggregation_cache = aggregation_cache
    output = test_obj.identify_records_with_outdated_mvkeys(
        records_to_review, phase_one_records
    )
    assert output == expected_output
