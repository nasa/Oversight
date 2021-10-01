## -*- coding: utf-8 -*-
## Tests for modular input 'oversight' aka dynamic configuration builder Script
import glob
import logging
import operator
import os
import re
import sys
from datetime import datetime, timedelta
from pprint import pprint as pp

import pyfakefs
import pytest

import tests

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


import import_declare_test
import input_module_oversight as lib
import oversight_utils
from splunklib.binding import AuthenticationError, HTTPError
from tests import mock_splunk_service, mock_scheme, mock_arg


@pytest.fixture(scope="function")
@pytest.mark.no_cover
def test_obj(fs):
    fs.create_dir("/opt/splunk/var/log/splunk")
    assert os.path.isdir("/opt/splunk/var/log")
    fs.add_real_directory("tests/data/", target_path="/opt/data")
    test_obj = lib.OversightBuilder()
    test_obj.name = "test"  # because this is done in setup() not init()
    test_obj.params = {"name": "test"}
    settings = {
        "additional_parameters": {
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "time_format": "%Y-%m-%d %H:%M",
            "primary_id_field": "ip",
            "primary_mv_id_field": "ip_addresses",
            "aggregated_collection_name": "hosts_lookup",
            "aggregated_lookup_name": "hosts_lookup",
            "default": 7,  # normalized
        },
        "logging": {"loglevel": "DEBUG"},
    }
    test_obj.settings = settings["additional_parameters"]
    test_obj.setup(mock_splunk_service(test_obj.APP_NAME), settings)
    test_obj.logger.setLevel("DEBUG")

    return test_obj


test_data = [
    ("test", None, "`test`"),
    ("test", ["1"], "`test(1)`"),
    ("test", ["1", "2"], "`test(1,2)`"),
]


@pytest.mark.parametrize("input_name, input_arg_list, expected_output", test_data)
def test_macro_string(input_name, input_arg_list, expected_output):
    if input_arg_list:
        output = lib.macro_string(input_name, *input_arg_list)
    else:
        output = lib.macro_string(input_name)

    assert output == expected_output


test_data = [
    (
        {
            "primary_id_field": "ip",
            "primary_mv_id_field": "ips",
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
        },
        {
            "inventory_source": "true",
            "name": "source1",
            "aggregation_fields": ["cpu", "os"],
        },
        ["ip", "ips", "last_seen", "first_seen", "cpu", "os", "source1_last_seen"],
    )
]


@pytest.mark.parametrize("app_settings, input_params, expected_output", test_data)
def test_get_aggregation_fieldlist(
    app_settings, input_params, expected_output, test_obj
):
    # test setup
    test_obj.settings = app_settings
    test_obj.params = input_params

    # test execution
    output = test_obj.get_aggregation_fieldlist()

    print("output: {}".format(str(output)))
    print("expected_output: {}".format(str(expected_output)))

    assert set(output) == set(expected_output)


test_data = [
    (  # test case all macros present
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "enrichment_expression_macro_name": "enrichment_expression_macro_name",
            "original_id_field": "old_id",
            "id_field_rename": "new_id",
            "source_filter_macro_name": "source_filter_macro_name",
            "inventory_filter_macro_name": "inventory_filter_macro_name",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
        },
        "`source_expression_macro_name` | `eval_last_inventoried` | `enrichment_expression_macro_name` | `set_id(old_id,new_id)` | `sort_dedup(new_id)` | `set_key(new_id)` | `source_filter_macro_name` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)` | `inventory_filter_macro_name`",
    ),
    (  # test case no filters
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "enrichment_expression_macro_name": "enrichment_expression_macro_name",
            "original_id_field": "old_id",
            "id_field_rename": "new_id",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
        },
        "`source_expression_macro_name` | `eval_last_inventoried` | `enrichment_expression_macro_name` | `set_id(old_id,new_id)` | `sort_dedup(new_id)` | `set_key(new_id)` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)`",
    ),
    (  # test case not renaming id field
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "enrichment_expression_macro_name": "enrichment_expression_macro_name",
            "original_id_field": "old_id",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
        },
        "`source_expression_macro_name` | `eval_last_inventoried` | `enrichment_expression_macro_name` | `sort_dedup(old_id)` | `set_key(old_id)` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)`",
    ),
    (  # test case no enrichment no filters
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "original_id_field": "old_id",
            "source_filter_macro_name": "source_filter_macro_name",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
        },
        "`source_expression_macro_name` | `eval_last_inventoried` | `sort_dedup(old_id)` | `set_key(old_id)` | `source_filter_macro_name` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)`",
    ),
    (  # test case no enrichment but source filter present and rename id
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "original_id_field": "old_id",
            "id_field_rename": "new_id",
            "source_filter_macro_name": "source_filter_macro_name",
            "inventory_filter_macro_name": "inventory_filter_macro_name",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
        },
        "`source_expression_macro_name` | `eval_last_inventoried` | `set_id(old_id,new_id)` | `sort_dedup(new_id)` | `set_key(new_id)` | `source_filter_macro_name` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)` | `inventory_filter_macro_name`",
    ),
    (  # test case no enrichment no filters and non-default last_inventoried_fieldname (from app settings)
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "original_id_field": "old_id",
            "source_filter_macro_name": "source_filter_macro_name",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
            "last_inventoried_fieldname": "last_seen",
        },
        "`source_expression_macro_name` | `eval_last_seen` | `sort_dedup(old_id)` | `set_key(old_id)` | `source_filter_macro_name` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)`",
    ),
    (  # test case supported generating_command
        {
            "source_expression_macro_name": "source_expression_macro_name",
            "enrichment_expression_macro_name": "enrichment_expression_macro_name",
            "original_id_field": "old_id",
            "fields_macro_name": "fields_macro_name",
            "transforms_name": "transforms_name",
            "supported_generating_command": True,
        },
        "| `source_expression_macro_name` | `eval_last_inventoried` | `enrichment_expression_macro_name` | `sort_dedup(old_id)` | `set_key(old_id)` | `set_not_expired` | table `fields_macro_name` | `outputlookup(transforms_name)`",
    ),
]


@pytest.mark.parametrize("kwargs, expected_output", test_data)
def test_build_search_query(kwargs, expected_output, test_obj):
    output = test_obj.build_search_query(**kwargs)
    print("output:   {}\nexpected: {}".format(output, expected_output))
    assert output == expected_output


test_data = [
    (  # test case all fields present, all lists are singletons
        {
            "id_field_rename": "id_field_rename",
            "id_field": "id_field",
            "source_fields": ["source1"],
            "enrichment_fields": ["enrich1"],
            "mv_id_field": "mv_id_field",
            "aggregation_fields": ["agg1"],
        },
        [
            "last_seen",
            "_key",
            "id_field_rename",
            "source1",
            "enrich1",
            "mv_id_field",
            "agg1",
            "expired",
        ],
    ),
    (  # test case all fields present, all lists populated
        {
            "id_field_rename": "id_field_rename",
            "id_field": "id_field",
            "source_fields": ["source1", "source2"],
            "enrichment_fields": ["enrich1", "enrich2"],
            "mv_id_field": "mv_id_field",
            "aggregation_fields": ["agg1", "agg2"],
        },
        [
            "last_seen",
            "_key",
            "id_field_rename",
            "source1",
            "source2",
            "enrich1",
            "enrich2",
            "mv_id_field",
            "agg1",
            "agg2",
            "expired",
        ],
    ),
    (  # test case no optional fields
        {
            "id_field": "id_field",
            "mv_id_field": "mv_id_field",
            "id_field_rename": None,
            "source_fields": None,
            "enrichment_fields": None,
            "aggregation_fields": None,
        },
        ["last_seen", "_key", "id_field", "mv_id_field", "expired"],
    ),
]


@pytest.mark.parametrize("params, expected_output", test_data)
def test_build_lookup_fieldlist(params, expected_output, test_obj):
    test_obj.params = params
    test_obj.params["name"] = "test"
    output = test_obj.build_lookup_fieldlist()
    assert set(output) == set(expected_output)


scheme = mock_scheme()
arg_list = [
    "asset_group",
    "aggregation_fields",
    "cron",
    "enrichment_expression",
    "enrichment_fields",
    "id_field",
    "id_field_rename",
    "inventory_filter",
    "inventory_source",
    "mv_id_field",
    "replicate",
    "source_expression",
    "source_fields",
    "source_filter",
]
for arg in arg_list:
    scheme.arguments.append(mock_arg(arg))


test_data = [
    (
        {"name": "test", "inventory_source": "false"},
        "test",
        "opt/data/test_input_xml1.xml",
        scheme,
        {
            "asset_group": "default",
            # defaults applied by method under test
            "aggregation_fields": None,
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": None,
            "id_field": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": False,
            "mv_id_field": None,
            "name": "test",
            "replicate": None,
            "source_expression": None,
            "source_fields": None,
            "source_filter": None,
        },
    ),
    (  # test enrichment_field singleton normalization
        {"name": "test0", "inventory_source": "false", "enrichment_fields": "foo"},
        "test",
        "opt/data/test_input_xml1.xml",
        scheme,
        {
            "asset_group": "default",
            # defaults applied by method under test
            "aggregation_fields": None,
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": ["foo"],
            "id_field": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": False,
            "mv_id_field": None,
            "name": "test0",
            "replicate": None,
            "source_expression": None,
            "source_fields": None,
            "source_filter": None,
        },
    ),
    (  # test enrichment_field multiple normalization
        {
            "name": "test0",
            "inventory_source": "false",
            "enrichment_fields": "foo, bar, zed ",
        },
        "test",
        "opt/data/test_input_xml1.xml",
        scheme,
        {
            "asset_group": "default",
            # defaults applied by method under test
            "aggregation_fields": None,
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": ["foo", "bar", "zed"],
            "id_field": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": False,
            "mv_id_field": None,
            "name": "test0",
            "replicate": None,
            "source_expression": None,
            "source_fields": None,
            "source_filter": None,
        },
    ),
    (  # test some optional fields
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "this /thing",
            "aggregation_fields": "agg1",
            "source_fields": "one, two",
            "inventory_source": "false",
            "replicate": "true",
        },
        "this /thing",
        "opt/data/test_input_xml2.xml",
        scheme,
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "this__thing",
            "aggregation_fields": ["agg1"],
            "source_fields": ["one", "two"],
            # defaults applied by method under test
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": False,
            "mv_id_field": None,
            "replicate": True,
            "source_expression": None,
            "source_filter": None,
        },
    ),
    (  # test empty strings
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "test",
            "aggregation_fields": "",
            "source_fields": "",
            "enrichment_fields": "",
            "inventory_source": "false",
        },
        "test",
        "opt/data/test_input_xml3.xml",
        scheme,
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "test",
            "aggregation_fields": None,
            "source_fields": None,
            # defaults applied by method under test
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": False,
            "mv_id_field": None,
            "replicate": None,
            "source_expression": None,
            "source_filter": None,
        },
    ),
    (  # test inventory source checkbox normalized correctly and singleton source field
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "that /thing",
            "aggregation_fields": "agg1",
            "source_fields": "one",
            "inventory_source": "true",
            "replicate": "false",
        },
        "this /thing",
        "opt/data/test_input_xml2.xml",
        scheme,
        {
            "asset_group": "group1",
            "id_field": "host",
            "name": "that__thing",
            "aggregation_fields": ["agg1"],
            "source_fields": ["one"],
            # defaults applied by method under test
            "cron": None,
            "enrichment_expression": None,
            "enrichment_fields": None,
            "id_field_rename": None,
            "inventory_filter": None,
            "inventory_source": True,
            "mv_id_field": None,
            "replicate": False,
            "source_expression": None,
            "source_filter": None,
        },
    ),
]


@pytest.mark.parametrize(
    "input_settings, input_name, input_xml_file, scheme, expected_output", test_data
)
def test_normalize_input_parameters(
    input_settings, input_name, input_xml_file, scheme, expected_output, test_obj
):

    test_obj.settings = {}
    test_obj.settings["default_asset_group_name"] = test_obj.DEFAULT_ASSET_GROUP_NAME
    output = test_obj.normalize_input_parameters(input_settings, scheme.arguments)
    print("output:")
    pp(output)
    print("expected:")
    pp(expected_output)
    assert output == expected_output


test_data = [
    (  # default test
        {
            "asset_groups": {
                "asset_group_1_name": "test_group",
                "asset_group_1_max_age": "45",
            },
            "additional_parameters": {
                "last_inventoried_fieldname": "last_seen",
                "first_inventoried_fieldname": "first_seen",
                "time_format": "%Y-%m-%d %H:%M",
                "aggregated_lookup_name": "all_hosts",
                "aggregated_collection_name": "all_collection",
                "primary_id_field": "ipaddress",
                "primary_mv_id_field": "ipaddresses",
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "default_asset_group_name": "test_group",
            "test_group": "45",
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "time_format": "%Y-%m-%d %H:%M",
            "aggregated_lookup_name": "all_hosts",
            "aggregated_collection_name": "all_collection",
            "primary_id_field": "ipaddress",
            "primary_mv_id_field": "ipaddresses",
            "loglevel": "ERROR",
        },
    ),
    (  # asset group info empty
        {
            "asset_groups": {},
            "additional_parameters": {
                "last_inventoried_fieldname": "last_seen",
                "first_inventoried_fieldname": "first_seen",
                "time_format": "%Y-%m-%d %H:%M",
                "aggregated_lookup_name": "all_hosts",
                "aggregated_collection_name": "all_collection",
                "primary_id_field": "ipaddress",
                "primary_mv_id_field": "ipaddresses",
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "default_asset_group_name": "default",
            "default": "30",
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "time_format": "%Y-%m-%d %H:%M",
            "aggregated_lookup_name": "all_hosts",
            "aggregated_collection_name": "all_collection",
            "primary_id_field": "ipaddress",
            "primary_mv_id_field": "ipaddresses",
            "loglevel": "ERROR",
        },
    ),
    (  # all 3 asset groups
        {
            "asset_groups": {
                "asset_group_1_name": "test_group",
                "asset_group_1_max_age": "45",
                "asset_group_2_name": "other_group",
                "asset_group_2_max_age": "60",
                "asset_group_3_name": "legacy_group",
                "asset_group_3_max_age": "90",
            },
            "additional_parameters": {
                "last_inventoried_fieldname": "last_seen",
                "first_inventoried_fieldname": "first_seen",
                "time_format": "%Y-%m-%d %H:%M",
                "aggregated_lookup_name": "all_hosts",
                "aggregated_collection_name": "all_collection",
                "primary_id_field": "ipaddress",
                "primary_mv_id_field": "ipaddresses",
            },
            "logging": {"loglevel": "ERROR"},
        },
        {
            "default_asset_group_name": "test_group",
            "test_group": "45",
            "other_group": "60",
            "legacy_group": "90",
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "time_format": "%Y-%m-%d %H:%M",
            "aggregated_lookup_name": "all_hosts",
            "aggregated_collection_name": "all_collection",
            "primary_id_field": "ipaddress",
            "primary_mv_id_field": "ipaddresses",
            "loglevel": "ERROR",
        },
    ),
]


@pytest.mark.parametrize("app_settings, expected_output", test_data)
def test_normalize_global_settings(app_settings, expected_output, test_obj):
    output = test_obj.normalize_global_settings(app_settings)
    assert output == expected_output


def test_build_search_name(test_obj):
    test_obj.name = "test1"

    test_obj.params = {"inventory_source": "1", "name": "test1"}
    result = test_obj.build_search_name()
    expected_result = "test1_hosts"
    assert result == expected_result

    test_obj.params["inventory_source"] = 0
    result = test_obj.build_search_name()
    expected_result = "test1_data"
    assert result == expected_result


def test_build_search_args(test_obj):
    test_obj.name = "test1"
    test_obj.params = {"cron": "0 1 * * *", "inventory_source": True, "name": "test1"}

    result = test_obj.build_search_args()
    expected_result = {
        "action.update_inventory": "1",
        "action.update_inventory.param.source_name": "test1",
        "description": "Hosts from test1",
        "cron_schedule": "0 1 * * *",
        # defaults
        "is_scheduled": "1",
        "alert.suppress": "0",
        "alert.track": "0",
        "dispatch.earliest_time": "-24h",
        "dispatch.latest_time": "now",
        "disabled": "0",
        "actions": "update_inventory",
    }
    assert result == expected_result

    test_obj.params = {"cron": "0 2 * * *", "inventory_source": False, "name": "test2"}

    result = test_obj.build_search_args()
    expected_result = {
        "action.update_inventory": "0",
        "action.update_inventory.param.source_name": "",
        "description": "Data from test2",
        "cron_schedule": "0 2 * * *",
        # defaults
        "is_scheduled": "1",
        "alert.suppress": "0",
        "alert.track": "0",
        "dispatch.earliest_time": "-24h",
        "dispatch.latest_time": "now",
        "disabled": "0",
    }

    assert result == expected_result


test_data = [
    (  # case time_format is same as old time_format, no need to change definition
        "%Y-%m-%d",
        "last_inventoried",
        'eval last_inventoried=strftime(_time, "%Y-%m-%d")',
        None,
    ),
    (  # case new time_format is substring of old time_format
        "%y-%m",
        "last_seen",
        'eval last_seen=strftime(foo, "%y-%m-%d")',
        'eval last_seen = strftime(foo, "%y-%m")',
    ),
    (  # case changed app setting LAST_INVENTORIED_FIELDNAME
        "%y-%m-%d",
        "last_seen",
        'eval last_inventoried=strftime(fooy, "%y-%m-%d")',
        'eval last_seen = strftime(fooy, "%y-%m-%d")',
    ),
    (  # case changed app setting LAST_INVENTORIED_FIELDNAME and user customizations first
        "%y-%m-%d %H:%M",
        "last_seen",
        '| eval real_time=strptime(strftime(_time, "%s"), "%Y-%m-%d") | eval last_inventoried=strftime(real_time, "%y-%m-%d")',
        '| eval real_time=strptime(strftime(_time, "%s"), "%Y-%m-%d") | eval last_seen = strftime(real_time, "%y-%m-%d %H:%M")',
    ),
    (  # case no existing `eval_last_inventoried` macro exists
        "%Y-%m-%d",
        "last_inventoried",
        None,
        'eval last_inventoried = strftime(_time, "%Y-%m-%d")',
    ),
    (  # case `eval_last_inventoried` macro exists but not recognizable to regex ... so just overwrite it
        "%Y-%m-%d",
        "last_inventoried",
        "eval foo=bar",
        'eval last_inventoried = strftime(_time, "%Y-%m-%d")',
    ),
]


@pytest.mark.parametrize(
    "time_format, last_inventoried_fieldname, existing_definition, expected_output",
    test_data,
)
def test_update_last_inventoried_macro_definition(
    test_obj,
    time_format,
    last_inventoried_fieldname,
    existing_definition,
    expected_output,
):
    result = test_obj.update_last_inventoried_macro_definition(
        time_format, last_inventoried_fieldname, existing_definition
    )
    assert result == expected_output


test_data = [
    (  # existing fields and new field needs to be added
        "one, two, three",
        ["four"],
        "one, two, three, four",
    ),
    (  # existing fields and multiple fields need to be added
        "one, two, three",
        ["four", "five"],
        "one, two, three, four, five",
    ),
    ("one, two, three", None, None),  # existing fields and no fields need to be added
    ("", ["one", "two"], "one, two"),  # no existing fields and fields need to be added
    (  # field that need to be added already present, no change needed
        "one, two, three",
        ["one", "two"],
        None,
    ),
]


@pytest.mark.parametrize(
    "current_fieldlist, necessary_fields, expected_output", test_data
)
def test_calculate_aggregation_transform_update(
    test_obj, current_fieldlist, necessary_fields, expected_output
):
    output = test_obj.calculate_aggregation_transform_fieldlist(
        necessary_fields, current_fieldlist
    )
    assert output == expected_output


test_data = [
    (mock_splunk_service.load_mock_saved_searches, "savedsearch foo", "savedsearches"),
    (mock_splunk_service.load_mock_transforms, "transform foo", "transforms"),
    (mock_splunk_service.load_mock_macros, "macro bar", "macros"),
    (mock_splunk_service.load_mock_collection, ["kvstore one"], "collections"),
]


@pytest.mark.parametrize("load_mock_method, mock_data, conf_type", test_data)
def test_get_collection(test_obj, load_mock_method, mock_data, conf_type):
    # test setup
    test_obj.service = mock_splunk_service("TA-oversight", "hosts_lookup")
    if load_mock_method == mock_splunk_service.load_mock_collection:
        collection_name = "test_kvstore"
        load_mock_method(test_obj.service, collection_name, mock_data)        
        output = test_obj.get_collection(conf_type)
        assert output[collection_name].data.query() == mock_data
    else:
        load_mock_method(test_obj.service, mock_data)
        output = test_obj.get_collection(conf_type)
        assert output == mock_data


def test_get_collection_with_exception(test_obj):
    # test setup
    invalid_conf_type = "invalid_macros"
    with pytest.raises(ValueError):
        test_obj.get_collection(invalid_conf_type)


test_data = [
    ("|tstats count by foo", "tstats count by foo"),
    ("| tstats count by foo", "tstats count by foo"),
    (" |tstats count by foo", "tstats count by foo"),
    (" | tstats count by foo", "tstats count by foo"),
    (
        "index=main sourcetype=log | append [|tstats count by foo]",
        "index=main sourcetype=log | append [|tstats count by foo]",
    ),
    (None, None),
    ("", ""),
]


@pytest.mark.parametrize("definition, expected_output", test_data)
def test_normalize_source_expression(definition, expected_output, test_obj):
    output = test_obj.normalize_source_expression(definition)
    assert output == expected_output
