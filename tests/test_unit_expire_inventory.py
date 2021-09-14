import copy
import glob
import os
import sys
from datetime import datetime, timedelta
from pprint import pprint as pp

import pyfakefs
import pytest

import tests
from tests import mock_arg, mock_scheme, mock_splunk_service

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

import expire_inventory
import oversight_utils
from expire_inventory import InventoryExpirator
from oversight_utils import MissingAppSetting


@pytest.fixture(scope="function")
@pytest.mark.no_cover
def test_obj(fs):
    fs.create_dir("/opt/splunk/var/log/splunk")
    obj = InventoryExpirator()
    obj.max_age = 7
    obj.app_settings = {
        "additional_parameters": {
            "last_inventoried_fieldname": "last_seen",
            "first_inventoried_fieldname": "first_seen",
            "time_format": "%Y-%m-%d %H:%M",
            "primary_id_field": "ip",
            "primary_mv_id_field": "ip_addresses",
            "aggregated_lookup_name": "hosts_lookup",
            "aggregated_collection_name": "hosts_collection",
        },
        "default_7": 7,  # normalized
    }
    obj.LAST_INVENTORIED_FIELD = "last_seen"
    obj.VISIBLE_MVKEY_FIELD = "ip_addresses"
    obj.HIDDEN_MVKEY_FIELD = "__mv_key"
    obj.VISIBLE_KEY_FIELD = "ip"
    obj.setup(mock_splunk_service(obj.APP_NAME), obj.app_settings)
    return obj


test_data = [
    (
        {
            "asset_groups": {
                "asset_group_1_name": "foo",
                "asset_group_1_max_age": "30",
                "asset_group_2_name": "bar",
                "asset_group_2_max_age": "45",
                "asset_group_3_name": "default_7",
                "asset_group_3_max_age": "7",
            },
            "additional_parameters": {
                "last_inventoried_fieldname": "last_seen",
                "time_format": "%Y-%m-%d %H:%M",
            },
        },
        {
            "foo": 30,
            "bar": 45,
            "default_7": 7,
            "asset_groups": {
                "asset_group_1_name": "foo",
                "asset_group_1_max_age": "30",
                "asset_group_2_name": "bar",
                "asset_group_2_max_age": "45",
                "asset_group_3_name": "default_7",
                "asset_group_3_max_age": "7",
            },
            "additional_parameters": {
                "last_inventoried_fieldname": "last_seen",
                "time_format": "%Y-%m-%d %H:%M",
            },
        },
    )
]


@pytest.mark.parametrize("input_settings, expected_output", test_data)
def test_normalize_global_settings(input_settings, expected_output, test_obj):
    output = test_obj.normalize_global_settings(input_settings)
    assert output == expected_output


@pytest.mark.parametrize("input_settings, expected_output", test_data)
def test_normalize_global_settings_exceptions(
    input_settings, expected_output, test_obj
):
    del input_settings["additional_parameters"]["last_inventoried_fieldname"]

    with pytest.raises(MissingAppSetting):
        output = test_obj.normalize_global_settings(input_settings)
    input_settings["additional_parameters"]["last_inventoried_fieldname"] = "last_seen"

    del input_settings["additional_parameters"]["time_format"]

    with pytest.raises(MissingAppSetting):
        output = test_obj.normalize_global_settings(input_settings)

    assert str(MissingAppSetting("error1")) == "'error1'"


good_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
good_timestamp2 = (datetime.now() - timedelta(days=6)).strftime("%Y-%m-%d %H:%M")
good_timestamp3 = (datetime.now() - timedelta(days=6, hours=23)).strftime(
    "%Y-%m-%d %H:%M"
)
bad_timestamp = (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d %H:%M")

test_data = [
    (
        {
            "last_seen": bad_timestamp,
            "_key": "1.1.1.1",
            "asset_group": "default_7",
            "ip": "1.1.1.1",
        },
        [],
        True,
    ),
    (
        {
            "last_seen": bad_timestamp,
            "_key": "account:instance:/i-111",
            "asset_group": "default_7",
            "ip": "account:instance:/i-111",
        },
        [],
        True,
    ),
    (
        {
            "last_seen": good_timestamp,
            "_key": "1.1.1.1",
            "asset_group": "default_7",
            "ip": "1.1.1.1",
        },
        [],
        False,
    ),
    (
        {
            "last_seen": good_timestamp2,
            "_key": "1.1.1.1",
            "asset_group": "default_7",
            "ip": "1.1.1.1",
        },
        [],
        False,
    ),
    (
        {
            "last_seen": good_timestamp2,
            "_key": "account:instance:/i-111",
            "asset_group": "default_7",
            "ip": "account:instance:/i-111",
        },
        [],
        False,
    ),
    (  # test pre-expired host
        {
            "last_seen": good_timestamp2,
            "_key": "account:instance:/i-111",
            "asset_group": "default_7",
            "ip": "account:instance:/i-111",
        },
        ["account:instance:/i-111"],
        True,
    ),
]


@pytest.mark.parametrize("input_row, pre_expired_list, expected_output", test_data)
def test_expire_inventory_is_expired(
    input_row, pre_expired_list, expected_output, test_obj
):

    result = test_obj.is_expired(input_row, pre_expired_list)
    assert result == expected_output


test_data = [
    (
        {
            "last_seen": "2020-10-01 01:10",
            "asset_group": "default_7",
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
        },
        True,
    ),
    (
        {
            "last_seen": "2020-10-01 01:10",
            "asset_group": "default_7",
            "_key": "account:instance:/i-111",
            "ip": "account:instance:/i-111",
        },
        True,
    ),
    (
        {
            "last_seen": "2020-10-01 01:10",
            "_key": "account:instance:/i-111",
            "ip": "account:instance:/i-111",
        },
        True,
    ),
    (
        {
            "last_seen": "2020-10-01 01:10",
            "asset_group": "not_default",
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
        },
        True,
    ),
    ({}, False),  # test row null
]


@pytest.mark.parametrize("input, expected_output", test_data)
def test_is_valid_record(input, expected_output, test_obj):
    result = test_obj.is_valid_record(input)
    assert result == expected_output


test_data = [
    (
        {"last_seen": "2020-10-01 01:10", "asset_group": "default_7", "ip": "1.1.1.1"},
        False,
    ),
    (
        {
            "last_seen": "2020-10-01 01:10",
            "asset_group": "default_7",
            "ip": "account:instance:/i-111",
        },
        False,
    ),
    (
        {
            "last_seen": "2020-10-01 01:10",
            "asset_group": "default_7",
            "_key": "1.1.1.1",
        },
        False,
    ),
    ({"asset_group": "default_7", "_key": "1.1.1.1", "ip": "1.1.1.1"}, False),
    (
        {
            "last_seen": "Tuesday, Jan 1, 2020",
            "asset_group": "default_7",
            "_key": "1.1.1.1",
            "ip": "1.1.1.1",
        },
        False,
    ),
]


@pytest.mark.parametrize("input, expected_output", test_data)
def test_is_valid_record_invalid_silently_continue(input, expected_output, test_obj):
    result = test_obj.is_valid_record(input)
    assert result == expected_output



active_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
expired_timestamp = (datetime.now() - timedelta(days=31)).strftime("%Y-%m-%d %H:%M")

active_record_1 = {
    "ip": "1.1.1.1",
    "_key": "1.1.1.1",
    "last_seen": active_timestamp,
    "ip_addresses": ["1.1.1.1", "2.2.2.2"]
}
active_record_2 = {
    "ip": "2.2.2.2",
    "_key": "2.2.2.2",
    "last_seen": active_timestamp,
    "ip_addresses": ["1.1.1.1", "2.2.2.2"]
}
expired_record_1 = {
    "ip": "1.1.1.1",
    "_key": "1.1.1.1",
    "last_seen": expired_timestamp,
    "ip_addresses": ["1.1.1.1", "2.2.2.2"]
}
expired_record_2 = {
    "ip": "2.2.2.2",
    "_key": "2.2.2.2",
    "last_seen": expired_timestamp,
    "ip_addresses": ["1.1.1.1", "2.2.2.2"]
}
expired_single_record_1 = {
    "ip": "1.1.1.1",
    "_key": "1.1.1.1",
    "last_seen": expired_timestamp,
    "ip_addresses": "1.1.1.1"
}

## use arn format instead of ip
active_arn_1 = {
    "ip": "account:instance:/i-111",
    "_key": "account:instance:/i-111",
    "last_seen": active_timestamp,
    "ip_addresses": ["account:instance:/i-111", "account:instance:/i-222"]
}
active_arn_2 = {
    "ip": "account:instance:/i-222",
    "_key": "account:instance:/i-222",
    "last_seen": active_timestamp,
    "ip_addresses": ["account:instance:/i-111", "account:instance:/i-222"]
}
expired_arn_1 = {
    "ip": "account:instance:/i-111",
    "_key": "account:instance:/i-111",
    "last_seen": expired_timestamp,
    "ip_addresses": ["account:instance:/i-111", "account:instance:/i-222"]
}
expired_arn_2 = {
    "ip": "account:instance:/i-222",
    "_key": "account:instance:/i-222",
    "last_seen": expired_timestamp,
    "ip_addresses": ["account:instance:/i-111", "account:instance:/i-222"]
}

test_data = [
    #     "expired_hosts, active_hosts, output_modified, output_expired",

    ({}, {}, {}, {}),  # test null input
    (  # test single non-expiring record
        {},
        {"1.1.1.1": active_record_1, "2.2.2.2": active_record_2},
        {},
        {},
    ),
    (  # test single non-expiring record
        {},
        {
            "account:instance:/i-111": active_arn_1,
            "account:instance:/i-222": active_arn_2,
        },
        {},
        {},
    ),
    (  # test one record expires one doesnt
        {"2.2.2.2": expired_record_2},
        {"1.1.1.1": active_record_1},
        {
            "1.1.1.1": {
                "ip": "1.1.1.1",
                "_key": "1.1.1.1",
                "last_seen": active_timestamp,
                "ip_addresses": ["1.1.1.1"]
            }
        },
        {
            "2.2.2.2": {
                "ip": "2.2.2.2",
                "_key": "2.2.2.2",
                "last_seen": expired_timestamp,
                "ip_addresses": ["2.2.2.2"]
            }
        },
    ),
    (  # test a single record without mv-key expires
        {"1.1.1.1": expired_single_record_1},
        {},
        {},
        {
            "1.1.1.1": {
                "ip": "1.1.1.1",
                "_key": "1.1.1.1",
                "last_seen": expired_timestamp,
                "ip_addresses": "1.1.1.1"
            }
        },
    ),
    (  # test both records expiring
        {"2.2.2.2": expired_record_2, "1.1.1.1": expired_record_1},
        {},
        {},
        {
            "1.1.1.1": {
                "ip": "1.1.1.1",
                "_key": "1.1.1.1",
                "last_seen": expired_timestamp,
                "ip_addresses": ["1.1.1.1"]
            },
            "2.2.2.2": {
                "ip": "2.2.2.2",
                "_key": "2.2.2.2",
                "last_seen": expired_timestamp,
                "ip_addresses": ["2.2.2.2"]
            },
        },
    ),
]


@pytest.mark.parametrize(
    "expired_hosts, active_hosts, output_modified, output_expired",
    test_data,
)
def test_strip_expiring_keys_from_mvkeys(
    expired_hosts,
    active_hosts,
    output_modified,
    output_expired,
    test_obj,
):
    print("input expired_hosts")
    pp(expired_hosts)
    print("input active_hosts")
    pp(active_hosts)
    expired = copy.deepcopy(expired_hosts)
    active = copy.deepcopy(active_hosts)
    (
        result_expired,
        result_modified,
    ) = test_obj.strip_expiring_keys_from_mvkeys(expired, active)

    print("Expected modified_hosts")
    pp(output_modified)
    print("Result modified_hosts")
    pp(result_modified)

    print("Expected expired_hosts")
    pp(output_expired)
    print("Result expired_hosts")
    pp(result_expired)

    assert result_modified == output_modified
    assert result_expired == output_expired
