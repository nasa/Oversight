import copy
import glob
import logging
import operator
import os
import re
import sys
import uuid
from datetime import datetime, timedelta
from pprint import pprint as pp

import pyfakefs
import pytest
import pytest_mock

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


from oversight_utils import OversightScript

from tests import (
    mock_arg,
    mock_kvstore,
    mock_kvstore_data,
    mock_scheme,
    mock_splunk_service,
)

ARN_PATTERN = re.compile(
    r"arn:aws:(?P<ResourceType>[^:]+):(?P<Region>[^:]+):(?P<Account>[^:]+)"
)


@pytest.fixture(scope="function")
@pytest.mark.no_cover
def test_obj(fs):
    fs.create_dir("/opt/splunk/var/log/splunk")
    test_obj = OversightScript()
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
    test_obj.AGGREGATED_COLLECTION_NAME = "hosts_collection"
    test_obj.kvstore_max_batch = int(1000)
    test_obj.run_id = "1"
    test_obj.source_name = "test"
    test_obj.service = mock_splunk_service(
        test_obj.APP_NAME,
        *[settings["additional_parameters"]["aggregated_collection_name"]]
    )
    test_obj.service.kvstore["hosts_collection"].data = mock_kvstore_data([])
    assert test_obj.service.kvstore["hosts_collection"].data.query() == []
    test_obj.setup(test_obj.service, settings)
    return test_obj


test_data = [
    ("2020-01-01", "%Y-%m-%d", datetime.strptime("2020-01-01", "%Y-%m-%d")),
    (None, None, None),
    ("2020-01-01", "%m/%d/%Y %H:%M", None),
]


@pytest.mark.parametrize("timestring, timeformat, expected_output", test_data)
def test_convert_timesting_to_epoch(test_obj, timestring, timeformat, expected_output):
    output = test_obj.convert_timestring_to_epoch(timestring, timeformat)
    assert output == expected_output


test_data = [
    ([{"_key": "bar"}], {"bar": {"_key": "bar"}}),
    (
        [{"_key": "bar"}, {"_key": "two"}, {"_key": "four"}],
        {"bar": {"_key": "bar"}, "two": {"_key": "two"}, "four": {"_key": "four"}},
    ),
]


@pytest.mark.parametrize("kvstore_data, expected_output", test_data)
def test_populate_local_aggregation_cache(test_obj, kvstore_data, expected_output):

    col_name = test_obj.AGGREGATED_COLLECTION_NAME
    ## cleanup any prior tests that failed
    test_obj.service.kvstore[col_name].data = mock_kvstore_data([])

    assert test_obj.service.kvstore[col_name].data.query() == []

    test_obj.write_cache[col_name] = kvstore_data
    test_obj.write_kvstore_batch(col_name)

    # method under test 1
    output = test_obj.get_kvstore_records(col_name)
    assert output == kvstore_data

    # method under test 2
    output2 = test_obj.get_dict_from_records("_key", output)
    assert output2 == expected_output

    ## cleanup
    test_obj.service.kvstore[col_name].data = mock_kvstore_data()


def test_get_cached_record(test_obj):
    cached_key = "1"
    cached_data = {"_key": "1", "status": "ok"}
    test_obj.aggregation_cache = {}
    test_obj.aggregation_cache[cached_key] = copy.deepcopy(cached_data)
    output = test_obj.get_cached_record("1")
    assert output == cached_data

    cached_data["status"] = "invalid"
    assert test_obj.get_cached_record("1")["status"] == "ok"

    # test none result
    assert test_obj.get_cached_record("invalid_key") is None


def test_update_cached_record(test_obj):
    # test setup
    test_obj.aggregation_cache = {}
    record = {"_key": "1", "status": "ok"}
    test_obj.aggregation_cache["1"] = copy.deepcopy(record)

    new_record = {"_key": "1", "status": "good", "best": "blue"}
    test_obj.update_cached_record("1", **new_record)
    new_record["status"] = "invalid"

    assert test_obj.aggregation_cache["1"]["status"] == "good"


test_data = [
    (
        {
            "key": "1.1.1.1",
            "last_seen": "1999-09-09",
            "mgmt1_last_seen": "1999-09-09",
        },
        ["mgmt1_collection"],
    ),
    ({"key": "1.1.1.1", "last_seen": "1999-09-09"}, []),
    (
        {
            "key": "account:instance:/i-111",
            "last_seen": "1999-09-09",
            "mgmt1_last_seen": "1999-09-09",
        },
        ["mgmt1_collection"],
    ),
    ({"key": "account:instance:/i-111", "last_seen": "1999-09-09"}, []),
]


@pytest.mark.parametrize("event, expected_output", test_data)
def test_oversight_utils_get_collection_names_to_purge(
    event, expected_output, test_obj
):

    result = test_obj.get_collection_names_to_purge(event)

    assert result == expected_output


test_data = [
    (
        {
            "_key": "1.1.1.1",
            "syslog_last_seen": "today",
            "last_seen": "today",
            "first_seen": "yesterday",
            "av_last_seen": "today",
        },
        ["syslog_last_seen", "av_last_seen"],
    ),
    ({"_key": "1.1.1.1"}, []),
]


@pytest.mark.parametrize("event, expected_output", test_data)
def test_oversight_utils_get_fieldnames_to_purge(event, expected_output, test_obj):
    # test setup
    assert test_obj.LAST_INVENTORIED_FIELD == "last_seen"

    # method under test
    result = test_obj.get_fieldnames_to_purge(event)
    assert result == expected_output


test_data = [
    ([{"_key": "bar"}], [{"_key": "bar"}]),  # test singleton cache
    (  # test multiple documents in cache
        [{"_key": "bar"}, {"_key": "two"}, {"_key": "four"}],
        [{"_key": "bar"}, {"_key": "two"}, {"_key": "four"}],
    ),
    (  # test accidently putting same document twice in cache, should
        # only be 2 documents written when done
        [{"_key": "bar"}, {"_key": "bar"}, {"_key": "four"}],
        [{"_key": "bar"}, {"_key": "four"}],
    ),
]


@pytest.mark.parametrize("write_cache, expected_output", test_data)
def test_write_kvstore_batch(test_obj, write_cache, expected_output):

    # cleanup from prior or failed tests
    col_name = test_obj.AGGREGATED_COLLECTION_NAME
    test_obj.service.kvstore[col_name].data = mock_kvstore_data([])
    assert test_obj.service.kvstore[col_name].data.query() == []

    # populate internal write cache

    test_obj.write_cache[col_name] = write_cache

    # call method under test
    test_obj.write_kvstore_batch(col_name)

    # validate that .data.query() returns the same data as was written
    assert (
        test_obj.service.kvstore[test_obj.AGGREGATED_COLLECTION_NAME].data.query()
        == expected_output
    )

    # validate that .data.query() returns the same number of records as what was written
    assert len(
        test_obj.service.kvstore[test_obj.AGGREGATED_COLLECTION_NAME].data.query()
    ) == len(expected_output)

    # validate that internal write cache is cleared out after writting
    assert test_obj.write_cache[col_name] == []

    # teardown
    test_obj.service.kvstore[col_name].data = mock_kvstore_data()


test_data = [
    # test batch smaller than max size and nothing cached
    ({}, [{"_key": "1"}], 3, 1),
    # test small cache and no additional records
    ({"hosts_collection": [{"_key": "1"}]}, None, 3, 1),
    # test batch and previous cache together smaller than max size
    (
        {"hosts_collection": [{"_key": "1"}]},
        [{"_key": "2"}],
        3,
        1,
    ),
    # test no cache, batch size larger then max size
    (
        {},
        [{"_key": "1"}, {"_key": "2"}, {"_key": "3"}, {"_key": "4"}, {"_key": "5"}],
        3,
        2,
    ),
    # test small cache, small batch, combined larger than max size
    (
        {"hosts_collection": [{"_key": "1"}, {"_key": "2"}]},
        [{"_key": "3"}, {"_key": "4"}],
        3,
        2,
    ),
    # test large cache, small batch
    (
        {"hosts_collection": [{"_key": "1"}, {"_key": "2"}, {"_key": "9"}]},
        [{"_key": "3"}, {"_key": "4"}],
        3,
        2,
    ),
    # test large cache, large batch
    (
        {
            "hosts_collection": [
                {"_key": "1"},
                {"_key": "2"},
                {"_key": "9"},
                {"_key": "8"},
            ]
        },
        [{"_key": "3"}, {"_key": "4"}, {"_key": "7"}, {"_key": "6"}],
        3,
        4,
    ),
    # test cache None, large batch
    (
        {},
        [{"_key": "3"}, {"_key": "4"}, {"_key": "7"}, {"_key": "6"}],
        3,
        2,
    ),
    # test cache None, batch None
    (
        {},
        None,
        3,
        0,
    ),
    # test cache large, batch None
    (
        {
            "hosts_collection": [
                {"_key": "3"},
                {"_key": "4"},
                {"_key": "7"},
                {"_key": "6"},
            ]
        },
        None,
        3,
        2,
    ),
    # test cache no cache, and batch is dict by mistake
    (
        {},
        {"_key": "3"},
        3,
        1,
    ),
    # test edge case where limit-records_size > limit
    (
        {},
        [
            {"_key": "9"},
            {"_key": "10"},
            {"_key": "11"},
            {"_key": "12"},
            {"_key": "13"},
            {"_key": "14"},
            {"_key": "15"},
        ],
        3,
        3,
    ),
]


@pytest.mark.parametrize(
    "initial_cache, additional_records, max_records_per_batch, minimum_expected_writes",
    test_data,
)
def test_handle_cached_write(
    test_obj,
    initial_cache,
    additional_records,
    max_records_per_batch,
    minimum_expected_writes,
    mocker,
):

    ## cleanup any prior test
    col_name = test_obj.AGGREGATED_COLLECTION_NAME
    test_obj.service.load_mock_collection(col_name, [])
    # determine expected output
    expected_keys = []
    if initial_cache:
        for key in initial_cache:
            expected_keys += [i["_key"] for i in initial_cache[key]]

    if additional_records and isinstance(additional_records, list):
        expected_keys += [i["_key"] for i in additional_records]
    elif additional_records and isinstance(additional_records, dict):
        expected_keys += [additional_records["_key"]]

    # object under test setup
    col_name = test_obj.AGGREGATED_COLLECTION_NAME
    test_obj.write_cache = initial_cache
    test_obj.kvstore_max_batch = int(max_records_per_batch)
    assert (
        col_name in test_obj.service.kvstore
        and test_obj.service.kvstore[col_name].data.query() == []
    )

    # method under test
    test_obj.handle_cached_write(col_name, records=additional_records, force=True)

    # format output for evaluation against expected
    output = test_obj.service.kvstore[col_name].data.query()
    output_keys = [i["_key"] for i in output]

    assert set(output_keys) == set(expected_keys)
    assert len(output) == len(expected_keys)

    ## teardown
    test_obj.service.kvstore[col_name].data = mock_kvstore_data()
    test_obj.write_cache[col_name] = []
