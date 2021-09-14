#%% Setup Environment
## Requirements:
## local docker instance with TA-fetch installed
## Login to docker splunk, set server to use HTTPs and restart.
## firewall access to bigfix web reports server
## credentials for both systems
## create bigfix index in splunk, add credential, select in each input and enable
## These tests are designed to be run against a splunk instance with the TA-oversight app installed.  
## These tests are responbile for loading any necessary test data

from remote_test_metadata import TestResults

import requests, json, splunklib.client as client, splunklib.results, time
import time, re, collections, difflib
from pprint import pprint as pp
from six import iteritems, itervalues, iterkeys
import pytest
import pytest_cov

# ignore SSL warnings
import sys
if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")

SPLUNK_USER="admin"
SPLUNK_PASS=input("Splunk Password")
SPLUNK_HOST="localhost"
APP_NAME="TA-oversight"

test_metadata = TestResults()

# %% Method Definition
def get_splunk_results(service, spl, kwargs):
    # https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython/
    job = service.jobs.create(spl, **kwargs)

    while True:
        while not job.is_ready():
            pass
        if job["isDone"] == "1":
            break
        time.sleep(1)

    return splunklib.results.ResultsReader(job.results())

def get_version_spl(app_name):
    return '''
    | rest splunk_server=local count=1 /services/server/info 
    | eval name="Splunk Server" 
    | append 
        [| rest /servicesNS/-/{}/properties/app/launcher/version 
        | rename value as version 
        | eval name="{}"] 
    | table name version'''.format(app_name, app_name)

def log_test_result(test_metadata, spl, test_name, score, **kwargs):
    if score:
        test_metadata.number_passes +=1
        status_message = "PASS"
    else:
        test_metadata.number_fails += 1
        status_message = "FAIL"
    
    test_metadata.result_log.append("{}: {}".format(test_name, status_message))

    for key, value in iteritems(kwargs):
        if "query" in key:
            test_metadata.query_log.append("{}: {} - {}".format(test_name, key, str(value)))
        elif "response" in key:
            test_metadata.query_log.append("{}: {} - {}".format(test_name, key, str(value)))
    

def return_records(search_results):
    return {k:v for k, v in iteritems(list(search_results)[0])}


# %% Connect to Splunk and setup for app
service=client.connect(host=SPLUNK_HOST, username=SPLUNK_USER, password=SPLUNK_PASS, port=8089)


#%% Report Test Environment

search_kwargs={"earliest_time": "-24h@h", "latest_time": time.time(), 'exec_mode':'normal'}
versions = get_splunk_results(service, get_version_spl(APP_NAME), search_kwargs)
test_name = "Versions Under Test"

output = []
output.append(time.ctime())
for item in versions:
    output.append("  {}:{}".format(item['name'], item['version']))

log_test_result(
    test_metadata=test_metadata, 
    spl=get_version_spl(APP_NAME), 
    test_name=test_name, 
    score=True, 
    *{"app_version_response": output})






# %% Execute Test-Assets-01 #################################
## Number of host records in Splunk matches totalRecords from BigFix API
print("""\nMethodology: Search splunk for the number of events with sourcetype=bigfix:hosts in the last 24 hours.  
             Compare this number to the `total_records` metadata returned when querying the BigFix server""")
# get splunk answer
search_kwargs={"earliest_time": "-24h@h", "latest_time": time.time()}
splunk_spl = "search index=bigfix sourcetype=bigfix:hosts | stats count"
splunk_search = get_splunk_results(service, splunk_spl, search_kwargs)

test_result = int(splunk_record_count) == int(bigfix_record_count)

log_test_result("Test-Assets-01", test_result, splunk_spl)
query_log.append({"Test-Assets-01": [splunk_spl]})

splunk_results = return_records(splunk_search)
splunk_record_count = splunk_results["count"]

print("\nTest-Assets-01: Number of host records Splunk={}, BigFix={}".format(
    str(splunk_record_count), str(bigfix_record_count)))

if int(splunk_record_count) == int(bigfix_record_count):
    print("\n\nTest-Assets-01: PASS\n")
    number_passes += 1
else:
    print("\n\nTest-Assets-01: FAIL\n")
    number_fails += 1


log.append("Test-Assets-01:  Number of Assets in Splunk matches BigFix")

# %% FINAL RESULTS ##########################################################

print("\n\n\n FINAL RESULTS: PASSING TESTS={}, FAILING TESTS={}".format(str(number_passes), str(number_fails)))
print("\n\nTests Performed: \n")
for item in log:
    print(item)


# %%
