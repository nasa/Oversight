## AUTH:
#splunk_session = Splunk_Caller()
from os import path
import datetime
import json
import ast
import sys
APP_NAME='Oversight'

TEST_PATH='/Users/pmeyerso/Documents/repos/OverSight/OverSight/bin/lib'
#LIBDIR = os.path.join(os.path.join(os.environ.get('SPLUNK_HOME')), 'etc', 'apps', APP_NAME, 'bin', 'lib')
if not TEST_PATH in sys.path:
    sys.path.append(TEST_PATH)
    
#from datetime import datetime, timedelta
from splunklib.binding import HTTPError
import splunklib.client as client

APP_NAME = 'Oversight'
#test_data_path = 'remote_tests/test_data/'
test_data_path = 'remote_tests/small_sample_data/'
#test_data_path = 'remote_tests/aws_test/'


def _txt_to_splunk(index, sourcetype, file_name):

    with open(test_data_path + file_name, 'r') as test_file:
        raw_events = test_file.read().splitlines()

    for event in raw_events:
        print(event)
        if event not in [None, '']:
            index.submit(event, sourcetype=sourcetype, host="local", source="http:inventory-data")
            

def _json_to_collection(collection, file_name):
    ''' @param file_name:  file with list of json entries
        @param collection: service.kvstore entity
    '''

    keyfield =''
    if collection.name == 'Account_collection':
        keyfield='account_arn'
    else:
        keyfield='UniqueId'
    
    collection.data.delete()
    with open(test_data_path + file_name, 'r') as f:
        bulk =f.read()
        for line in bulk.splitlines():
            if line != '' and len(line) >2:
                line = ast.literal_eval(line)
                line['_key'] = line[keyfield]
                # print(line)
                collection.data.insert(json.dumps(line))

    print("collection now has " + str(len(collection.data.query())))





############## Upload test data to Splunk

#make sure app has been Setup first!
## */*/ AWS TEST DATA
if 'Test_collection' not in service.kvstore:
    service.kvstore.create('Test_collection')


kvstore_names = [i.name for i in service.confs['inventory_sources']]
kvstores = {}
kvstore_names.append('Test_collection')

for item in kvstore_names:
    kvstores[item] = service.kvstore[item]

if "aws_main" not in [i.name for i in service.indexes]:
    service.indexes.create("aws_main")

aws_main_index = service.indexes["aws_main"]
test_data_path = 'remote_tests/data/aws_test/'

#_json_to_collection(kvstores['EC2_metadata_collection'], 'EC2_metadata_lookup.json')
_txt_to_splunk(aws_main_index, "inventory_EC2", 'EC2_metadata_lookup.json')
#_json_to_collection(kvstores['Inspector_agent_status_collection'], 'Inspector_agent_status_lookup.json')
_txt_to_splunk(aws_main_index, "inventory_Inspector", 'Inspector_agent_status_lookup.json')
#_json_to_collection(kvstores['SSM_status_collection'], 'SSM_status_lookup.json')
_txt_to_splunk(aws_main_index, "inventory_SSM", 'SSM_status_lookup.json')
#_json_to_collection(kvstores['Test_collection'], 'test.json')

## Summary index data of hosts on network
'''
index=summary search_name="Internal Clients" OR search_name="Unique Hosts Seen" earliest=-1d
| sort _time
| dedup src
'''

test_data_path = 'remote_tests/data/small_sample_data/'
indexes = [i.name for i in service.indexes.list()] #all indexes
assert('summary' in indexes) #verify that summary already exists, should be default
summary_index = service.indexes["summary"] #create summary index client

_txt_to_splunk(summary_index,'stash','firewall_summary.txt')

_txt_to_splunk(summary_index,'stash','syslog_summary.txt')


'''
index=forescout earliest=-1d
| sort -_time
| dedup ip
'''
## Summary index data of hosts on network
test_data_path = 'remote_tests/data/small_sample_data/'

try:
    forescout_index = service.indexes.create("forescout")
except Exception as e:
    forescout_index = service.indexes["forescout"] #create summary index client

_txt_to_splunk( forescout_index,'scan_result_id:1666','forescout.txt')



'''
index=bigfix earliest=-1d
| sort time
| dedup ip_address
'''
## Summary index data of hosts on network
try:
    bigfix_index = service.indexes.create("bigfix")
except Exception as e:
    bigfix_index = service.indexes["bigfix"] #create summary index client

_txt_to_splunk( bigfix_index,'scan_result_id:1666','bigfix.txt')


#test_data_path = 'remote_tests/small_sample_data/'


'''
index="tenable" sourcetype="tenable:sc:vuln" pluginID=19506 earliest=-31d latest=now 
| sort -credentialed_checks, _time
| dedup ip
'''
## Summary index data of hosts on network
try:
    tenable_index = service.indexes.create("tenable")
except Exception as e:
    tenable_index = service.indexes["tenable"] #create summary index client
#one sample host
_txt_to_splunk( tenable_index,'tenable:sc:vuln','nessus_host.txt')



############## Very Data was added to inventory

TEST_ID = "172.1.2.3"
INVENTORY_SOURCE_CONFIG = 'inventory_sources'
INVENTORY_COLLECTION = 'hosts_collection'


# Pull every kvcollection for inventory
inventory_sources= [source.name for source in service.confs[INVENTORY_SOURCE_CONFIG]]
# Add the apps inventory kvcollection
inventory_sources.append(INVENTORY_COLLECTION)

# Verify that test ID exists in each source
for collection in inventory_sources:
    print(collection)
    kv_collection = service.kvstore[collection]
    try:
        out = kv_collection.data.query_by_id(TEST_ID)
        print(out)
    except HTTPError as err:
        print("Could not find id")
    print("\n")

############## Test Expiration

# Pull every kvcollection for inventory
inventory_sources= [source.name for source in service.confs[INVENTORY_SOURCE_CONFIG]]
# Add the apps inventory kvcollection
inventory_sources.append(INVENTORY_COLLECTION)
MAX_DAYS = 31

tod = datetime.datetime.now()
diff = datetime.timedelta(days = MAX_DAYS)
date_31_days_ago = tod - diff
expired_date  = date_31_days_ago.strftime('%s')

collections_with_test = []

# Verify that test ID exists in each source
for collection in inventory_sources:
    print(collection)
    kv_collection = service.kvstore[collection]
    try:
        # extract existing data
        host_row = kv_collection.data.query_by_id(TEST_ID)
        print(host_row)
        # add date from 31 days ago
        host_row['last_inventoried'] = expired_date
        # update in kvlookup
        out_host = json.dumps(host_row)
        kv_collection.data.update(TEST_ID, out_host)

        collections_with_test.append(collection)

    except HTTPError as err:
        print("Could not find id")
    print("\n")


### ENSURE THAT ADDER searchers are disabled so that it's possible to detect host being deleted!
for collection in collections_with_test:
    print(collection)
    kv_collection = service.kvstore[collection]
    try:
        # extract existing data
        host_row = kv_collection.data.query_by_id(TEST_ID)
        print(host_row)

    except HTTPError as err:
        print("Could not find id")
    print("\n")





'''
index="tenable" sourcetype="tenable:sc:vuln" pluginID=11936 earliest=-30d latest=now 
| sort -_time
|  dedup ip
'''
## Summary index data of hosts on network
## Summary index data of hosts on network
try:
    tenable_index = service.indexes.create("tenable")
except Exception as e:
    tenable_index = service.indexes["tenable"] #create summary index client
#one sample host
_txt_to_splunk( tenable_index,'tenable:sc:vuln','nessus_19506.txt')

_txt_to_splunk( tenable_index,'tenable:sc:vuln','nessus_plugins.txt')
_txt_to_splunk( tenable_index,'tenable:sc:vuln','nessus_host.txt')

test_data_path = 'remote_tests/sample_data/'
_txt_to_splunk( tenable_index,'tenable:sc:vuln','24hour_nessus.txt')