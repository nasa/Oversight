# OverSight Technical Add-On

OverSight is a Technical Add-On application for the Splunk data analytics platform, see more at https://splunk.com.  (Splunk is a trademark of Splunk Inc.)

OverSight creates inventory lookups across multiple sets of already ingested events, normalized to the user's specifications.
OverSight takes the Modular Input parameters to create multiple knowledge objects, which are then used to execute scheduled saved searches
and populate KV Store lookups.

The latest version of this document can always be found at https://github.com/nasa/Oversight

## Build and Package Instructions

We've included the Splunk app installation file under the tagged releases.  Navigate to Code -> tags.
This repository is designed to allow users to rebuild and repackage the Splunk app installation file at any time.

If you would like to build this app from source, please follow these steps:

```
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install splunk-add-on-ucc-framework
 
ucc-gen --source TA-oversight --ta-version 2.3.5
mkdir output/TA-oversight/bin/TA-oversight
cp -vRP output/TA-oversight/lib/* output/TA-oversight/bin/TA-oversight
```

You can then package this output:
``` 
pip install kintyre-splunk-conf
python3 -m ksconf package -f TA-oversight_2.3.5.spl --set-version 2.3.5 --app-name TA-oversight  output/TA-oversight
```

or running ./splunk cmd package app TA-oversight against a running splunk instance.

For more information on these utilities see:
https://github.com/splunk/addonfactory-ucc-generator
https://github.com/Kintyre/ksconf

## Integration Tests against a docker splunk instance

We've included integration tests which are designed to run against a running docker splunk image.
Thanks to pytest-splunk-addon for making this integration easy!

relevant configurations:

docker-compose.yml - SPLUNK_VERSION has the splunk image version to pull from docker hub.
Dockerfile-splunk - SPLUNK_VERSION has the splunk image version to pull from docker hub.
tests/integration/conftest.py - calls docker compose for integration test spin up.

tests/integration/test_integration*.py - each integration test file has a splunk_setup() which provides a test fixture for the running splunk instance.
You can use this fixture to interact with the Splunk REST API or SDK through the test_obj.service attribute.

To run integration tests:
NOTE: Splunk 8.x supports python3.7, we suggest using that version for local testing.  Oversight does not support python2.

1. Clone this repo
2. python3 -m venv .venv
3. pip3 install splunk-add-on-ucc-framework pytest
4. ucc-gen --source TA-oversight --ta-version 2.3.5
5. source .venv/bin/activate
6. python -m pytest -rA tests/integration  --splunk-type=docker --splunk-password=splunkpassword > pytest_integration.log 
   1. see Dockerfile-splunk for password

To run unit tests:
1. Clone this repo
2. python3 -m venv .venv
3. pip3 install splunk-add-on-ucc-framework pytest
4. ucc-gen --source TA-oversight --ta-version 2.3.5
5. srouce .venv/bin/activate
6. python3 -m pip install -r requirements-test.txt
7. python -m pytest -rA --cov-config=.coveragerc tests/test_unit* --cov=output/TA-oversight/bin/

## Development with a running docker instance

After building the app, you can also choose to manually package the output, or bind the output directory into a docker splunk instance.  Guidance is below:

1. Clone this repo
2. python3 -m venv .venv
3. python3 -m pip install splunk-add-on-ucc-framework pytest
4. ucc-gen --source TA-oversight --ta-version 2.3.5

Setup splunk docker image:

1. docker run --name splunk_test -e "SPLUNK_PASSWORD=splunkpassword" \
         -e "SPLUNK_START_ARGS=--accept-license" \
         -p "127.0.0.1:8000:8000" \
         -p "127.0.0.1:8089:8089" \
         -v /path/to/Oversight/TA-oversight:/opt/splunk/etc/apps/TA-oversight \
         -it splunk/splunk:latest

The password is in the dockerfile.
Navigate to web interface:  `http://0.0.0.0:8000/` and login with the username/password configured in the Dockerfile. 

The rest API can be found at:  `http://0.0.0.0:8089/`
## Additional Docs

Please see /docs for more info on using Oversight.
The documentation is also available from the in-app navigation link.

* Oversight README
* Getting Started Guide
* User Guide
* Saved Searches Macro Definitions
