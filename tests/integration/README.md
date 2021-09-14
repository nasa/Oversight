# example execution
```
.venv/bin/python3 -m pytest -rA --splunk-type=docker --splunk-password=mybestpassword tests/integration > pytest_integration.log
```

## Dockerfile-slpunk
```
ARG SPLUNK_VERSION=8.1.4
FROM splunk/splunk:$SPLUNK_VERSION
ARG SPLUNK_APP=TA-oversight
ARG SPLUNK_APP_PACKAGE=package
COPY $SPLUNK_APP_PACKAGE /opt/splunk/etc/apps/$SPLUNK_APP
```

## docker-compose.yml
```
# https://pytest-splunk-addon.readthedocs.io/en/latest/how_to_use.html
version: "3.7"
services:
  splunk:
    build:
      context: .
      dockerfile: Dockerfile-splunk
      args:
        SPLUNK_APP_ID: TA-oversight
        SPLUNK_APP_PACKAGE: output/TA-oversight
        SPLUNK_VERSION: 8.1.4
    ports:
      - "8000"
      - "8088"
      - "8089"
      - "9997"
    environment:
      - SPLUNK_PASSWORD=${SPLUNK_PASSWORD}
      - SPLUNK_START_ARGS=--accept-license
```
this assumes the built app is in output

see pytest-splunk-addon docs for more info
had to manually build the ptest-splunk-addon by cloning the repo otherwise maybe the docker fixtures aren't available??

the great thing about this is:
* log pytest output (which is very large) to a file, easier searching in vscode
* make changes to the code that is in the output directory, including adding debug logging, and re-run the integration tests.  Its a LOT easier than trying to edit the files directly in the docker container

## Additional Notes
* Ensure tests are targeted at build output directory
* set debug=True in calls to test_obj.get_blocking_search_results() to capture search.log in std.out