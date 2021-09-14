Dockerfile for remote testing splunk.

See /remote_tests/README.md for directions on using dev_splunk.

Build:
* `docker build --no-cache --tag container_splunk:latest --force-rm container_splunk`

Logs should read:
```markdown
Successfully built <container id>
Successfully tagged dev_splunk:latest
```
Run docker container & bind ports to localhost. 
Splunk uses 
* 8000 for web access to search head/indexer, 
* 8089 for REST API, 
* 8088 for HEC (HTTP Event collector).


Run the docker container with no code inside of it:
 `docker run -d -p 8000:8000 -p 8089:8089 -p 8088:8088 container_splunk:latest`
 
 or to mount the app from inside the top Oversight directory:
 
 Clear local data:
`rm Oversight/local/*.conf && rm Oversight/metadata/local.meta && rm Oversight/bin/*.log`

Then Run:
 `docker run -d -p 8000:8000 -p 8089:8089 -v  $PWD/Oversight:/opt/splunk/etc/apps/Oversight container_splunk:latest`

As one line:

`rm Oversight/local/*.conf && rm Oversight/metadata/local.meta && rm Oversight/bin/*.log && docker run -d -p 8000:8000 -p 8089:8089 -v  $PWD/Oversight:/opt/splunk/etc/apps/Oversight container_splunk:latest`

 
View the container id: `docker ps`
Check the docker logs: `docker logs <container id>`

Should see:
```markdown
localhost                  : ok=10   changed=5    unreachable=0    failed=0
```

Navigate to web interface:  `http://0.0.0.0:8000/` and login with the username/password configured in the Dockerfile. 

The rest API can be found at:  `http://0.0.0.0:8089/` 


To replace the code inside the container:
* `rm container_splunk/oversight.tgz`
* `tar czf container_splunk/oversight.tgz oversight`
* `docker cp container_splunk/oversight.tgz <container_id>:/opt/splunk/etc/apps`

SSH into the container, unzip, and re-start Splunk:
* `cd $SPLUNK_HOME/etc/apps/`
* `tar -xvzf /opt/splunk/etc/apps/oversight.tgz`
* `$SPLUNK_HOME/bin/./splunk restart`
