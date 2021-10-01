# encoding = utf-8

import csv
import datetime
import gzip
import json
import sys
from datetime import datetime

import import_declare_test
import solnlib.log
import splunklib.binding as binding
import splunklib.client as client
import splunklib.results as results
from six import iteritems

from oversight_utils import OversightScript, log_enter_exit


class InventoryExpirator(OversightScript):
    """This class is responsible for determining if a record should be flagged as expired, updating the aggregation kvstore
    as necessary.  If a record for a host with multiple ip-addresses is expired, that ip will be stripped from all the remaining
    records for that host, if any remain.  No input events are required to be in the pipeline; this command pulls data it needs
    directly from the kvstores.

    """

    SCRIPT_NAME = "expire_inventory"
    logger = None
    service = None

    def __init__(self):
        """ """
        super().__init__()

    def is_valid_record(self, row):
        """validate necessary fields are present prior to processing

        @param row:  dict, the event record being processed
        @returns    bool

        return True if:
            row.get(self.app_settings['additional_parameters']['primary_id_field'])
            row.get('asset_group')
            self.app_settings.get(asset_group)
            row.get(self.app_settings['last_inventoried_field'])
            row.get(self.app_settings['last_inventoried_field']) in format self.app_settings.get('time_format')
        """
        if not row:
            return False

        if not row.get("_key"):
            self.logger.error(
                "run_id={} Unable to detect _key field in record={}".format(
                    self.run_id, str(row)
                )
            )
            return False

        if not row.get(
            self.app_settings.get("additional_parameters").get("primary_id_field")
        ):
            self.logger.error(
                "run_id={} Unable to detect field={} in record={}".format(
                    self.run_id,
                    str(
                        self.app_settings.get("additional_parameters").get(
                            "primary_id_field"
                        )
                    ),
                    str(row),
                )
            )
            return False

        if "asset_group" not in row:
            self.logger.warning(
                'run_id={} asset_group field missing from record={} will use "default"'.format(
                    self.run_id, str(row)
                )
            )
        else:
            asset_group = row.get("asset_group")

            if asset_group not in self.app_settings:
                self.logger.warning(
                    "run_id={} asset_group={} does not have max age set in app settings, will use 180d default".format(
                        self.run_id, str(asset_group)
                    )
                )

        if (
            self.LAST_INVENTORIED_FIELD not in row
            or row.get(self.LAST_INVENTORIED_FIELD) == ""
        ):
            self.logger.error(
                "run_id={} field={} missing from record={}".format(
                    self.run_id, self.LAST_INVENTORIED_FIELD, str(row)
                )
            )
            return False

        try:
            last_inventoried = row.get(self.LAST_INVENTORIED_FIELD)
            last_inventoried_date = datetime.strptime(
                last_inventoried,
                self.app_settings["additional_parameters"]["time_format"],
            )

        except (ValueError) as error:
            self.logger.error(
                "run_id={} error={} row={} field={} should be in format={}".format(
                    self.run_id,
                    str(error),
                    str(row),
                    str(self.LAST_INVENTORIED_FIELD),
                    str(self.app_settings["additional_parameters"]["time_format"]),
                )
            )
            return False
        except TypeError as error:
            self.logger.error(
                "run_id={} error={} row={} field={} missing".format(
                    self.run_id, str(error), str(row), str(self.LAST_INVENTORIED_FIELD)
                )
            )
            return False

        return True

    def is_expired(self, host_row, pre_expired_hosts):
        """
        Determine if the record should be expired out of hosts_lookup by comparing
        row[self.LAST_INVENTORIED_FIELD] to
          app_settings["asset_groups"][asset_group_xxx_max_age]

        @param host_row:            dict, an individual record from the aggregation lookup
        @param pre_expired_hosts:   list of strings, listing primary_id_field of each record matching
                                     the expiration clause.  These should automatically be marked expired
                                     even if max age has not passed.
        @returns                    boolean, should host be expired or is it still active?

        """
        key = host_row["_key"]
        asset_group = host_row.get("asset_group") or "default"
        max_age = int(self.app_settings.get(asset_group) or 180)

        last_inventoried = host_row.get(self.LAST_INVENTORIED_FIELD)

        last_inventoried_date = datetime.strptime(
            last_inventoried,
            self.app_settings["additional_parameters"]["time_format"],
        )

        ## should be adjusted for timezone but not possible with default python2.7
        ## TODO fix after update to splunk8
        delta = datetime.today() - last_inventoried_date
        self.logger.debug(
            "run_id={} row={} delta={} max_age={}".format(
                self.run_id, str(host_row), str(delta), str(max_age)
            )
        )

        to_delete = False
        if delta.days > max_age:
            # if delta is +10minutes from max_age, its still the same *day* and shouldn't be expired
            to_delete = True
            self.logger.info(
                'run_id={} script={} method=is_expired key={} status=expired reason="Last Inventoried {} days ago"'.format(
                    self.run_id, self.SCRIPT_NAME, str(key), str(delta)
                )
            )
        if host_row.get(self.VISIBLE_KEY_FIELD) in pre_expired_hosts:
            to_delete = True
            self.logger.info(
                'run_id={} script={} method=is_expired key={} stats=expired reason="matched expiration expression"'.format(
                    self.run_id, self.SCRIPT_NAME, str(key)
                )
            )
        return to_delete

    @log_enter_exit()
    def mark_expired(self, key, row, collection):
        """
        Denote records which have not received telemetry within the expected time range as expired, or match
        the specified expiration expression search.
        Set the 'expired' field to timestamp
        Write updated record back to Splunk kvstore collection
        NOTE: https://github.com/splunk/splunk-sdk-python/issues/361 regarding update calls with special characters in _key

        @param key:         string, the key attribute for this kvstore record
        @param row:         dict, the existing kvstore record
        @param collection:  splunklib.service.KvstoreCollection
        @returns            None

        """
        row[self.EXPIRED_FIELD] = datetime.today().strftime(
            self.app_settings["additional_parameters"]["time_format"]
        )
        payload = json.dumps(row)
        collection.data.update(key, payload)

    def strip_expiring_keys_from_mvkeys(self, expired_hosts, active_hosts):
        """
            Strip expiring key from any record VISIBLE_MVKEY_FIELD.
            If a record expires, set visible MVKEY to default (its visble key field)
            If key is contained in any OTHER records' hidden or visible MVKEY, strip it out.
            ie:
                ip       | ip_addresses    | (expiring)
                1.1.1.1  | 1.1.1.1 3.3.3.3 |  no
                3.3.3.3  | 1.1.1.1 3.3.3.3 |  yes

            In this case, 1.1.1.1 would be a key in active_hosts, 3.3.3.3 would be a key in expired_hosts.
            When we return, 1.1.1.1 will be moved in modified_hosts and 3.3.3.3 will be in expired hosts:

                ip       | ip_addresses     | (expiring)
                1.1.1.1  | 1.1.1.1          |  no
                3.3.3.3  | 3.3.3.3          |  yes

            If both records were expiring they would look like this:

                ip       | ip_addresses     | (expiring)
                1.1.1.1  | 1.1.1.1          |  yes
                3.3.3.3  | 3.3.3.3          |  yes

        @param expired_hosts:   2D dict, key is a record ip and the value is the event record from the aggregation table
        @param active_hosts:    2D dict, key is a record ip and the value is the event record from the aggregation table

        @return expired_hosts, modified_hosts   dicts
        """
        self.logger.debug(
            "run_id={} script={} method=strip_expiring_keys_from_mvkeys status=entered args={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                str(
                    {
                        "expired_host_count": len(expired_hosts or []),
                        "active_host_count": len(active_hosts or []),
                    }
                ),
            )
        )
        modified_hosts = {}
        all_expired_hosts = set(list(expired_hosts))

        for key, host_row in iteritems(expired_hosts):
            additional_records = host_row.get(
                self.VISIBLE_MVKEY_FIELD  ## stored as a list of strings
            )
            if not isinstance(additional_records, list):
                additional_records = [additional_records]

            if additional_records and len(additional_records) < 2:
                # no other elements to mvkey besides key (ie not really multi-valued)
                continue
            self.logger.debug(
                """run_id={} script={} method=strip_expiring_keys_from_mvkeys status="ensuring mvkey consistency" key={} host_row={} additional_record_keys={} type={}""".format(
                    self.run_id,
                    self.SCRIPT_NAME,
                    str(key),
                    str(host_row),
                    str(additional_records),
                    str(type(additional_records)),
                )
            )

            # in case IP becomes active in the future, dont want it to bring with it dirty mvkey data
            expired_hosts[key][self.VISIBLE_MVKEY_FIELD] = [key]
            # expired_hosts[key][self.HIDDEN_MVKEY_FIELD] = "${}$".format(str(key))

            ## speed optimization -- no further action needed
            if set(additional_records).issubset(all_expired_hosts):
                continue

            if additional_records:
                additional_records.pop(additional_records.index(key))

                for additional_key in additional_records:
                    ## check modified hosts first so we don't lose prior keys that have been stripped already
                    if (
                        additional_key not in modified_hosts
                        and additional_key in active_hosts
                    ):

                        modified_hosts[additional_key] = active_hosts[additional_key]

                    if (
                        additional_key in modified_hosts
                        and self.VISIBLE_MVKEY_FIELD in modified_hosts[additional_key]
                    ):

                        new_mvkey = modified_hosts[additional_key].get(
                            self.VISIBLE_MVKEY_FIELD
                        )

                        if new_mvkey and key in new_mvkey:
                            new_mvkey.pop(new_mvkey.index(key))
                            modified_hosts[additional_key][
                                self.VISIBLE_MVKEY_FIELD
                            ] = new_mvkey

        self.logger.debug(
            "run_id={} script={} method=strip_expiring_keys_from_mvkeys status=exited args={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                str(
                    {
                        "expired_host_count": len(expired_hosts or []),
                        "modified_host_count": len(modified_hosts or []),
                    }
                ),
            )
        )
        return expired_hosts, modified_hosts

    @log_enter_exit()
    def get_expiration_expression_results(self):
        """if the global add-on setting 'expiration_expression' exists, run the expression against
        the aggregation lookup table.  return a list of any keys with matching results.

        @returns    list of string, ip (key) from any records that match the expiration_expression search and should
        be flagged expired regardless of age.
        """

        output = []
        search = None

        if self.EXPIRATION_EXPRESSION:

            search_kwargs = {
                "search_mode": "normal",
                "count": 0,
                "preview": False,
                "output_mode": "json",
            }
            search = """| inputlookup {}
            | {} """.format(
                self.AGGREGATED_LOOKUP_NAME, self.EXPIRATION_EXPRESSION
            )
            self.logger.debug(
                "run_id={} script={} method=get_expiration_expression_results search={}".format(
                    self.run_id, self.SCRIPT_NAME, search
                )
            )
            expired = self.service.jobs.export(search, **search_kwargs)

            for item in expired:
                if item:
                    record = json.loads(item.decode("utf-8"))
                else:
                    continue

                if "result" in record:
                    key_match = record["result"].get(self.VISIBLE_KEY_FIELD)
                    if key_match:
                        output.append(key_match)
                    self.logger.debug(
                        "expire_inventory matched for expiration record dict: {}".format(
                            str(key_match)
                        )
                    )

                if "lastrow" in record:
                    break

        self.logger.debug(
            "run_id={} script={} method=get_expiration_expression_results status=executing expiration_search={} matching_records={}".format(
                self.run_id, self.SCRIPT_NAME, str(search), str(output)
            )
        )
        return output

    def categorize_host_records(self, valid, expiration_expression_matched):
        """categorize records into active or expired dicts
        @param valid:                           list of dicts
        @param expiration_expression_matched:   list of record keys (self.VISIBLE_KEY_FIELD)
        @returns                                list of dicts, list of dicts

        """
        self.logger.debug(
            "run_id={} script={} method=categorize_host_records status=entered".format(
                self.run_id,
                self.SCRIPT_NAME,
            )
        )
        expired = []
        active = []
        for record in valid:
            record_status = self.is_expired(record, expiration_expression_matched)
            if record_status:
                expired.append(record)
            elif record_status == False:
                active.append(record)

        self.logger.info(
            "run_id={} script={} method=categorize_host_records status=executing matched_expiration_expression={} valid={} active={} expired={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                str(len(expiration_expression_matched)),
                str(len(list(valid))),
                str(len(list(active))),
                str(len(list(expired))),
            )
        )

        # convert list of dicts to dicts, with key of primary_id_field
        active_hosts = {}
        if active:
            for item in active:
                key_field = "_key" or self.app_settings.get(
                    "additional_parameters"
                ).get("primary_id_field")
                key = item.get(key_field)
                active_hosts[key] = item

        expired_hosts = {}
        if expired:
            for item in expired:
                key_field = "_key" or self.app_settings.get(
                    "additional_parameters"
                ).get("primary_id_field")
                key = item.get(key_field)
                expired_hosts[key] = item

        self.logger.info(
            "run_id={} script={} method=categorize_host_records status=exited expired_host_count={} active_host_count={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                str(len(expired_hosts)),
                str(len(active_hosts)),
            )
        )
        return expired_hosts, active_hosts

    def expire_inventory(self, payload):
        """
        main method
        iterate over records in the aggregation collection (hosts_lookup_all)
        compare records age to global settings max_age for matching asset_group.
        once all records have been processed:
           * if asset only has 1 record, set expired appropriately
           * if asset has multiple (ip) records, don't expire them unless ALL are expired.
        finally, set any remaining in the expired group, | eval expired="true"

        """

        # initialize

        token = payload.get("session_key")
        self.service = client.connect(token=token, app=self.APP_NAME, owner="Nobody")
        self.app_settings = self.read_app_settings(token)
        self.app_settings = self.normalize_global_settings(self.app_settings)
        super().setup(self.service, self.app_settings)

        if payload.get("configuration") and payload["configuration"].get("log_level"):
            loglevel = payload["configuration"].get("log_level")
        else:
            try:
                loglevel = self.app_settings["logging"].get("loglevel")
                if not loglevel:
                    self.logger.error(
                        "LOGLEVEL app configuration not set, please visit app configuration page"
                    )
                    sys.exit(1)
            except KeyError:
                self.logger.error(
                    "LOGLEVEL app configuration not set, please visit app configuration page"
                )
                sys.exit(1)

        solnlib.log.Logs().set_level(loglevel)
        self.logger.info("run_id:{} loglevel:{}".format(self.run_id, str(loglevel)))

        self.logger.info(
            "run_id={} script=expire_inventory settings={}".format(
                self.run_id, str(self.app_settings)
            )
        )
        collection_svc = self.service.kvstore[self.AGGREGATED_COLLECTION_NAME]
        collection_data = self.get_kvstore_records(self.AGGREGATED_COLLECTION_NAME)

        self.logger.info(
            "run_id={} examining count={} host records".format(
                self.run_id, str(len(collection_data))
            )
        )

        force = False
        payload_config = {}
        if "configuration" in payload:
            payload_config = payload["configuration"]
            force = payload_config.get("force")
            if force == "None":
                force = None
            elif force in ["true", "True", "TRUE", "1", "t", "T"]:
                force = True
            else:
                force = False

        if force:
            expiration_expression_matched = []
            self.logger.debug(
                "run_id:{} force expiration of all records passed".format(self.run_id)
            )
            results_file = payload.get("results_file")
            if not results_file:
                self.logger.error(
                    'run_id={} status:fail, msg="no results file included"'.format(
                        self.run_id
                    )
                )
                sys.exit(1)
            with gzip.open(results_file, "rt") as csv_file:
                csvreader = csv.DictReader(csv_file)
                for line in csvreader:
                    if line:
                        try:
                            expiration_expression_matched.append(
                                line[self.VISIBLE_KEY_FIELD]
                            )
                        except KeyError:
                            self.logger.error(
                                'run_id:{} status="failed to force expiration", field={} is not present in record={}'.format(
                                    self.run_id, self.VISIBLE_KEY_FIELD, str(line)
                                )
                            )

        else:
            self.logger.debug("run_id:{} NOT force mode".format(self.run_id))
            expiration_expression_matched = self.get_expiration_expression_results()
        self.logger.info(
            "found {} expiration expression matches: ".format(
                str(len(expiration_expression_matched))
            )
        )

        valid = filter(lambda x: self.is_valid_record(x) == True, collection_data)
        expired_hosts, active_hosts = self.categorize_host_records(
            valid, expiration_expression_matched
        )

        (
            expired_hosts,
            modified_hosts,
        ) = self.strip_expiring_keys_from_mvkeys(expired_hosts, active_hosts)

        self.logger.debug(
            'run_id={} expired_host_count={} active_host_count={} modified_host_count={} status="finished removing expired keys from mv_keys across all records"'.format(
                self.run_id,
                str(len(expired_hosts)),
                str(len(active_hosts)),
                str(len(modified_hosts)),
            )
        )

        ## write any needed record updates
        ## TODO should make this more atomic and make updates around the same mv_key changes all at the same time...
        ## but we should be reducing writes this way as well
        if not expired_hosts and not modified_hosts:
            self.logger.info(
                "run_id={} status:completed expired_hosts_count={} modified_hosts_count={}".format(
                    self.run_id, str(len(expired_hosts)), str(len(modified_hosts))
                )
            )
            return True

        if expired_hosts:

            for key, host_row in iteritems(expired_hosts):
                self.logger.info(
                    "run_id={} expiring key={} from source={}".format(
                        self.run_id, str(key), str(collection_svc.name)
                    )
                )
                host_row[self.EXPIRED_FIELD] = datetime.today().strftime(
                    self.app_settings["additional_parameters"]["time_format"]
                )

                ## scan remaining lookup tables to purge host from
                self.expire_all_records_for_key(host_row)

            # now we write the expired records to the kvstore
            expired_records = [
                record for key, record in iteritems(expired_hosts) if record
            ]
            self.handle_cached_write(
                self.AGGREGATED_COLLECTION_NAME, records=expired_records
            )
            self.logger.info(
                "run_id={} script={} method=write_expired_records status=complete expired_record_count={}".format(
                    self.run_id, self.SCRIPT_NAME, str(len(expired_records))
                )
            )

        if modified_hosts:

            for key, host_row in iteritems(modified_hosts):
                self.logger.info(
                    "run_id={} updating mvkey for ={} from source={}".format(
                        self.run_id, str(key), str(collection_svc.name)
                    )
                )
                payload = json.dumps(host_row)

                # cache record for batch writing
                self.handle_cached_write(
                    self.AGGREGATED_COLLECTION_NAME, records=payload
                )

        for collection_name in self.write_cache.keys():
            if len(self.write_cache[collection_name]) > 0:
                self.logger.debug(
                    "run_id={} script={} status=writing_cache collection={} record_count={}".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        str(collection_name),
                        str(len(self.write_cache[collection_name])),
                    )
                )
                self.handle_cached_write(collection_name, force=True)

        self.logger.info(
            "run_id={} status:completed expired_hosts_count={} modified_hosts_count={} with updated mvkey".format(
                self.run_id, str(len(expired_hosts)), str(len(modified_hosts))
            )
        )

        return True


# splunk doc boilerplate
if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print(
            "FATAL Unsupported Execution mode :expected --execute flag, got "
            + str(sys.argv)
            + "; see alert_actions.conf",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        payload = json.loads(sys.stdin.read())
        obj = InventoryExpirator()
        if not obj.expire_inventory(payload):
            print("FATAL Failed trying to expire inventory", file=sys.stderr)
            sys.exit(2)
        else:
            print("DEBUG Inventory Successfully Expired", file=sys.stderr)
