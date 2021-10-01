# encoding = utf-8

import copy
import csv
import gzip
import json
import os
import sys

import import_declare_test
import solnlib.log
import splunklib.client

from oversight_utils import log_enter_exit, OversightScript


class InventoryUpdater(OversightScript):
    """This class is responsible for aggregating one or more events into the aggregated lookup table.
    These defaults are overridden by any values specified in app-wide setup"""

    SCRIPT_NAME = "update_inventory"
    logger = None

    def __init__(self):

        ########### Set file logging #############################
        # logs found: index=_internal sendmodalert action=update_inventory
        # Splunk native logs can be found at:
        # index=_internal sourcetype=splunkd component=sendmodalert action=update_inventory
        # or
        # index=_internal sourcetype="oversight:log"
        super().__init__()

    @log_enter_exit()
    def aggregate_timestamps(self, output_event, input_event):
        """This method compares takes the existing aggregated record, the input event record,
        and outputs a dict with any updated values for self.FIRST_INVENTORIED_FIELD, self.LAST_INVENTORIED_FIELD,
        and self.last_checkin_source_field.  The values should be strings for each of these fields.  If the existing values
        are correct (from host_row), then omit the key and value from the result.

        self.source_name=test
        aggregate_timestamps(
            {"first_seen": "2020-01-01", "last_seen": "2020-02-01", "test_last_seen": "2020-02-01"},
            {"last_seen":"2020-03-01"}
        )
        ==> {"test_last_seen":"2020-03-01","last_seen":"2020-03-01"}

        aggregate_timestamps(
            {"first_seen": "2020-01-01", last_seen": "2020-01-01", "test_last_seen":"2020-01-05"},
            {"last_seen": "2020-01-08"}
        )
        ==> {"test_last_seen":"2020-01-08}

        aggregate_timestamps(
            {"first_seen": "2020-01-01", last_seen": "2020-01-01", "test_last_seen":"2020-01-05"},
            {"last_seen": "2019-12-25"}
        )
        ==> {}




        @param output_event:        dict - should be None, or contain values for keys self.FIRST_INVENTORIED_FIELD and
                                      self.LAST_INVENTORIED_FIELD, and possibly for self.last_checkin_source_field
        @param input_event:     dict - the input event - must contain a value for self.LAST_INVENTORIED_FIELD
        @returns                dict with updated values of self.FIRST_INVENTORIED_FIELD, self.LAST_INVENTORIED_FIELD,
                                     and self.last_checkin_source_field
        """
        output = {}
        if not input_event:
            input_event = {}
        if not output_event:
            output_event = {}

        if not output_event and not input_event:
            return {}

        if not input_event:
            return {}

        try:
            input_event_last_inventoried = input_event[self.LAST_INVENTORIED_FIELD]
        except KeyError as error:
            self.logger.error(
                'run_id={} status="missing required field" in input: {} error:{}'.format(
                    self.run_id, self.LAST_INVENTORIED_FIELD, str(error)
                )
            )
            raise ValueError(
                "input event missing field={}".format(self.LAST_INVENTORIED_FIELD)
            )

        if not output_event:
            return {
                self.FIRST_INVENTORIED_FIELD: input_event_last_inventoried,
                self.LAST_INVENTORIED_FIELD: input_event_last_inventoried,
                self.last_checkin_source_field: input_event_last_inventoried,
            }

        existing_first = output_event.get(self.FIRST_INVENTORIED_FIELD)
        existing_last = output_event.get(self.LAST_INVENTORIED_FIELD)
        existing_last_checkin_source_field = output_event.get(
            self.last_checkin_source_field
        )

        # normalize to epoch time
        existing_first_epoch = None
        existing_last_epoch = None
        input_event_last_inventoried_epoch = None
        existing_last_checkin_source_field_epoch = None

        if existing_first:
            existing_first_epoch = self.convert_timestring_to_epoch(
                existing_first, self.TIME_FORMAT
            )

        if existing_last:
            existing_last_epoch = self.convert_timestring_to_epoch(
                existing_last, self.TIME_FORMAT
            )

        if input_event_last_inventoried:
            input_event_last_inventoried_epoch = self.convert_timestring_to_epoch(
                input_event_last_inventoried, self.TIME_FORMAT
            )

        if existing_last_checkin_source_field:
            existing_last_checkin_source_field_epoch = self.convert_timestring_to_epoch(
                existing_last_checkin_source_field, self.TIME_FORMAT
            )

        if (
            not existing_last_epoch
            or input_event_last_inventoried_epoch > existing_last_epoch
        ):
            output.update({self.LAST_INVENTORIED_FIELD: input_event_last_inventoried})

        if (
            not existing_first_epoch
            or input_event_last_inventoried_epoch < existing_first_epoch
            or (existing_first is None)
        ):
            output.update({self.FIRST_INVENTORIED_FIELD: input_event_last_inventoried})

        if (
            not existing_last_checkin_source_field_epoch
            or input_event_last_inventoried_epoch
            > existing_last_checkin_source_field_epoch
        ):
            output.update(
                {self.last_checkin_source_field: input_event_last_inventoried}
            )

        return output

    @log_enter_exit()
    def make_key_safe(self, key):
        """Work around for bug using ':' and/or other special characters in _key
        If this is not done, inserts will succeed but updates/queries will return null, so app logic will
        fall back to insert which will then fail.

        @param key:  string
        @returns     string
        """
        if not key:
            return None
        if "/" in key:
            key = key.replace("/", "")
        return key

    @log_enter_exit()
    def extract_aggregation_fields(self, input_event):
        """returns dict of any aggregation fields present in input_event with their values
        aggregation_fields is normalized into a list during setup, and is definied as an input parameter
        of the oversight modular input.  The use of the parameter is to specify fields from the inital source event which
        should be copied verbatim into the aggregated lookup table

        @param input_event:    dict, the current input event being processed
        @returns        dict, aggregation field keys and their values from input_event"""

        output = {}
        if self.aggregation_fields:
            for field in self.aggregation_fields:
                mv_fieldname = "__mv_{}".format(field)
                if input_event.get(mv_fieldname):
                    output[field] = self.parse_mvkey_string(
                        input_event.get(mv_fieldname)
                    )
                elif input_event.get(field):
                    output[field] = input_event.get(field)
                else:
                    output[field] = None

        return output

    @log_enter_exit()
    def parse_mvkey_string(self, string):
        """splunk sends multi-value field values in format "$val1$;$val2$;$val3$;....
        string may be an empty string as that is the default sent by splunk if there is a single or null value

        @param string:  input splunk mk field value
        @returns        list of strings or none
        """
        if string is None:
            return None
        output = [i.strip("$") for i in string.split(";")]

        if (
            output
            and isinstance(output, list)
            and len(output) == 1
            and bool(output[0]) is False
        ):
            return None
        else:
            return output

    def get_normalized_fieldlist(self, aggregation_fieldlist_string):
        """@param aggregation_fieldlist_string: string of zero or more field names, comma seperated
        @return                                 None or list of strings
        """
        if aggregation_fieldlist_string:
            aggregation_fieldlist = aggregation_fieldlist_string.split(",")
            aggregation_fieldlist = [
                i.strip() for i in aggregation_fieldlist if i is not None
            ]
            return aggregation_fieldlist
        else:
            return None

    def validate_alert_arguments(self, payload):
        """validate required command parameters have been included or raise ValueError and log CRITICAL"""

        if not payload["configuration"].get("source_name"):
            self.logger.critical(
                "run_id={} source_name parameter missing, aborting".format(self.run_id)
            )
            raise ValueError(
                "run_id={} source_name parameter missing, aborting".format(self.run_id)
            )
        self.logger.debug(
            "run_id={} script={} method=validate_alert_arguments status=exiting source_name={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                payload["configuration"].get("source_name"),
            )
        )

    @log_enter_exit()
    def aggregate_event(self, input_event, output_event, output_key):
        """
        Take a single event from the input pipeline and aggregate it with the
        existing contents of the aggregated lookup

        1. Update output_event timestamps for self.LAST_INVENTORIED_FIELD,
            self.FIRST_INVENTORIED_FIELD, and self.last_checkin_source_field, as necessary
        2. Add the aggregation field values to output_event from input_event, if necessary
        3. Set output_event['asset_group'] if defined in modular input parameters
        4. Set "expired" to false unless it is current not false

        @param input_event - dict - the input event to be aggregated from the splunk event pipeline
        @param output_event - dict - the event record being aggregated for writing to the kvstore
        @param output_key - string - the self.HIDDEN_KEY_FIELD of output_event
        @return - output_key, output_event
        """
        updated_timestamp_fields = self.aggregate_timestamps(output_event, input_event)
        output_event.update(updated_timestamp_fields)

        aggregation_field_update = self.extract_aggregation_fields(input_event)

        # remove any mvkey_update.keys() from aggregation_field_update to guard against user error
        if self.VISIBLE_MVKEY_FIELD in aggregation_field_update:
            aggregation_field_update.pop(self.VISIBLE_MVKEY_FIELD)

        # Add input_settings.aggregation field values
        output_event.update(aggregation_field_update)

        # lastly, set 'expired' to false
        if self.asset_group:
            output_event["asset_group"] = self.asset_group

        output_event["expired"] = input_event.get("expired") or "false"
        return output_event, output_key

    def get_base_fields(self):
        """enforce the schema and ensure minimal fields are populated if there is no existing data for the key"""
        base_fields = [
            self.HIDDEN_KEY_FIELD,
            self.VISIBLE_KEY_FIELD,
            self.last_checkin_source_field,
            self.LAST_INVENTORIED_FIELD,
            self.FIRST_INVENTORIED_FIELD,
            self.VISIBLE_MVKEY_FIELD,
            self.id_field,
        ]
        if self.mv_id_field:
            base_fields.append(self.mv_id_field)

        base_fields = dict.fromkeys(list(set(base_fields)))
        return base_fields

    # do not log payload directly it includes a token and splunk URI (sensitive)
    def setup_attributes(self, service, payload, app_settings, input_settings):
        """set InventoryUpdater attributes from app settings and input settings"""
        self.logger.debug(
            "run_id={} script={} input={} method={} status={} app_settings={} input_settings={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                "setup_attributes",
                "entered",
                str(app_settings),
                str(input_settings),
            )
        )
        super().setup(service, app_settings)

        self.TIME_FORMAT = app_settings["additional_parameters"].get("time_format")

        if payload.get("configuration") and payload["configuration"].get("log_level"):
            loglevel = payload["configuration"].get("log_level")
        else:
            try:
                loglevel = app_settings["logging"].get("loglevel")
                if not loglevel:
                    self.logger.error(
                        "LOGLEVEL app configuration not set, please visit app configuration page"
                    )
                    raise ValueError(
                        "LOGLEVEL app configuration setting not set, please visit app configuration page and retry"
                    )
            except KeyError:
                self.logger.error(
                    "LOGLEVEL app configuration not set, please visit app configuration page"
                )
                raise ValueError(
                    "LOGLEVEL app configuration setting not set, please visit app configuration page and retry"
                )
        solnlib.log.Logs().set_level(loglevel)

        # https://docs.splunk.com/Documentation/Splunk/7.3.0/AdvancedDev/CustomAlertConfig
        # payload parameter defined in alert_actions.conf then value overwritten by each savedsearch invocation
        self.logger.info(
            "Payload included parameters={} run_id={} ".format(
                str(payload["configuration"]), self.run_id
            )
        )

        if not self.source_name:
            self.logger.error(
                'run_id={} status=fail msg="missing required alert action parameter `source_name`"'.format(
                    self.run_id
                )
            )
            raise ValueError(
                'run_id={} status=fail msg="missing required alert action parameter `source_name`"'.format(
                    self.run_id
                )
            )

        self.last_checkin_source_field = "{}_{}".format(
            self.source_name, self.LAST_INVENTORIED_FIELD
        )
        # service.inputs yields 404 if directly accessed as non-admin .... not sure why
        if self.source_name not in [
            i.name for i in self.service.inputs.list(self.MODINPUT_KIND, count=-1)
        ]:
            self.logger.error(
                "run_id={} input={} status=fail msg=invalid source={} specified".format(
                    self.run_id, self.source_name, self.source_name
                )
            )
            raise ValueError(
                "run_id={} input={} status=fail msg=invalid source={} specified".format(
                    self.run_id, self.source_name, self.source_name
                )
            )

        self.asset_group = input_settings.get("asset_group") or "default"
        self.aggregation_fields = self.get_normalized_fieldlist(
            input_settings.get("aggregation_fields")
        )
        self.id_field = input_settings.get("id_field_rename") or input_settings.get(
            "id_field"
        )

        self.mv_id_field = input_settings.get("mv_id_field")
        self.mv_key_field = "__mv_" + self.mv_id_field if self.mv_id_field else []
        self.logger.info(
            "mv_key_field={} timestamp_field={} run_id={} input={}".format(
                str(self.mv_key_field),
                str(self.last_checkin_source_field),
                self.run_id,
                self.source_name,
            )
        )
        if self.AGGREGATED_COLLECTION_NAME in self.service.kvstore:

            self.aggregated_collection = self.service.kvstore[
                self.AGGREGATED_COLLECTION_NAME
            ]
        else:
            self.logger.error(
                "run_id={} script={} input={} method={} status={}".format(
                    self.run_id,
                    self.SCRIPT_NAME,
                    self.source_name,
                    "setup_attributes",
                    "could not connect to aggregated collection name, check {} exists in collections.conf".format(
                        self.AGGREGATED_COLLECTION_NAME
                    ),
                )
            )
        self.logger.debug(
            "run_id={} script={} input={} method={} status={} attributes={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                "setup_attributes",
                "exited",
                str(
                    {
                        "TIME_FORMAT": self.TIME_FORMAT,
                        "loglevel": loglevel,
                        "last_checkin_source_field": self.last_checkin_source_field,
                        "asset_group": self.asset_group,
                        "aggregation_fields": self.aggregation_fields,
                        "id_field": self.id_field,
                        "mv_id_field": self.mv_id_field,
                        "mv_key_field": self.mv_key_field,
                        "aggregated_collection": self.aggregated_collection.name,
                    }
                ),
            )
        )

    def validate_input_event(self, event):
        """return True if event has all required fields"""
        if not event:
            return False

        if not event.get(self.LAST_INVENTORIED_FIELD):
            self.logger.warning(
                'run_id={} status="invalid input" event={} missing_field={}'.format(
                    self.run_id, str(event), self.LAST_INVENTORIED_FIELD
                )
            )
            return False
        if not event.get(self.id_field):
            self.logger.warning(
                'run_id={} status="invalid input" event={} missing_field={}'.format(
                    self.run_id, str(event), self.id_field
                )
            )
            return False
        if not event.get("expired"):
            self.logger.warning(
                'run_id={} status="invalid input" event={} missing_field={}'.format(
                    self.run_id, str(event), "expired"
                )
            )
            return False
        if not event.get(self.HIDDEN_KEY_FIELD):
            self.logger.warning(
                'run_id={} status="invalid input" event={} missing_field={}'.format(
                    self.run_id, str(event), self.HIDDEN_KEY_FIELD
                )
            )
            return False

        return True

    @log_enter_exit()
    def initialize_output_event(self, input_event, base_fields):
        """either pull current record from local cache, or initialize new empty record for self.HIDDEN_KEY_FIELD
        NOTE that input_event has already been passed through validate_input_event so we know minimal fields are
        present

        @param input_event - dict - the input event from the alert arg pipeline
        @return output_key, output_event - string, dict
           output_key is the hidden key
           output_event is either the existing data for the record in the aggregation collection (cached) or a dict
           with the required keys set to None
        """
        output_key = input_event[self.HIDDEN_KEY_FIELD]

        # remove chars illegal for kvstore/mongodb _key field value
        readable_key = copy.deepcopy(output_key)
        output_key = self.make_key_safe(output_key)

        output_event = self.get_cached_record(output_key)

        if not output_event:
            output_event = copy.deepcopy(base_fields)
            output_event.update({self.VISIBLE_KEY_FIELD: input_event[self.id_field]})

        output_event[self.HIDDEN_KEY_FIELD] = output_key
        if self.mv_key_field:
            mvkeys = self.parse_mvkey_string(input_event.get(self.mv_key_field))
        else:
            mvkeys = None
        output_event.update({self.VISIBLE_MVKEY_FIELD: mvkeys or [readable_key]})
        return output_key, output_event

    def identify_records_with_outdated_mvkeys(
        self, records_to_review, phase_one_records
    ):
        """this method provides a list of which record keys have multi-value field self.VISIBLE_MVKEY_FIELD which is out-of sync.
        Out-of-sync means either there is an incomming, to-be-aggregated record where self.VISIBLE_MVKEY_FIELD is missing values,
        or an existing record in self.AGGREGATION_COLLECTION that is missing values in self.VISIBLE_MVKEY_FIELD.
        Our business logic is the self.VISIBLE_MVKEY_FIELD is the set of all active self.VISIBLE_KEY_FIELD, given at least one or more common values.
        No other fields are examined (mac address, hostname, etc)

        @param records_to_review: list of strings - all records in phase_one_records where self.VISIBLE_MVKEY_FIELD len>1 or
                                                    aggregation_cache where self.VISIBLE_MVKEY_FIELD len>1
        @param phase_one_records - aggregated records which may have multi-value
        """
        self.logger.debug(
            """run_id={} script={} input={} method=identify_records_with_outdated_mvkeys status=entered args={}""".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                str(
                    {
                        "records_to_review_size": len(records_to_review or []),
                        "phase_one_records_size": len(phase_one_records or []),
                    }
                ),
            )
        )
        output = []

        for key in records_to_review:
            cached_mvkey = (
                self.aggregation_cache[key].get(self.VISIBLE_MVKEY_FIELD)
                if self.aggregation_cache.get(key)
                else None
            )
            phase_one_mvkey = (
                phase_one_records[key].get(self.VISIBLE_MVKEY_FIELD)
                if phase_one_records.get(key)
                else None
            )
            if cached_mvkey != phase_one_mvkey:
                output.append(key)
        self.logger.debug(
            """run_id={} script={} input={} method=identify_records_with_outdated_mvkeys status=exited return_size={}""".format(
                self.run_id, self.SCRIPT_NAME, self.source_name, str(len(output))
            )
        )

        return output

    def calculate_new_mvkeys(self, current_mvkey, incoming_mvkey):
        """this method returns the sorted list of all mvkey values seen for the given asset"""
        if not current_mvkey and not incoming_mvkey:
            new_mvkey = None
        elif current_mvkey == incoming_mvkey:
            new_mvkey = None
        elif current_mvkey and incoming_mvkey:
            new_mvkey = sorted(list(set.union(current_mvkey, incoming_mvkey)))
        elif current_mvkey:
            new_mvkey = sorted(list(current_mvkey))
        elif incoming_mvkey:
            new_mvkey = sorted(list(incoming_mvkey))
        return new_mvkey

    def update_cache_and_aggregation_mvkeys(
        self, key, new_mvkey, phase_one_records, update_existing_key_only
    ):
        """given a key and the correct mvkey value, update the cache and add pending writes if necessary

        @param key:       string - record key known to be out of sync between incoming records and existing records
        @param new_mvkey: list of strings -  the correct self.VISIBLE_MVKEY_FIELD to use
        @param phase_one_records: 2D dict - records aggregated but may be without mvkey syncronization
        @param update_existing_key_only: 2d dict - updated records of the aggregation cache that are not included in the incoming event set
        @returns update_existing_key_only - 2d dict - with any changes"""

        # the current mvkey already in the aggregation lookup needs to be updated!
        # queue every existing record to be written as well, if not already queued
        # this updates the cache copy of splunklib.client.service.kvstore[self.AGGREGATION_COLLECTION].data.query()
        # as well as the
        # step1 update aggregation_cache

        self.logger.debug(
            """run_id={} script={} input={} method=update_cache_and_aggregation_mvkeys status=entered args={}""".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                str(
                    {
                        "key": key,
                        "new_mvkey": new_mvkey,
                        "update_existing_key_only_size": len(
                            update_existing_key_only or []
                        ),
                    }
                ),
            )
        )

        if key in self.aggregation_cache:
            self.update_cached_record(key, **{self.VISIBLE_MVKEY_FIELD: new_mvkey})

            # step2, queue record for writing with updated VISIBLE_MVKEY_FIELD

            if key not in phase_one_records and key not in update_existing_key_only:
                update_existing_key_only[key] = self.get_cached_record(key)
                update_existing_key_only[key][self.VISIBLE_MVKEY_FIELD] = new_mvkey

        self.logger.debug(
            """run_id={} script={} input={} method=update_cache_and_aggregation_mvkeys status=exited args={}""".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                str(
                    {
                        "update_existing_key_only_size": len(
                            update_existing_key_only or []
                        )
                    }
                ),
            )
        )
        return update_existing_key_only

    def update_inventory(self, payload):
        """This is the method called by Splunk to initate the alert action.
        @param payload:      contains link to results file from outputlookup

        """

        ## token not available at script init for alert action so set now

        self.logger.info(
            "run_id={} script={} status=running".format(self.run_id, self.SCRIPT_NAME)
        )
        self.validate_alert_arguments(payload)
        token = payload.get("session_key")
        app_settings = self.read_app_settings(token)
        service = splunklib.client.connect(
            token=token, app=self.APP_NAME, owner="Nobody"
        )
        super().setup(service, app_settings)

        # get information about the source being aggregated
        # beware permission issues if changing this statement
        self.source_name = payload["configuration"].get("source_name")
        self.logger.debug(
            """run_id={} script={} input={} status="loading input definition" """.format(
                self.run_id, self.SCRIPT_NAME, self.source_name
            )
        )
        try:
            input_settings = [
                i.content
                for i in self.service.inputs.list(self.MODINPUT_KIND, count=-1)
                if i.name == self.source_name
            ][0]
        except IndexError:
            self.logger.critical(
                """run_id={} script={} input={} status=failed reason="could not load input definition.  Please try to EDIT and SAVE this input definition. Aborting execution." """.format(
                    self.run_id, self.SCRIPT_NAME, self.source_name
                )
            )
            sys.exit(1)

        self.setup_attributes(self.service, payload, app_settings, input_settings)
        self.logger.debug(
            "run_id={} script={} input={} input_settings={} app_settings={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                str(input_settings),
                str(app_settings),
            )
        )
        base_fields = self.get_base_fields()

        self.logger.debug(
            "run_id={} input={} base_fields={}".format(
                self.run_id, self.source_name, str(base_fields)
            )
        )

        # prior host variables are to track if a given key has already been inserted previously.
        # If so, do an update not an insert.  Used to avoid excessive API calls for each record.
        # helpful to have this cache as an attribute for testing
        cache = self.get_kvstore_records(self.AGGREGATED_COLLECTION_NAME)
        self.aggregation_cache = self.get_dict_from_records("_key", cache)
        aggregation_cache_mvkey = [
            k
            for k, v in self.aggregation_cache.items()
            if v.get(self.VISIBLE_MVKEY_FIELD) and len(v[self.VISIBLE_MVKEY_FIELD]) > 1
        ]

        self.logger.debug(
            "prior_host_data_size={} run_id={} input={} kvstore_max_batch={}".format(
                str(len(self.aggregation_cache)),
                self.run_id,
                self.source_name,
                self.kvstore_max_batch,
            )
        )

        results_file = payload.get("results_file")
        if not results_file:
            self.logger.error(
                'run_id={} input={} status:fail msg="no results file included"'.format(
                    self.run_id,
                    self.source_name,
                )
            )
            sys.exit(1)

        # still need to examine to see if self.VISIBLE_MVKEY_FIELD needs to be synchronized or not, dont' write yet!
        phase_one_records = {}
        phase_one_mvkey_records = []

        with gzip.open(
            results_file,
            "rt",
        ) as csv_file:
            csvreader = csv.DictReader(csv_file)
            invalid_input_event_count = 0

            for input_event in csvreader:
                if not self.validate_input_event(input_event):
                    invalid_input_event_count += 1
                    continue
                output_key, output_event = self.initialize_output_event(
                    input_event, base_fields
                )

                if output_event.get("expired") != "false":
                    # this is a repurposed IP that was previously expired; search and destory all records!
                    field_names_to_purge = self.get_fieldnames_to_purge(output_event)
                    if self.aggregation_cache.get(output_key):
                        del self.aggregation_cache[output_key]
                    self.expire_all_records_for_key(output_event, purge_mode=True)
                    if field_names_to_purge:
                        for field in field_names_to_purge:
                            del output_event[field]

                    output_key, output_event = self.initialize_output_event(
                        input_event, base_fields
                    )
                    self.logger.debug(
                        "run_id={} input={} key={} purged from cache and re-initialized to event={}".format(
                            self.run_id,
                            self.source_name,
                            str(output_key),
                            str(output_event),
                        )
                    )

                output_event, output_key = self.aggregate_event(
                    input_event, output_event, output_key
                )
                phase_one_records.update({output_key: output_event})
                if (
                    output_event.get(self.VISIBLE_MVKEY_FIELD)
                    and len(output_event.get(self.VISIBLE_MVKEY_FIELD)) > 1
                ):
                    phase_one_mvkey_records.append(output_key)

        self.logger.debug(
            """run_id={} input={} method=mvkey_synchronization status=entered""".format(
                self.run_id, self.source_name
            )
        )
        # existing records with mvkey that are also in the incoming event set
        records_to_review = set(aggregation_cache_mvkey + phase_one_mvkey_records)
        keys_of_records_with_incorrect_mvkeys = (
            self.identify_records_with_outdated_mvkeys(
                records_to_review, phase_one_records
            )
        )

        update_existing_key_only = {}
        for key in keys_of_records_with_incorrect_mvkeys:
            existing_mvkey = (
                self.aggregation_cache[key].get(self.VISIBLE_MVKEY_FIELD)
                if key in self.aggregation_cache
                else None
            )
            incoming_mvkey = (
                phase_one_records[key].get(self.VISIBLE_MVKEY_FIELD)
                if key in phase_one_records
                else None
            )
            if existing_mvkey:
                existing_mvkey = set(existing_mvkey)
            if incoming_mvkey:
                incoming_mvkey = set(incoming_mvkey)

            new_mvkey = self.calculate_new_mvkeys(existing_mvkey, incoming_mvkey)
            if not new_mvkey:
                continue

            if key in phase_one_records:
                phase_one_records[key][self.VISIBLE_MVKEY_FIELD] = new_mvkey
            if existing_mvkey and sorted(list(existing_mvkey)) != new_mvkey:
                update_existing_key_only = self.update_cache_and_aggregation_mvkeys(
                    key, new_mvkey, phase_one_records, update_existing_key_only
                )

            if (
                existing_mvkey
                and incoming_mvkey
                and not existing_mvkey.issubset(incoming_mvkey)
            ):
                # add additional pending writes in edge cases
                # look for all OTHER keys in new_keys, make sure they get updated too!
                # ie existing_mvkey =["1", "2", "3"], incoming_mvkey: ["1","2","4"] ==> new_keys=["1", "2", "3", "4"]
                # "4" will not be included in phase_one_records but needs to be updated in the aggregation collection

                missing_mvkey_values = (
                    set(incoming_mvkey).difference(set(new_mvkey))
                    if incoming_mvkey and new_mvkey
                    else incoming_mvkey or new_mvkey
                )
                for key in missing_mvkey_values:
                    if (
                        key in self.aggregation_cache
                        and key not in update_existing_key_only
                        and key not in phase_one_mvkey_records
                    ):
                        update_existing_key_only[key] = self.get_cached_record(key)
                        update_existing_key_only[key][
                            self.VISIBLE_MVKEY_FIELD
                        ] = new_mvkey

        self.logger.debug(
            "run_id={} input={} method=mvkey_synchronization status=exit".format(
                self.run_id, self.source_name
            )
        )
        records_batch_1 = [
            value for value in update_existing_key_only.values() if value
        ]
        records_batch_2 = [value for value in phase_one_records.values() if value]
        if len(records_batch_1) > 0:
            self.handle_cached_write(
                self.AGGREGATED_COLLECTION_NAME, records=records_batch_1, force=True
            )
        if len(records_batch_2) > 0:
            self.handle_cached_write(
                self.AGGREGATED_COLLECTION_NAME, records=records_batch_2, force=True
            )
        self.logger.debug(
            "run_id={} input={} forcing a cached write".format(
                self.run_id, self.source_name
            )
        )
        self.logger.info(
            "run_id={} input={} status=completed skipped_invalid_events={} aggregated_record_count={} aggregated_record_key_update_count={}".format(
                self.run_id,
                self.source_name,
                str(invalid_input_event_count),
                str(len(phase_one_records)),
                str(len(update_existing_key_only)),
            )
        )
        return True


## https://localhost:8089/servicesNS/nobody/TA-oversight/storage/collections/data/hosts_collection

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print(
            "FATAL Unsupported Execution mode :expected --execute flag, got "
            + str(sys.argv),
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        payload = json.loads(sys.stdin.read())
        obj = InventoryUpdater()

        if not obj.update_inventory(payload):
            print("FATAL Failed trying to update inventory", file=sys.stderr)
            sys.exit(2)
        else:
            print("DEBUG Inventory Successfully Updated", file=sys.stderr)
