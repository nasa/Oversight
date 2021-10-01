# encoding = utf-8

import copy
import inspect
import json
import os
import time
from datetime import datetime, timedelta

import import_declare_test
import splunklib.binding as binding
from solnlib import conf_manager, log
from splunklib.client import HTTPError, namespace


def log_enter_exit(msg="entered"):
    """logging decorator, example from solnlib.log"""

    def log_decorator(func):
        def wrapper(self=None, *args, **kwargs):
            bound = inspect.signature(func).bind(self, *args, **kwargs)
            self.logger.debug(
                'run_id={} script={} input={} method={} status="{}" args={}'.format(
                    self.run_id,
                    self.SCRIPT_NAME,
                    str(self.params.get("name")),
                    func.__name__,
                    str(msg),
                    str([{k: v} for k, v in bound.arguments.items() if k != "self"]),
                )
            )
            if self:
                result = func(self, *args, **kwargs)
            else:
                result = func(*args, **kwargs)

            if result is not None:
                self.logger.debug(
                    "run_id={} script={} input={} method={} status=exited return={}".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        str(self.params.get("name")),
                        func.__name__,
                        str(result),
                    )
                )
            else:
                self.logger.debug(
                    "run_id={} script={} input={} method={} status=exited".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        str(self.params.get("name")),
                        func.__name__,
                    )
                )
            return result

        return wrapper

    return log_decorator


class MissingAppSetting(Exception):
    """This exception indicates that a required setting is missing"""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class OversightScript:

    APP_NAME = import_declare_test.ta_name
    APP_SETTINGS_FILENAME = "ta_oversight_settings"
    SERVICE_CONTEXT = namespace(
        app=APP_NAME, user="nobody", sharing="app"
    )  # required for editing collections.conf
    SCRIPT_NAME = "OversightScript"

    # Class Variables - reasonable defaults
    HIDDEN_KEY_FIELD = "_key"
    VISIBLE_KEY_FIELD = "key"
    HIDDEN_MVKEY_FIELD = (
        "__mv_key"  # per splunk serialization format ("__mv" + fieldname)
    )
    VISIBLE_MVKEY_FIELD = "mv_key"
    LAST_INVENTORIED_FIELD = "last_inventoried"
    FIRST_INVENTORIED_FIELD = "first_inventoried"
    AGGREGATED_COLLECTION_NAME = "hosts_collection"
    MODINPUT_KIND = "oversight"  # name of modular input definition in inputs.conf.spec
    EXPIRED_FIELD = "expired"  # "false" = not expired, otherwise date marked as expired

    def __init__(self):
        self.run_id = str(int(time.time()))
        splunkhome = self.get_splunkhome_env()
        log.Logs.set_context(
            directory=os.path.join(splunkhome, "var", "log", "splunk"),
            namespace=self.APP_NAME,
        )
        log.Logs().set_level("INFO")
        self.logger = log.Logs().get_logger(self.SCRIPT_NAME)
        self.logger.info(
            "run_id={} script={} status=initializing".format(
                self.run_id, self.SCRIPT_NAME
            )
        )
        self.write_cache = {}  # dict of lists; write buffer
        self.params = {}
        self.app_settings = {}
        self.aggregation_cache = {}  # local copy of kvstore data
        self.source_name = "None"

    def setup(self, service, app_settings):
        """perform actions which require splunklib.client.service, which is not available during __init__()
        for alert actions per Splunk docs"""
        self.logger.debug(
            "run_id={} script={} starting setup".format(self.run_id, self.SCRIPT_NAME)
        )
        if not service:
            self.logger.error(
                "run_id={} script={} status=fail reason=no valid splunklib.client.service received for setup()".format(
                    self.run_id, self.SCRIPT_NAME
                )
            )
            raise ValueError(
                "setup failed, no valid splunklib.client.service received, aborting."
            )
        service.namespace = self.SERVICE_CONTEXT
        self.service = service
        self.logger.debug(
            "run_id={} script={} getting kvstore max batch".format(
                self.run_id, self.SCRIPT_NAME
            )
        )
        try:
            self.kvstore_max_batch = int(
                self.service.confs["limits"]["kvstore"]["max_documents_per_batch_save"]
            )
        except:
            self.kvstore_max_batch = 1000

        self.VISIBLE_KEY_FIELD = app_settings["additional_parameters"][
            "primary_id_field"
        ]
        self.VISIBLE_MVKEY_FIELD = app_settings["additional_parameters"][
            "primary_mv_id_field"
        ]
        self.LAST_INVENTORIED_FIELD = app_settings["additional_parameters"][
            "last_inventoried_fieldname"
        ]
        self.FIRST_INVENTORIED_FIELD = app_settings["additional_parameters"][
            "first_inventoried_fieldname"
        ]
        self.AGGREGATED_LOOKUP_NAME = app_settings["additional_parameters"][
            "aggregated_lookup_name"
        ]
        self.AGGREGATED_COLLECTION_NAME = app_settings["additional_parameters"].get(
            "aggregated_collection_name"
        )

        # optional settings
        self.EXPIRATION_EXPRESSION = app_settings["additional_parameters"].get(
            "expiration_expression"
        )

    def get_splunkhome_env(self):
        """modified from solnlib.splunkenv::_splunk_home()"""
        return os.path.normpath(os.environ.get("SPLUNK_HOME", "/opt/splunk"))

    def read_app_settings(self, token, stanza="all"):
        """read custom conf file with app settings written
        @param token - string of session key
        @param obj - the script class caller
        @returns - dict of settings
        """

        # Retreive App Settings
        cfm = conf_manager.ConfManager(token, self.APP_NAME)
        try:
            app_settings_file = cfm.get_conf(self.APP_SETTINGS_FILENAME)

            if stanza != "all":
                settings = app_settings_file.get(stanza, only_current_app=True)
            else:
                settings = app_settings_file.get_all()

        except conf_manager.ConfManagerException:
            self.logger.error(
                "Unable to open app settings file:{} using token namespace:{} please re-run app Setup".format(
                    self.APP_SETTINGS_FILENAME, self.APP_NAME
                )
            )
        self.logger.debug(
            "run_id={} script={} method=read_app_settings status=exited".format(
                self.run_id, self.SCRIPT_NAME
            )
        )
        return settings

    def normalize_global_settings(self, settings):
        """normalize global app-wide settings
        @param settings: dict of custom conf stanza kv pairs
        @returns         dict, normalized and validated

        """
        self.logger.debug(
            "run_id={} starting normalize_global_settings".format(self.run_id)
        )

        settings[settings["asset_groups"]["asset_group_1_name"]] = int(
            settings["asset_groups"]["asset_group_1_max_age"]
        )

        if settings["asset_groups"].get("asset_group_2_name"):
            settings[settings["asset_groups"]["asset_group_2_name"]] = int(
                settings["asset_groups"]["asset_group_2_max_age"]
            )

        if settings["asset_groups"].get("asset_group_3_name"):
            settings[settings["asset_groups"]["asset_group_3_name"]] = int(
                settings["asset_groups"]["asset_group_3_max_age"]
            )

        if not settings["additional_parameters"].get("last_inventoried_fieldname"):
            raise MissingAppSetting(
                "run_id={} Please configure last_inventoried_fieldname in App Settings".format(
                    self.run_id
                )
            )

        if not settings["additional_parameters"].get("time_format"):
            raise MissingAppSetting(
                "run_id={} Please configure time_format in App Settings".format(
                    self.run_id
                )
            )

        return settings

    def convert_timestring_to_epoch(self, timestring, timeformat):
        """convert timesting to epoch using timeformat"""
        if not timestring or not timeformat:
            return None

        try:
            output = datetime.strptime(timestring, timeformat)
        except ValueError as error:
            self.logger.error(
                'run_id={} script={} method=convert_timestring_to_epoch status="invalid event with incorrect time format" value={} does not match format_string={} error={}'.format(
                    self.run_id,
                    self.SCRIPT_NAME,
                    timestring,
                    timeformat,
                    str(error),
                )
            )
            output = None
        return output

    def get_collection(self, conf_type):
        """return sdk collection object for the knowledge object type specified

        @param conf_type:    string, one of savedsearches, transforms, macros, or collections
        @returns             either splunklib.client.ConfigurationFile, splunklib.client.KVstoreCollections, or
                               splunklib.client.SavedSearches collection"""

        if conf_type == "savedsearches":
            return self.service.saved_searches
        elif conf_type == "transforms":
            return self.service.confs["transforms"]
        elif conf_type == "macros":
            return self.service.confs["macros"]
        elif conf_type == "collections":
            return self.service.kvstore
        raise ValueError(
            "getPathSegment input=%s not savedsearches, transforms, or macros"
            % str(conf_type)
        )

    def write_conf(self, conf_type, name, args):
        """write a knowledge object configuration to disk.
        owner=nobody for kvstore access fyi.
        wrapper for post() to ensure that name is included or not included as required

        @param conf_type:   string, splunk knowledge object type to write
        @param name:        string, name of splunk knowledge object
        @param args:        dict, arguments to write
        @returns            None
        """
        # path = get_uri_path(conf_type)
        collection = self.get_collection(conf_type)

        if name not in collection:
            collection.create(name, **args)

        else:
            collection[name].update(**args)

    @log_enter_exit()
    def write_macro(self, name, definition):
        """wrapper for write_conf used when the args are in string form,
        and not a dict, like macros.
        @param name:        string, name of splunk knowledge object to write
        @param definition:  string, representing the macro definition
        @returns            None
        """

        args = {"definition": definition}
        self.write_conf("macros", name, args)

    def get_kvstore_records(self, collection_name):
        try:
            cache = self.service.kvstore[collection_name].data.query()
        except KeyError as error:
            self.logger.critical(
                "run_id={} Unable to examine kvstore={} for expiry job, error={} skipping data source.".format(
                    self.run_id, str(collection_name), str(error)
                )
            )
        except Exception as error:
            self.logger.critical(
                "run_id={} Unable to examine kvstore={} for expiry job, error={} skipping data source.".format(
                    self.run_id, str(collection_name), str(error)
                )
            )
        return cache

    def get_dict_from_records(self, key_fieldname, cache):
        """
        >>> get_dict_from_records("key", [{"key":"1", "status":"OK"}, {"key":"2", "status":"fair"}])

        {"1": {"key":"1", "status":"OK"}, "2": {"key":"2", "status":"fair"}}
        """
        output = {}
        for item in cache:
            key = item[key_fieldname]
            output[key] = item
        return output

    def get_cached_record(self, record_key):
        """perform a copy.deepcopy of record, so it can be assigned literally instead of by reference
        return cached and reformatted data from the aggregation kvstore"""

        if record_key in self.aggregation_cache:
            return copy.deepcopy(self.aggregation_cache[record_key])
        else:
            return None

    def update_cached_record(self, record_key, **kwargs):
        """safe update to locally cached kvstore records"""

        if record_key in self.aggregation_cache:
            self.aggregation_cache[record_key].update(copy.deepcopy(kwargs))

    def write_kvstore_batch(self, collection_name, documents=None):
        """Write cached records in self.write_cache to kvstore
        NOTE: documents overwrite the previous document completely, not just the fields specified
        see https://docs.splunk.com/DocumentationStatic/PythonSDK/1.6.16/client.html#splunklib.client.KVStoreCollectionData"""

        self.logger.debug(
            "run_id={} input={} method=write_kvstore_batch status=enter write_catch_size={} collection_name={}".format(
                self.run_id,
                self.source_name,
                str(len(self.write_cache[collection_name])),
                str(collection_name),
            )
        )
        try:
            if not documents:
                self.service.kvstore[collection_name].data.batch_save(
                    *self.write_cache[collection_name]
                )
                self.write_cache[collection_name] = []
            else:
                self.service.kvstore[collection_name].data.batch_save(*documents)

        except HTTPError as error:
            self.logger.error(
                'run_id={} input={} error={} status="ERROR writing cache to={}"'.format(
                    self.run_id,
                    self.source_name,
                    str(error),
                    collection_name,
                )
            )
            raise ValueError(
                'run_id={} input={} status="ERROR writing cached records:{}"'.format(
                    self.run_id, self.source_name, str(error)
                )
            )
        self.logger.debug(
            "run_id={} input={} method=write_kvstore_batch status=exit write_cache_size={}".format(
                self.run_id,
                self.source_name,
                str(len(self.write_cache[collection_name])),
            )
        )

    def handle_cached_write(self, collection_name, records=None, force=False):
        """implement kvstore batch saving to improve efficiency.
        If records is None, consider it a request to flush and write the current cache, no matter the size.

        @param records:         list of dicts, dict, or None; the record(s) to be written
        @param collection_name: string, name of kvstore to cache and write to
        @param force:           bool, if True, must write all.  Implicit if records=None.
        """
        if (
            collection_name not in self.write_cache
            or self.write_cache[collection_name] is None
        ):
            self.write_cache[collection_name] = []

        if not records:
            force = True

        if records is None and len(self.write_cache[collection_name]) == 0:
            return

        if (
            records is None
            and len(self.write_cache[collection_name]) > self.kvstore_max_batch
        ):
            ## cached too much data previously, whoops!
            overflow = []
            overflow_count = (
                len(self.write_cache[collection_name]) - self.kvstore_max_batch
            )

            while overflow_count > 0:
                overflow.append(self.write_cache[collection_name].pop(-1))
                overflow_count -= 1
                time.sleep(0.01)
            self.write_kvstore_batch(collection_name)
            if len(overflow) > 0:
                self.write_cache[collection_name] = copy.deepcopy(overflow)
                self.write_kvstore_batch(collection_name)

        elif (
            records is None
            and len(self.write_cache[collection_name]) <= self.kvstore_max_batch
            and force
        ):
            ## flush cache
            self.write_kvstore_batch(collection_name)

        elif records:

            # first add the record into the cache

            if isinstance(records, list):
                self.write_cache[collection_name].extend(copy.deepcopy(records))
                self.logger.debug(
                    "run_id={} script={} input={} method=handle_cached_write extended records into write_cache".format(
                        self.run_id, self.SCRIPT_NAME, self.source_name
                    )
                )
                records = None

            elif isinstance(records, dict):
                self.write_cache[collection_name].append(
                    copy.deepcopy(json.dumps(records))
                )
                records = None
                self.logger.debug(
                    "run_id={} script={} input={} method=handle_cached_write appending records into write_cache".format(
                        self.run_id, self.SCRIPT_NAME, self.source_name
                    )
                )
            elif isinstance(records, str):
                self.write_cache[collection_name].append(copy.deepcopy(records))
                records = None
                self.logger.debug(
                    "run_id={} script={} input={} method=handle_cached_write appending records into write_cache".format(
                        self.run_id, self.SCRIPT_NAME, self.source_name
                    )
                )

            elif records:
                self.logger.warning(
                    "run_id={} script={} input={} method=handle_cached_write records={} are invalid, not caching; should be dict or list".format(
                        self.run_id, self.SCRIPT_NAME, self.source_name, str(records)
                    )
                )

            ## recursive call
            self.handle_cached_write(collection_name, force=force)
        self.logger.debug(
            "run_id={} script={} input={} method=handle_write_cache status=exit existing_cache_size={}".format(
                self.run_id,
                self.SCRIPT_NAME,
                self.source_name,
                str(len(self.write_cache[collection_name])),
            )
        )

    def get_collection_names_to_purge(self, event):
        """
        Examine the host_row record and return a list of data source names which are present.  These source names will subsequently be
        used to delete the associated records in a later method.

        EX:  host_record: {last_inventoried: 1999-01-01, bigfix_last_inventoried: null, forescout_last_inventoried} => [forescout_collection]

        @param event:       dict, the existing kvstore record
        @returns            list of strings
        """

        fields = list(event)

        data_sources = [
            x
            for x in fields
            if self.LAST_INVENTORIED_FIELD in x
            if x != self.LAST_INVENTORIED_FIELD
        ]
        data_sources = [
            x.replace(
                "_{}".format(self.LAST_INVENTORIED_FIELD),
                "_collection",
            )
            for x in data_sources
        ]
        return data_sources

    @log_enter_exit()
    def get_fieldnames_to_purge(self, event):
        """list all fields that contain but are not self.LAST_INVENTORIED_FIELDNAME"""
        fields = list(event)
        filtered_list = [
            x
            for x in fields
            if self.LAST_INVENTORIED_FIELD in x and x != self.LAST_INVENTORIED_FIELD
        ]
        return filtered_list

    @log_enter_exit()
    def expire_all_records_for_key(self, event, purge_mode=False):
        """
        look at every _last_inventoried data source and mark expired those component data source records.
        However the record updates are now written now but cached.
        EX: bigfix_last_inventoried is not null for our host_row, so mark expired host from bigfix lookup.

        @param event:    dict, the existing kvstore record
        """

        host_key = event.get(self.VISIBLE_KEY_FIELD)
        primary_key = event.get(self.HIDDEN_KEY_FIELD)
        data_sources = self.get_collection_names_to_purge(event)

        for source in data_sources:

            try:
                # make sure we can connect to the kvstore
                self.collection_svc = self.service.kvstore[source]
            except KeyError as error:
                self.logger.warning(
                    "run_id={} method=expire_all_records_for_key Unable to examine kvstore={} for expiry job, error={} skipping data source.".format(
                        self.run_id, str(source), str(error)
                    )
                )
                continue
            except binding.HTTPError as error:
                self.logger.warning(
                    "run_id={} method=expire_all_records_for_key Unable to read kvstore={} for expiry job, error={} skipping data source.".format(
                        self.run_id, str(source), str(error)
                    )
                )
                continue
            except Exception as error:
                self.logger.warning(
                    "run_id={} method=expire_all_records_for_key Unable to examine kvstore={} for expiry job, error={} skipping data source.".format(
                        self.run_id, str(source), str(error)
                    )
                )
                continue

            readable_key = host_key or primary_key
            self.logger.info(
                "run_id={} method=expire_all_records_for_key  expiring id={} from source={}".format(
                    self.run_id, str(readable_key), str(source)
                )
            )
            if purge_mode and primary_key:
                try:
                    self.collection_svc.data.delete_by_id(primary_key)
                except binding.HTTPError as error:
                    self.logger.warning(
                        "run_id={} method=expire_all_records_for_key Unable to delete from kvstore={} for expiry job, error={} key={} should be purged manually.".format(
                            self.run_id, str(source), str(error), primary_key
                        )
                    )
                    continue
            elif purge_mode and not primary_key:
                self.logger.warning(
                    "run_id={} method=expire_all_records_for_key Unable to purge key for event={}, _key not found for expiry job, error={} verify key={} does not exist and purge manually if needed.".format(
                        self.run_id, str(event), str(error), str(host_key)
                    )
                )
                continue

            else:
                query_key = json.dumps(
                    {
                        "_key": host_key,
                    }
                )
                # get the original record in the kvstore
                record = self.collection_svc.data.query(query=query_key)
                if record:
                    record = record[0]

                    # set expired = timestamp
                    record.update(
                        {
                            "expired": datetime.today().strftime(
                                self.app_settings["additional_parameters"][
                                    "time_format"
                                ]
                            )
                        }
                    )
                    self.logger.debug(
                        "run_id={} script={} method=expire_all_records_for_key status=updating record={}".format(
                            self.run_id, self.SCRIPT_NAME, str(record)
                        )
                    )

                    # append event to write_cache for the kvstore
                    if source in self.write_cache:
                        if isinstance(self.write_cache[source], list):
                            self.write_cache[source].append(record)

                        elif self.write_cache[source] is None:
                            self.write_cache[source] = []
                            self.write_cache[source].append(record)

                        else:
                            self.logger.warning(
                                "run_id={} script={} method=expire_all_records_for_key status=unable_to_cache_write key={}".format(
                                    self.run_id, self.SCRIPT_NAME, str(query_key)
                                )
                            )
                    else:
                        self.write_cache[source] = []
                        self.write_cache[source].append(record)
                else:
                    self.logger.warning(
                        "run_id={} method=expire_all_records_for_key Unable to delete record host_key={} from data_source={}".format(
                            self.run_id, str(host_key), str(source)
                        )
                    )


if __name__ == "main":
    pass
