# encoding = utf-8

import collections
import copy
import re

from six import iteritems
from solnlib import log
from splunklib.client import HTTPError

from oversight_utils import log_enter_exit, OversightScript

KNOWLEDGE_OBJECTS_WRITTEN = {
    "transforms": ["_lookup", "_lookup_all"],
    "collections": ["_collection"],
    "macros": [
        "_source",
        "_fields",
        "_source_filter",
        "_inventory_filter",
        "_enrichment_expression",
    ],
    "saved_searches": ["_hosts", "_data"],
}

SUPPORTED_GENERATING_COMMANDS = [
    "metadata",
    "loadjob",
    "inputcsv",
    "inputlookup",
    "dbinspect",
    "datamodel",
    "pivot",
    "tstats",
]


class OversightBuilder(OversightScript):
    """This class is responsible for generating the necessary Splunk Knowledge Objects for this modular input:
    * kvstore collection and transform
    * macros and savedsearch

    We expect it is only called once, or as edits to the input definition are made.
    """

    # match fieldname, strptime_fieldname, time_format
    # ie last_seen = strptime(_time, "%Y-%m-%d %H:%M")
    LAST_INVENTORIED_MACRO_FORMAT_PATTERN = re.compile(
        r"(\w*)\s*=\s*strftime\(\s*([^ ,]*)\s*,\s*\"([^\"]*)\"\)"
    )

    SCRIPT_NAME = "input_module_oversight"
    DEFAULT_ASSET_GROUP_NAME = "default"
    DEFAULT_MAX_AGE = "30"

    def __init__(self):
        """note that the Splunk service object is not available at __init__ time per Splunk docs"""
        super().__init__()
        self.default_savedsearch_args = {
            "alert.suppress": "0",
            "alert.track": "0",
            "dispatch.earliest_time": "-24h",
            "dispatch.latest_time": "now",
            "disabled": "0",
            "action.update_inventory": "0",
            "action.update_inventory.param.source_name": "",
        }
        self.alert_args = {
            "counttype": "number of events",
            "relation": "greater than",
            "quantity": "0",
            "enableSched": "1",
        }

    @log_enter_exit()
    def normalize_input_parameters(self, input, arguments):
        """parse input parameters and apply necessary normalization
        @param input    splunklib.modularinput.input_defintion InputDefinition
        @returns        dict, normalized input parameters
        """
        output = {}
        checkbox_fields = ["inventory_source", "replicate"]

        # ensure key exists for all input parameters, even if not defined for this input
        for arg in arguments:
            output.update({arg.name: None})

        # convert input in xml to dict
        for key, value in iteritems(input):
            if value and value != "":
                output.update({key: value})

        output["name"] = output["name"].split("oversight://")[-1].strip()
        output["name"] = (
            output["name"]
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .strip()
        )
        for field in checkbox_fields:
            if output[field] in ["false", "f", "False", 0, "0", ""]:
                output[field] = False
            elif output[field] in ["true", "t", "True", 1, "1"]:
                output[field] = True
            else:
                output[field] = None

        ## apply normalizations
        if (
            output.get("aggregation_fields")
            and output.get("aggregation_fields").strip()
        ):
            fields_list = output["aggregation_fields"].split(",")
            fields_list = [i.strip() for i in fields_list if i is not None]
            output["aggregation_fields"] = fields_list

        # field params should always be lists
        if output.get("source_fields") and "," in output.get("source_fields"):
            temp = output["source_fields"].split(",")
            output["source_fields"] = [i.strip(" ") for i in temp]

        elif output.get("source_fields"):
            output["source_fields"] = [output["source_fields"].strip()]

        else:
            output["source_fields"] = None

        if not output.get("asset_group"):
            output["asset_group"] = self.settings["default_asset_group_name"]

        if output.get("enrichment_fields") and "," in output.get("enrichment_fields"):
            temp = output["enrichment_fields"].split(",")
            output["enrichment_fields"] = [i.strip(" ") for i in temp]

        elif (
            output.get("enrichment_fields") and output.get("enrichment_fields").strip()
        ):
            output["enrichment_fields"] = [output["enrichment_fields"].strip()]

        # replace any '' values with None
        for key, value in iteritems(output):
            if value == "":
                output[key] = None

        return output

    @log_enter_exit()
    def build_lookup_fieldlist(self):
        """build a list of all fields that need to be included when writing the lookup and the savedsearch.

        @returns    list of strings or []
        """
        fields = []
        fields.append("_key")

        if self.params["id_field_rename"]:
            fields.append(self.params["id_field_rename"])
        else:
            fields.append(self.params["id_field"])

        fields.append(self.settings["last_inventoried_fieldname"])

        if self.params["source_fields"]:
            fields.extend(self.params["source_fields"])
            self.logger.debug(
                """run_id={} script={} input={} method=build_lookup_fieldlist status="extended inventory" fields={}""".format(
                    self.run_id, self.SCRIPT_NAME, self.params["name"], str(fields)
                )
            )

        if self.params["enrichment_fields"]:
            fields.extend(self.params["enrichment_fields"])
        if self.params["mv_id_field"]:
            fields.append(self.params["mv_id_field"])
        if self.params["aggregation_fields"]:
            fields.extend(self.params["aggregation_fields"])

        fields.append("expired")
        # make sure field_list is unique:
        fields = list(collections.OrderedDict.fromkeys(fields))
        return fields

    @log_enter_exit()
    def build_search_query(self, **kwargs):
        """return a string, consisting of the SPL query to produce lookup results
        @param **kwargs:    dict of the macros that have already been written to disk which are used to construct the query
        @returns            string, of a query based on the macros provided."""

        last_inventoried_fieldname = (
            kwargs.get("last_inventoried_fieldname") or "last_inventoried"
        )

        search_query = macro_string(kwargs.get("source_expression_macro_name")) + " | "
        if kwargs.get("supported_generating_command") == True:
            search_query = "| {} | {} | ".format(
                macro_string(kwargs.get("source_expression_macro_name")),
                macro_string("eval_{}".format(last_inventoried_fieldname)),
            )
        else:
            search_query = "{} | {} | ".format(
                macro_string(kwargs.get("source_expression_macro_name")),
                macro_string("eval_{}".format(last_inventoried_fieldname)),
            )

        if kwargs.get("enrichment_expression_macro_name"):
            search_query += (
                macro_string(kwargs.get("enrichment_expression_macro_name")) + " | "
            )

        if kwargs.get("id_field_rename"):
            search_query += " | ".join(
                [
                    macro_string(
                        "set_id",
                        kwargs.get("original_id_field"),
                        kwargs.get("id_field_rename"),
                    ),
                    macro_string("sort_dedup", kwargs.get("id_field_rename")),
                    macro_string("set_key", kwargs.get("id_field_rename")),
                ]
            )
        else:
            search_query += " | ".join(
                [
                    macro_string("sort_dedup", kwargs.get("original_id_field")),
                    macro_string("set_key", kwargs.get("original_id_field")),
                ]
            )

        if kwargs.get("source_filter_macro_name"):
            search_query += " | " + macro_string(kwargs.get("source_filter_macro_name"))

        search_query += " | " + macro_string("set_not_expired")

        # Ensure a space is prepended to the table macro line to avoid a splunk bug
        # otherwise | table ... will be evaluted as | ifields + at run time
        search_query += " | table " + macro_string(kwargs.get("fields_macro_name"))
        search_query += " | " + macro_string(
            "outputlookup", kwargs.get("transforms_name")
        )

        if kwargs.get("inventory_filter_macro_name"):
            search_query += " | " + macro_string(
                kwargs.get("inventory_filter_macro_name")
            )

        return search_query

    @log_enter_exit()
    def build_search_args(self):
        """update search kwargs for saved search
        @returns    dict, of savedsearch settings"""

        if self.params["inventory_source"]:
            description = "Hosts from {}".format(self.params["name"])
        else:
            description = "Data from {}".format(self.params["name"])

        args = copy.deepcopy(self.default_savedsearch_args)
        args["description"] = description
        args["cron_schedule"] = self.params["cron"]
        args["is_scheduled"] = "1"

        if self.params["inventory_source"]:
            if "action.update_inventory.param_last_checkin_field" in args:
                del args["action.update_inventory.param_last_checkin_field"]

            args.update(
                {
                    "action.update_inventory": "1",
                    "action.update_inventory.param.source_name": self.params["name"],
                    "actions": "update_inventory",
                }
            )

        return args

    def build_search_name(self):
        """return formatted search name based on inventory_source and name
        @returns    string"""

        if self.params["inventory_source"]:
            return "{}_hosts".format(self.params["name"])
        else:
            return "{}_data".format(self.params["name"])

    def get_aggregation_fieldlist(self):
        """populate list of strings for the fields that need to be ensured are present in aggregation lookup transform
        These fields are those which this data source is adding (ie sourcename_last_inventoried),
        any fields listed in aggregated_fields, and also the general fields from app settings, which we don't have
        any other place to add them in.

        @returns     list of strings comma seperated.

        """
        necessary_fields = [
            self.settings["primary_id_field"],
            self.settings["primary_mv_id_field"],
            self.settings["last_inventoried_fieldname"],
            self.settings["first_inventoried_fieldname"],
        ]

        if self.params.get("inventory_source"):
            necessary_fields.append(
                "{}_{}".format(
                    self.params["name"], self.settings["last_inventoried_fieldname"]
                )
            )
            if self.params["aggregation_fields"]:
                necessary_fields.extend(self.params["aggregation_fields"])

        return necessary_fields

    @log_enter_exit()
    def calculate_aggregation_transform_fieldlist(
        self, necessary_fields, existing_fields
    ):
        """append any missing necessary_fields to existing_fields

        @param necessary_fields - list of strings - calculated by OversightBuilder
        @param existing_fields - list of strings - current fields listed in transform config for aggregation lookup
        @return (bool, list of strings)
        """
        if not necessary_fields:
            return None

        if existing_fields:
            original_fields = copy.deepcopy(existing_fields)
        else:
            original_fields = None

        for field in necessary_fields:
            if field not in existing_fields:
                existing_fields += ", {}".format(field)

        # strip any leading commas, if exisint_fields is null
        existing_fields = existing_fields.strip(" ,")

        if original_fields == existing_fields:
            return None
        else:
            return existing_fields

    @log_enter_exit("adding any missing fields to aggregation lookup")
    def update_aggregation_transform(self, new_fields_list):
        """examine the transform lookup definition for the aggregation lookup
        add name_last_inventoried
        add settings["aggregation_fields"]
        do a create if transform doesnt already exist
        only do a POST if data has changed

        @param necessary_fields:    list of string
        @returns                    None

        """
        if not new_fields_list:
            return

        aggregation_transform = self.service.confs["transforms"][
            self.settings["aggregated_lookup_name"]
        ]
        aggregation_transform_all = self.service.confs["transforms"][
            "{}_all".format(self.settings["aggregated_lookup_name"])
        ]

        self.logger.debug(
            "run_id={} input={} script={} method=update_aggregation_transform status=executing type=transform name={} args={}".format(
                self.run_id,
                self.params["name"],
                self.SCRIPT_NAME,
                aggregation_transform.name,
                str(new_fields_list),
            )
        )
        aggregation_transform.update(fields_list=new_fields_list)

        aggregation_transform_all.update(fields_list=new_fields_list)

    def normalize_global_settings(self, app_settings):
        """normalize app-wide global settings specified

        @returns    dict

        """
        self.logger.debug(
            """run_id={} script={} method=normalize_global_settings status=entered args={}""".format(
                self.run_id, self.SCRIPT_NAME, str(app_settings)
            )
        )
        settings = {}
        if "asset_groups" in app_settings:
            asset_group1 = (
                app_settings["asset_groups"].get("asset_group_1_name")
                or self.DEFAULT_ASSET_GROUP_NAME
            )
            asset_group2 = app_settings["asset_groups"].get("asset_group_2_name")
            asset_group3 = app_settings["asset_groups"].get("asset_group_3_name")

            if asset_group1 and asset_group1 != "":
                settings[asset_group1] = (
                    app_settings["asset_groups"].get("asset_group_1_max_age")
                    or self.DEFAULT_MAX_AGE
                )
            if asset_group2 and asset_group2 != "":
                settings[asset_group2] = app_settings["asset_groups"].get(
                    "asset_group_2_max_age"
                )
            if asset_group3 and asset_group3 != "":
                settings[asset_group3] = app_settings["asset_groups"].get(
                    "asset_group_3_max_age"
                )
        settings["default_asset_group_name"] = asset_group1
        settings["last_inventoried_fieldname"] = app_settings["additional_parameters"][
            "last_inventoried_fieldname"
        ]
        settings["first_inventoried_fieldname"] = app_settings["additional_parameters"][
            "first_inventoried_fieldname"
        ]
        settings["time_format"] = app_settings["additional_parameters"]["time_format"]
        settings["aggregated_lookup_name"] = app_settings["additional_parameters"][
            "aggregated_lookup_name"
        ]
        settings["aggregated_collection_name"] = app_settings["additional_parameters"][
            "aggregated_collection_name"
        ]
        settings["primary_id_field"] = app_settings["additional_parameters"][
            "primary_id_field"
        ]
        settings["primary_mv_id_field"] = app_settings["additional_parameters"][
            "primary_mv_id_field"
        ]
        settings["loglevel"] = app_settings["logging"]["loglevel"]
        self.logger.debug(
            "run_id={} script={} method=normalize_global_settings status=exited return={}".format(
                self.run_id, self.SCRIPT_NAME, str(settings)
            )
        )
        return settings

    @log_enter_exit()
    def update_last_inventoried_macro_definition(
        self, time_format, last_inventoried_fieldname, existing_definition
    ):
        """Return defintion string if `eval_last_inventoried` macro doesnt already use time_format, to account for
        possible user changes to this setting.  Keep in mind there could be previous splunk SPL statements before this eval statement.

        @param time_format                - string used to convert time string to datetime, specified in app settings
        @param last_inventoried_fieldname - string, self.LAST_INVENTORIED_FIELDNAME
        @ param existing_definition       - updated definition string for macro, or None
        """

        definition = None
        if existing_definition:
            matches = re.findall(
                self.LAST_INVENTORIED_MACRO_FORMAT_PATTERN, str(existing_definition)
            )
            if matches:
                (
                    old_last_inventoried_fieldname,
                    old_time_fieldname,
                    old_format,
                ) = matches[-1]

                if (
                    old_format.strip('"') != time_format
                    or old_last_inventoried_fieldname.strip('"')
                    != last_inventoried_fieldname
                ):

                    repl = '{} = strftime({}, "{}")'.format(
                        last_inventoried_fieldname, old_time_fieldname, time_format
                    )
                    definition = re.sub(
                        self.LAST_INVENTORIED_MACRO_FORMAT_PATTERN,
                        repl,
                        str(existing_definition),
                    )

                else:
                    # update not needed
                    pass
            else:
                self.logger.warning(
                    "run_id={} script={} input={} method=update_last_inventoried_macro_definition overwriting `eval_last_inventoried macro, unable to match pattern {} against existing defintion {}".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        self.params["name"],
                        str(self.LAST_INVENTORIED_MACRO_FORMAT_PATTERN),
                        str(existing_definition),
                    )
                )
                definition = 'eval {} = strftime(_time, "{}")'.format(
                    last_inventoried_fieldname, time_format
                )
        else:
            self.logger.debug(
                'run_id={} script={} input={} method=update_last_inventoried_macro_definition status="no existing definition"'.format(
                    self.run_id, self.SCRIPT_NAME, self.name
                )
            )
            definition = 'eval {} = strftime(_time, "{}")'.format(
                last_inventoried_fieldname, time_format
            )

        return definition

    @log_enter_exit()
    def write_savedsearch_definition(
        self, saved_search_name, saved_search_args, search_query
    ):
        """calculate savedsearch parameters
        either update existing savedsearch, or create a new one if it does not yet exist
        """
        execution_error = False

        # don't create new if search already exists, just update
        searches = self.service.saved_searches

        if saved_search_name in searches:

            saved_search_args["search"] = search_query
            try:

                searches[saved_search_name].update(**saved_search_args).refresh()

            except HTTPError as error:
                execution_error = True
                self.logger.error(
                    'run_id={} input={} status="error updating savedsearch" type=savedsearch update args={} details={}'.format(
                        self.run_id, self.name, str(saved_search_args), str(error)
                    )
                )
        else:
            try:

                searches.create(saved_search_name, search_query, **saved_search_args)

            except HTTPError as error:
                execution_error = True
                self.logger.error(
                    'run_id={} input={} status="error creating savedsearch" type=savedsearch create args={} details={}'.format(
                        self.run_id, self.name, str(saved_search_args), str(error)
                    )
                )
        return execution_error

    @log_enter_exit()
    def update_aggregation_transform_name(self, transform_name):
        """if the ta_oversight_settings["additional_parameters]["aggregated_lookup_name]
        doesn't exist; create it"""
        name = copy.deepcopy(transform_name)
        try:
            existing_args = self.service.confs["transforms"]["hosts_lookup"].content()
        except KeyError:
            existing_args = {}
        args = {
            "external_type": "kvstore",
            "collection": self.settings["aggregated_collection_name"],
            "fields_list": existing_args.get("fields_list"),
        }
        if "filter" in existing_args:
            args["filter"] = existing_args["filter"]
        self.logger.debug(
            "run_id={} script={} input={} method=update_aggregation_transform_name status=writing type=transform name={} args={}".format(
                self.run_id, self.SCRIPT_NAME, self.name, str(name), str(args)
            )
        )
        self.write_conf("transforms", name, args)
        # write _all transform unfiltered
        name = "{}_all".format(name)
        del args["filter"]
        self.logger.debug(
            "run_id={} script={} input={} method=update_aggregation_transform_name status=writing type=transform name={} args={}".format(
                self.run_id, self.SCRIPT_NAME, self.name, str(name), str(args)
            )
        )
        self.write_conf("transforms", name, args)

    def normalize_source_expression(self, definition):
        """strip any leading '|' from definition.  It will need to be prepended to the search if
        its a generating command besides 'search'"""

        if definition is None:
            return definition

        LEADING_PIPE = r"\s*\|\s*"

        if re.match(LEADING_PIPE, definition):
            # only replace first occurence
            definition = definition.replace("|", "", 1)
            definition = definition.strip()
        return definition


def validate_input(self, definition):
    """This validation occurs when the user clicks save after editing or creating new input settings.
    An error message will display at the top of the input settings form if validation fails with the error indicated

    @definition:    modular input definition
    """

    asset_group = definition.parameters.get("asset_group", None)
    source_expression = definition.parameters.get("source_expression", None)
    source_fields = definition.parameters.get("source_fields", None)
    id_field = definition.parameters.get("id_field", None)
    id_field_rename = definition.parameters.get("id_field_rename", None)
    mv_id_field = definition.parameters.get("mv_id_field", None)
    enrichment_expression = definition.parameters.get("enrichment_expression", None)
    enrichment_fields = definition.parameters.get("enrichment_fields", None)
    source_filter = definition.parameters.get("source_filter", None)
    inventory_filter = definition.parameters.get("inventory_filter", None)
    inventory_source = definition.parameters.get("inventory_source", None)
    aggregation_fields = definition.parameters.get("aggregation_fields", None)
    replicate = definition.parameters.get("replicate", None)
    cron = definition.parameters.get("cron", None)

    if inventory_source == "false" or inventory_source in ["f", "0", 0, None, ""]:
        inventory_source = False
    else:
        inventory_source = True

    if not id_field:
        raise ValueError("Unique ID Field is a required parameter")

    if not source_expression:
        raise ValueError("Source Expression is a required parameter")

    if "|" in source_expression[-3:]:
        raise ValueError("remove trailing '|' from Source Expression")

    if inventory_filter and not inventory_source:
        raise ValueError(
            "Inventory Filter should not be specified if not Inventory Source"
        )

    if aggregation_fields and not inventory_source:
        raise ValueError(
            "Aggregation Fields should not be specified if not Inventory Source"
        )

    if enrichment_expression:
        if "|" in enrichment_expression[0:3] or "|" in enrichment_expression[-3:]:
            raise ValueError(
                "Remove trailing or leading '|' from Enrichment Expresison"
            )

    if enrichment_expression and not enrichment_fields:
        raise ValueError(
            "Enrichment Fields should be present when Enrichment Expression is specified"
        )

    if not cron:
        raise ValueError("Cron parameter is required")

    if len(cron.split(" ")) != 5:
        raise ValueError(
            "Cron parameter should have 5 elements seperated by space, ie: 0 23 * * *"
        )


def macro_string(macro_name, *macro_args):
    """
    Formats macros for Splunk query by wrapping with backticks
    and putting =arguments in parenthesis
    assert(macro_string('test') == "`test`")
    assert(macro_string('test', "1")  == "`test(1)`")
    assert(macro_string('test', "1", "2") == "`test(1,2)`")

    @param instring: macro name
    @param args:     args that go to macro
    @returns         string of formatted macro
    """
    outstring = "`" + macro_name
    if macro_args:
        outstring += "("
        outstring += ",".join([i for i in macro_args if i is not None])
        outstring += ")"
    outstring += "`"
    return outstring


def stream_events(self, inputs, ew):
    """main method that executes when input parameter settings are saved in the UI and on interval
    (or splunkd restart if interval=-1)

    @param inputs:  Splunk InputDefinition
    @param ew:      splunk event writer
    @returns        None

    """
    if not (self.service):
        raise ValueError(
            "stream_events service object is null, this should not happen."
        )

    for input_name, input in iteritems(inputs.__dict__["inputs"]):
        input["name"] = input_name
        builder = OversightBuilder()
        app_settings = builder.read_app_settings(self.service.token)
        builder.logger.debug(
            "run_id={} done reading app_settings".format(builder.run_id)
        )

        builder.settings = builder.normalize_global_settings(app_settings)
        builder.logger.debug(
            "run_id={} done normalizing global settings".format(builder.run_id)
        )
        builder.setup(self.service, app_settings)
        builder.logger.debug(
            "run_id={} app global settings={}".format(
                builder.run_id, str(builder.settings)
            )
        )
        arguments = self.get_scheme().arguments
        builder.logger.debug(
            "run_id={} got scheme arguments={}".format(builder.run_id, str(arguments))
        )
        builder.params = builder.normalize_input_parameters(input, arguments)
        builder.logger.debug(
            "run_id={} normalized input parameters={}".format(
                builder.run_id, str(builder.params)
            )
        )
        builder.name = builder.params["name"]
        if builder.settings.get("loglevel"):
            log.Logs().set_level(builder.settings["loglevel"])

        builder.logger.info(
            'run_id={} input={} status="setup completed", args={} connected={}'.format(
                builder.run_id,
                builder.name,
                str(builder.params),
                "true" if builder.service else "false",
            )
        )

        ## create aggregation collection if needed
        if (
            builder.settings["aggregated_collection_name"]
            not in builder.service.kvstore
        ):
            builder.service.kvstore.create(
                builder.settings["aggregated_collection_name"]
            )
            builder.logger.debug(
                "run_id={} input={} creating kvstore={}".format(
                    builder.run_id,
                    builder.params["name"],
                    builder.settings["aggregated_collection_name"],
                )
            )

        ## create aggregation lookup if needed or rename
        target_transform_name = builder.settings["aggregated_lookup_name"]
        if target_transform_name not in builder.service.confs["transforms"]:
            builder.update_aggregation_transform_name(target_transform_name)

        ## create or update `eval_last_inventoried` if needed

        try:
            eval_last_inventoried_macro = builder.service.confs["macros"][
                "eval_last_inventoried"
            ]
        except KeyError:
            eval_last_inventoried_macro = None
            builder.logger.debug(
                'run_id={} input={} status="could not get last inventoried macro"'.format(
                    builder.run_id, builder.name
                )
            )
        existing_definition = (
            eval_last_inventoried_macro.content().definition
            if eval_last_inventoried_macro
            else None
        )
        builder.logger.debug(
            'run_id={} input={} status="got last_inventoried macro definition"'.format(
                builder.run_id, builder.name
            )
        )
        definition_update = builder.update_last_inventoried_macro_definition(
            builder.settings["time_format"],
            builder.settings["last_inventoried_fieldname"],
            existing_definition,
        )
        if definition_update:
            new_macro_name = "eval_{}".format(
                builder.settings["last_inventoried_fieldname"]
            )
            builder.logger.debug(
                'run_id={} input={} status="writing updated last_inventoried macro definition"'.format(
                    builder.run_id, builder.name
                )
            )
            builder.write_macro(new_macro_name, definition_update)
        else:
            builder.logger.debug(
                'run_id={} input={} status="no update to last_inventoried macro needed"'.format(
                    builder.run_id, builder.name
                )
            )

        ## create macros
        source_expression_macro_name = None
        enrichment_expression_macro_name = None
        source_filter_macro_name = None
        inventory_filter_macro_name = None
        fields_macro_name = None
        transforms_name = None
        kv_lookup_fields = []

        ## Create kvstore or update if already exists
        collection_args = {}
        collection_name = builder.name + "_collection"
        transforms_name = builder.name + "_lookup"

        if builder.params["replicate"]:
            collection_args["replicate"] = "true"

        builder.logger.debug(
            "run_id={} input={} collection={} replicate={}".format(
                builder.run_id,
                builder.name,
                collection_name,
                "true" if collection_args.get("replicate") else "false",
            )
        )
        if collection_name in builder.service.kvstore:
            builder.service.kvstore[collection_name].update(**collection_args)
            builder.logger.debug(
                "run_id={} input={} collection={} status=updated, args={}".format(
                    builder.run_id, builder.name, collection_name, str(collection_args)
                )
            )
        else:
            builder.service.kvstore.create(name=collection_name, **collection_args)
            builder.logger.debug(
                "run_id={} input={} collection={} status=created, args={}".format(
                    builder.run_id, builder.name, collection_name, str(collection_args)
                )
            )

        kv_lookup_fields = builder.build_lookup_fieldlist()
        builder.logger.debug('run_id={} input={} status="building transform fieldlist"')

        ## Write lookup transforms
        transforms_args = {
            "external_type": ["kvstore"],
            "collection": [collection_name],
            "case_sensitive_match": ["false"],
            "fields_list": ",".join(kv_lookup_fields),
        }
        if builder.params["inventory_source"]:
            transforms_args.update({"filter": "expired=false"})

        builder.logger.debug(
            "run_id={} input={} writing type=transform name={} args={}".format(
                builder.run_id, builder.name, str(transforms_name), str(transforms_args)
            )
        )
        builder.write_conf("transforms", transforms_name, transforms_args)

        ## Write transform without filter, but only needed if inventory_source
        if builder.params["inventory_source"]:
            transforms_all_name = "{}_all".format(transforms_name)
            transforms_all_args = transforms_args
            del transforms_all_args["filter"]

            builder.logger.debug(
                "run_id={} input={} writing type=transform name={} args={}".format(
                    builder.run_id,
                    builder.name,
                    transforms_all_name,
                    str(transforms_all_args),
                )
            )
            builder.write_conf("transforms", transforms_all_name, transforms_all_args)

        ## Define and Write macros
        source_expression_macro_name = builder.name + "_source"
        source_definition = builder.normalize_source_expression(
            builder.params["source_expression"]
        )
        supported_generating_command = False
        if source_definition in SUPPORTED_GENERATING_COMMANDS:
            supported_generating_command = True

        builder.write_macro(source_expression_macro_name, source_definition)

        fields_macro_name = builder.name + "_fields"
        builder.write_macro(fields_macro_name, ",".join(kv_lookup_fields))

        if builder.params["enrichment_expression"]:
            enrichment_expression_macro_name = builder.name + "_enrichment_expression"
            builder.write_macro(
                enrichment_expression_macro_name,
                builder.params["enrichment_expression"],
            )

        if builder.params["source_filter"]:
            source_filter_macro_name = builder.name + "_source_filter"
            builder.write_macro(
                source_filter_macro_name, builder.params["source_filter"]
            )

        # evaluated after | outputlookup and passed to exlcude events from update_inventory
        if builder.params["inventory_filter"]:
            inventory_filter_macro_name = builder.name + "_inventory_filter"
            builder.write_macro(
                inventory_filter_macro_name, builder.params["inventory_filter"]
            )

        ## Build search query for saved search
        search_query = builder.build_search_query(
            source_expression_macro_name=source_expression_macro_name,
            enrichment_expression_macro_name=enrichment_expression_macro_name,
            original_id_field=builder.params["id_field"],
            id_field_rename=builder.params["id_field_rename"],
            source_filter_macro_name=source_filter_macro_name,
            inventory_filter_macro_name=inventory_filter_macro_name,
            fields_macro_name=fields_macro_name,
            transforms_name=transforms_name,
            last_inventoried_fieldname=builder.settings["last_inventoried_fieldname"],
            supported_generating_command=supported_generating_command,
        )
        saved_search_name = builder.build_search_name()
        saved_search_args = builder.build_search_args()

        builder.logger.debug(
            "run_id={} input={} writing type=savedsearch, name={} search={} args={}".format(
                builder.run_id,
                builder.name,
                saved_search_name,
                str(search_query),
                str(saved_search_args),
            )
        )
        savedsearch_write_error = builder.write_savedsearch_definition(
            saved_search_name, saved_search_args, search_query
        )

        if builder.params["inventory_source"]:
            """
            If the input is an inventory source, set the alert action to run
            when the savedsearch executes

            Also extend the fieldlist of the aggregation transforms if necessary
            """

            savedsearch_stanza = builder.service.confs["savedsearches"][
                saved_search_name
            ]
            savedsearch_stanza.submit(builder.alert_args)
            savedsearch_stanza.refresh()

            # get list of fields from this input which need to be aggregated
            aggregating_fields = builder.get_aggregation_fieldlist()

            aggregation_transform = builder.service.confs["transforms"][
                "{}".format(builder.settings["aggregated_lookup_name"])
            ]

            existing_fields = aggregation_transform.fields_list

            # calculate new fieldlist to write, if needed
            updated_fieldlist = builder.calculate_aggregation_transform_fieldlist(
                aggregating_fields, existing_fields
            )
            # write update fieldlist (if any) to confs['transforms']
            builder.logger.debug(
                "run_id={} input={} writing updated_field={} to aggregation transforms".format(
                    builder.run_id, builder.name, str(updated_fieldlist)
                )
            )
            builder.update_aggregation_transform(updated_fieldlist)

        if not savedsearch_write_error:
            builder.logger.info(
                "run_id={} input={} status=completed, args={}".format(
                    builder.run_id, builder.name, str(builder.params)
                )
            )
        else:
            builder.logger.info(
                'run_id={} input={} status="completed with error", args={}'.format(
                    builder.run_id, builder.name, str(builder.params)
                )
            )
