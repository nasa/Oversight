# encoding = utf-8

import os
import re
import time

import import_declare_test
import splunklib.client
from solnlib import conf_manager, log
from solnlib.utils import is_true
from splunktaucclib.rest_handler import admin_external

from input_module_oversight import KNOWLEDGE_OBJECTS_WRITTEN

__all__ = [
    "OversightInputExternalHandler",
]


class OversightInputExternalHandler(admin_external.AdminExternalHandler):

    SCRIPT_NAME = "oversight_settings"
    APP_SETTINGS_FILE = "ta_oversight_settings"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = splunklib.client.connect(
            token=self.handler._session_key, app=import_declare_test.ta_name
        )
        splunkhome = os.path.normpath(os.environ.get("SPLUNK_HOME", "/opt/splunk"))
        log.Logs.set_context(
            directory=os.path.join(splunkhome, "var", "log", "splunk"),
            namespace=import_declare_test.ta_name,
        )
        log.Logs().set_level("DEBUG")
        self.logger = log.Logs().get_logger(self.SCRIPT_NAME)
        self.run_id = str(int(time.time()))

        self.logger.info(
            "run_id={} script={} status=initializing namespace={}".format(
                self.run_id, self.SCRIPT_NAME, self.service.namespace
            )
        )

    @admin_external.build_conf_info
    def handleEdit(self, confInfo):
        disabled = self.payload.get("disabled")
        if disabled is None:
            self.edit_hook(
                session_key=self.getSessionKey(),
                config_name=self._get_name(),
                stanza_id=self.callerArgs.id,
                payload=self.payload,
            )
            return self.handler.update(
                self.callerArgs.id,
                self.payload,
            )
        elif is_true(disabled):

            inventory_saved_search_name = "{}_{}".format(self.callerArgs.id, "hosts")
            non_inventory_saved_search_name = "{}_{}".format(self.callerArgs.id, "data")
            saved_search_names = [i.name for i in self.service.saved_searches]

            # disable savedsearch
            if inventory_saved_search_name in self.service.saved_searches:
                self.logger.debug(
                    "run_id={} script={} action=disable target={}".format(
                        self.run_id, self.SCRIPT_NAME, str(inventory_saved_search_name)
                    )
                )
                self.service.saved_searches[inventory_saved_search_name].disable()

            elif non_inventory_saved_search_name in self.service.saved_searches:
                self.logger.debug(
                    "run_id={} script={} action=disable target={}".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        str(non_inventory_saved_search_name),
                    )
                )
                self.service.saved_searches[non_inventory_saved_search_name].disable()

            return self.handler.disable(self.callerArgs.id)

        else:
            # enable savedsearch
            saved_search_names = [i.name for i in self.service.saved_searches]
            inventory_saved_search_name = "{}_{}".format(self.callerArgs.id, "hosts")
            non_inventory_saved_search_name = "{}_{}".format(self.callerArgs.id, "data")

            if inventory_saved_search_name in self.service.saved_searches:
                self.logger.debug(
                    "run_id={} script={} action=enable target={}".format(
                        self.run_id, self.SCRIPT_NAME, str(inventory_saved_search_name)
                    )
                )
                self.service.saved_searches[inventory_saved_search_name].enable()

            elif non_inventory_saved_search_name in self.service.saved_searches:
                self.logger.debug(
                    "run_id={} script={} action=enable target={}".format(
                        self.run_id,
                        self.SCRIPT_NAME,
                        str(non_inventory_saved_search_name),
                    )
                )
                self.service.saved_searches[non_inventory_saved_search_name].enable()

            return self.handler.enable(self.callerArgs.id)

    @admin_external.build_conf_info
    def handleRemove(self, confInfo):
        self.delete_hook(
            session_key=self.getSessionKey(),
            config_name=self._get_name(),
            stanza_id=self.callerArgs.id,
        )
        # remove  macros
        target_macros = [
            "{}{}".format(self.callerArgs.id, i)
            for i in KNOWLEDGE_OBJECTS_WRITTEN["macros"]
        ]
        for target in target_macros:
            if target in self.service.confs["macros"]:
                self.logger.debug(
                    "run_id={} script={} action=delete target={}".format(
                        self.run_id, self.SCRIPT_NAME, str(target)
                    )
                )
                self.service.confs["macros"][target].delete()

        # remove transforms
        target_transforms = [
            "{}{}".format(self.callerArgs.id, i)
            for i in KNOWLEDGE_OBJECTS_WRITTEN["transforms"]
        ]
        for target in target_transforms:
            if target in self.service.confs["transforms"]:
                self.logger.debug(
                    "run_id={} script={} action=delete target={}".format(
                        self.run_id, self.SCRIPT_NAME, str(target)
                    )
                )
                self.service.confs["transforms"][target].delete()

        # remove savedsearch
        target_saved_searches = [
            "{}{}".format(self.callerArgs.id, i)
            for i in KNOWLEDGE_OBJECTS_WRITTEN["saved_searches"]
        ]
        for target in target_saved_searches:
            if target in self.service.saved_searches:
                self.service.saved_searches[target].disable()
                try:
                    self.logger.debug(
                        "run_id={} script={} action=delete target={}".format(
                            self.run_id, self.SCRIPT_NAME, str(target)
                        )
                    )
                    self.service.saved_searches[target].delete()
                except Exception:
                    pass

        # remove collection
        target_collections = [
            "{}{}".format(self.callerArgs.id, i)
            for i in KNOWLEDGE_OBJECTS_WRITTEN["collections"]
        ]
        for target in target_collections:
            if target in self.service.confs["collections"]:
                self.logger.debug(
                    "run_id={} script={} action=delete target={}".format(
                        self.run_id, self.SCRIPT_NAME, str(target)
                    )
                )
                self.service.confs["collections"][target].delete()

        ## TODO remove "{}_last_inventoried".format(self.callerArgs.id) from aggregation_lookup and aggregation_lookup_all
        ## dont forget to use the app setting last_inventoried_fieldname
        return self.handler.delete(self.callerArgs.id)
