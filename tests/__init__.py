# -*- coding: utf-8 -*-
# # TEST_DIR='/Users/pmeyerso/Documents/repos/custom_report_app/'
TEST_DIR = "TA-oversight/bin"
APP_NAME = "TA-oversight"
BUILD_OUTPUT_BIN = "output/TA-oversight/bin"
import copy
import uuid
import json


class mock_splunk_service(object):
    def __init__(self, app_name, *collections):
        super(mock_splunk_service, self).__init__()
        self.namespace = {"app": app_name, "sharing": None, "user": None}
        self.kvstore = {}
        for collection in collections:
            self.kvstore[collection] = mock_kvstore(collection)

        # needed for InventoryUpdater.setup_attributes()
        # and batch writing
        self.confs = {}
        self.confs["limits"] = {}
        self.confs["limits"]["kvstore"] = {}
        self.confs["limits"]["kvstore"]["max_documents_per_batch_save"] = 3
        self.inputs = mock_service_inputs()
        self.saved_searches = None
        self.confs["transforms"] = None
        self.confs["macros"] = None

    ## needed for input_module_oversight::get_collection()
    def load_mock_saved_searches(self, data):
        self.saved_searches = data

    def load_mock_transforms(self, data):
        self.confs["transforms"] = data

    def load_mock_macros(self, data):
        self.confs["macros"] = data

    def load_mock_collection(self, collection, data):
        if collection not in self.kvstore:
            self.kvstore[collection] = mock_kvstore(collection, data)
        else:
            self.kvstore[collection].data = mock_kvstore_data(data)

class mock_service_inputs(object):
    def __init__(self):
        super(mock_service_inputs, self).__init__()
        self.input_list = []

    def list(self, type_name, count=None):
        return self.input_list

    def add(self, input_name):
        self.input_list.append(mock_input_item(input_name))


class mock_input_item(object):
    def __init__(self, name):
        super(mock_input_item, self).__init__()
        self.name = name


class mock_kvstore_data(object):
    def __init__(self, data=[]):
        super(mock_kvstore_data, self).__init__()
        self.data = data

    def query(self):
        return self.data

    def batch_save(self, *payload):
        input = iter(copy.deepcopy(payload))
        for document in input:
            if isinstance(document, str):
                document = json.loads(document)

            print("trying to save {}:{}".format(str(type(document)), str(document)))
            if not document.get("_key"):
                document["_key"] = str(uuid.uuid4()).replace("-", "")
            existing_keys = [i.get("_key") for i in self.data]
            if document["_key"] in existing_keys:
                position = existing_keys.index(document["_key"])
                tmp = copy.copy(self.data.pop(position))
                tmp.update(document)
                self.data.extend([tmp])
            else:
                self.data.extend([document])

class mock_kvstore(object):
    def __init__(self, name, data=[]):
        super(mock_kvstore, self).__init__()
        self.name = name
        self.data = mock_kvstore_data(data)


class mock_arg(object):
    # for mocking input definition arguments
    def __init__(self, data):
        super(mock_arg, self).__init__()
        self.name = data


class mock_scheme(object):
    # for mocking modularinput.Scheme
    def __init__(self):
        super(mock_scheme, self).__init__()
        self.arguments = []


class mock_definition(object):
    def __init__(self, data):
        super(mock_definition, self).__init__()
        self.parameters = data
