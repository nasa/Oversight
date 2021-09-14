## AUTH:
#splunk_session = Splunk_Caller()
from os import path
import datetime
import json
import ast
import sys
import logging
APP_NAME='Oversight'

class TestResults(object):

    def __init__(self):
        number_passes = 0
        number_fails = 0
        query_log = []
        response_log = []
        result_log = []

