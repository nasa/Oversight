import re
import json

def additional_packaging(ta_name):

    if ta_name=="TA-oversight":

        print("additional_packaging:checking for invalid schema property schemaVersion")

        pattern1 = re.compile(r',\s*\"schemaVersion\":\s*\"[\d\.]+\"', re.MULTILINE)
        repl1 = ''

        globalConfig = 'output/{}/appserver/static/js/build/globalConfig.json'.format(ta_name)
        with open(globalConfig, 'r+b') as file1:
            contents = file1.read().decode('utf-8')
            print("additional_packaging:opened file {}".format(file1.name))
            if re.search(pattern1, contents):
                print("additional_packaging:removing schemaVersion attribute")
            
                contents = re.sub(pattern1, repl1, contents)

                contents = contents.encode("utf-8")
                file1.seek(0)
                file1.write(contents)
                file1.truncate()
                file1.close()
            
        print("additional_packaging:done with file")
    
        ## add 'interval' as a key for the modular input so it can be set as a default value
        ## since we ONLY want the modular input to execute once        
        # add 'index' as a key because it is required for modular input but we dont want the other to have to select 
        # it and since we don't use it, it doesn't matter what it is.
        # listing both here allows us to specify a default value in inputs.conf

        """
        inputs_conf_spec = 'output/{}/README/inputs.conf.spec'.format(ta_name)
        append_text = '\ninterval = build script execution schedule\nindex = required by splunk but not used'.encode("utf-8")
        with open(inputs_conf_spec, 'a+b') as file1:
            print("opened {}".format(file1.name))
            file1.write(append_text)
            file1.truncate()
            
            print("appended text: {} to file: {}".format(str(append_text), str(inputs_conf_spec)))
            # append python.version = python3 if it is not already present
            append_text = '\npython.version = python3'.encode('utf-8')
            file1.seek(0)
            content = file1.read().decode("utf-8")
            if 'python.version' not in content:
                file1.write(append_text)
            file1.truncate()
            file1.close() """
        
            # print("appended text: {} to file: {}".format(str(append_text), str(inputs_conf_spec)))
        ## add import statement
        oversight_file = 'output/{}/bin/oversight.py'.format(ta_name)
        
        repl1_append = 'import input_module_oversight as input_module\n'

        # replace default generation of stream_events() by ucc-gen
        pattern2 = r'def stream_event[\w\W]*(?:\n\n)'
        repl2 = 'def stream_events(self, inputs, ew):\n        input_module.stream_events(self, inputs, ew)\n\n\n'

        # replace default generation of validate_input() by ucc-gen
        pattern3 = r'def validate_input[\w\W]*return\n'
        repl3 = 'def validate_input(self, definition):\n        input_module.validate_input(self, definition)\n\n'

        ## set to single instance mode = false
        pattern4 = r'scheme.use_single_instance = True'
        repl4 = 'scheme.use_single_instance = False'

        with open(oversight_file, 'r+b') as file1:
            print("additional_packaging:opened {} for post-processing".format(file1.name))
            file1.seek(0)
            pattern1 = file1.readline().decode("utf-8")
            file1.seek(0)
            content = file1.read().decode("utf-8")

            repl1 = pattern1 + repl1_append
            if not re.search(pattern1, content): print("additional_packaging:pattern1 not found")
            if not re.search(pattern2, content): print("additional_packaging:pattern2 not found")
            if not re.search(pattern3, content): print("additional_packaging:pattern3 not found")
            if not re.search(pattern4, content): print("additional_packaging:pattern4 not found")
            content = re.sub(pattern1, repl1, content)
            content = re.sub(pattern2, repl2, content)
            content = re.sub(pattern3, repl3, content)
            content = re.sub(pattern4, repl4, content)
            content = content.encode("utf-8")

            file1.seek(0)
            file1.write(content)
            file1.truncate()
            file1.close()

        print("done modifying file {}".format(file1.name))

        """
        " Update TA_oversight_rh_oversight.py, the rest handler/data model.  Use our custom rest handler instead.
        " Ensures that disable/enable/delete an Input stanza also disable/enable savedsearch, and deletes all generated kos
        """
        handler_model_file = 'output/{}/bin/TA_oversight_rh_oversight.py'.format(ta_name)
        custom_handler_name= "OversightInputExternalHandler"
        custom_handler_import = "from input_module_handler import {}\n".format(custom_handler_name)


        # replace handler object
        pattern1 = r'handler=[a-zA-Z]+,'
        repl1 = 'handler={},'.format(custom_handler_name)

        with open(handler_model_file, 'r+b') as file1:
            print("additional_packaging:opened {} for post-processing".format(file1.name))
            file1.seek(0)
            content = file1.read().decode("utf-8")            

            changes_made = False
            ## Find first import statement and insert AFTER
            if "import " in content:
                print("additional_packaging:found import statement")
                last_import = content.split('import ')[-1]
                last_import = last_import.split('\n')[0]
                last_import = "import {}\n".format(last_import)
                import_repl = "{}{}".format(last_import, custom_handler_import)
                # ex last_import="import logging\n"
                print("additional_packaging:substituting import statements")
                content = re.sub(last_import,import_repl, content)
                changes_made = True
            else:
                print("additional_packaging:couldn't figure out how to add import statement")
                raise ValueError("Couldn't include needed import statement, likely regex failure, maybe ucc output file has changed")

            ## replace handler=AdminExternalHandler with handler=OversightInputExternalHandler
            if "handler=" in content:
                current_handler_statement = re.search(r"handler=[a-zA-Z]+,", content)
                if current_handler_statement:
                    current_handler_statement = current_handler_statement[0]
                    print("additional_packaging:substituting handler name")
                    content = re.sub(current_handler_statement, repl1, content)
                    changes_made=True
                else:
                    print("additional_packaging:couldn't figure out how to change handler")
                    raise ValueError("Couldn't change handler from default, likely regex failure, maybe ucc output file has changed")
            
            if changes_made:
                content = content.encode("utf-8")
                file1.seek(0)
                file1.write(content)
                file1.truncate()
                file1.close()                
            
            print("additional_packaging:done modifying file {}".format(file1.name))

    else:
        print("additional_packaging:no settings for {}".format(ta_name))

