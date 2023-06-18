#!/bin/bash

field=$1
field_value=$2
show_value=$3 # y/N

for key in $(redis-cli --scan | head -10); do 
    key_type=${key%:*}
    if [ $key_type == "TurbiniaTask" ]; then
        # Gets the Task value and split its key:value pairs into an array
        value=$(redis-cli get $key)
        modified_value="${value//\"/}"
        modified_value="${modified_value//\{/}"
        modified_value="${modified_value//\}/}"
        IFS=',' read -r -a array <<< "$modified_value"

        # Gets the Task value and split its key:value pairs into an array
        for pair in "${array[@]}"; do
            # Gets the Task value and split its key:value pairs into an array
            pair="${pair#"${pair%%[![:space:]]*}"}"
            if  [ "$pair"  == "$field: $field_value"  ]; then
                #echo -e "\033[0;31m$key\033[0m";
                if [ "$show_value" == "y" ]; then echo -e "$value\n"; fi
            fi
        done
    fi
done
