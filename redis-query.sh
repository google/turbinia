#!/bin/bash

action=$1 # query / delete / dump
field=$2 # "all" or field name
field_value=$3 # Field value

if [ "$action" != "query" ]; then
    key_array=()
    echo Keys found:
fi

# Iterates over keys in redis to find suitable ones
for key in $(redis-cli --scan); do 
    key_type=${key%:*}
    if [ $key_type == "TurbiniaTask" ]; then
        # Gets the Task value and split its key:value pairs into an array
        value=$(redis-cli get $key)
        modified_value="${value//\"/}"
        modified_value="${modified_value//\{/}"
        modified_value="${modified_value//\}/}"
        IFS=',' read -r -a array <<< "$modified_value"

        for pair in "${array[@]}"; do
            # Cleans the pair to allow comparison with given field and value
            pair="${pair#"${pair%%[![:space:]]*}"}"
            if  [ "$pair"  == "$field: $field_value" ] || [ "$field" == "all" ]; then
                if [ "$action" == "query" ]; then
                    echo -e "$value\n";
                else
                    echo "$key"
                    key_array+=( "$key" )
                fi
            fi
        done
    fi
done

# If not querying, confirms if user wants to delete or dump keys
if [ "$action" == "delete" ] || [ "$action" == "dump" ] && [ -n "$array" ]; then
    echo Do you want to "$action" the keys above? [y/N]
    read answer
    if [ "$answer" == 'y' ]; then
        if [ "$action" == "delete" ]; then redis-cli DEL "${key_array[@]}"; fi
        if [ "$action" == "dump" ]; then
            for key in ${key_array[@]}; do
                redis-cli DUMP "$key"
            done
        fi
    fi
fi