#!/bin/bash
# This script iterates over the Turbinia Redis keys to find keys matching the
# passed arguments. The first parameter indicates the action to be performed 
# by the script. If "query" is chosen, the value of the the matching keys
# will be printed. This can be piped to jq to improve visualization. If 
# "delete" is chosen the matching keys will be deleted from redis. If "dump" is
# chosen, the matching keys will be dumped to the file indicated by the 4th
# argument ("dump_file"). The second argument indicates the field of the Redis
# value that will be queried, and the Third argument indicates the value that
# this field should have for a key to be selected. The keyword "all" can be
# passed to the second parameter so that all keys will be selected.

action=$1 # "query" / "delete" / "dump"
field=$2 # "all" / Field name
field_value=$3 # Field value
dump_file=$4 # File to dump 

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
            if   [ "$field" == "all" ] || [ "$pair"  == "$field: $field_value" ]; then
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
    if [ "$answer" == 'y' ] || [ "$answer" == 'Y' ]; then
        if [ "$action" == "delete" ]; then redis-cli DEL "${key_array[@]}"; fi
        if [ "$action" == "dump" ]; then
            for key in ${key_array[@]}; do
                redis-cli DUMP "$key" >> "$dump_file"
            done
            echo Dumped in "$dump_file"
        fi
    fi
fi