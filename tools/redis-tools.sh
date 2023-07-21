#!/bin/bash
#
# This script provides tools to be used with the TurbiniaEvidence keys in
# Redis. There are 5 main functions: keys, values, delete, dump and restore.
# The first five will query over Redis to find keys that have the same value
# in a specific field, as determined by the passed arguments. Restore will
# restore all keys dumped in a directory. If "all" is used in [Field Name]
# and [Field Value] is left empty, all keys will be selected. 
#
# Usage:
#   ./redis-tools.sh keys [Field Name] [Field Value]
#       The matching keys are printed out.
#   ./redis-tools.sh values [Field Name] [Field Value]
#       The values of the matching keys are printed out.
#   ./redis-tools.sh delete [Field Name] [Field Value]
#       The matching keys are deleted from redis.
#   ./redis-tools.sh dump [Field Name] [Field Value] [Directory to Dump]
#       The matching keys are dumped to the indicated directory.
#   ./redis-tools.sh restore [Directory to Restore] 
#       The keys dumped in the directory are restored.
#
# Examples: 
#  ./redis-tools.sh keys all
#  ./redis-tools.sh values id f5bd194d9424427c9d82a57eedc531d0
#  ./redis-tools.sh dump request_id 09879dbc90a44c6db80dc9f68113d829 storagefolder
#  ./redis-tools.sh delete all
#  ./redis-tools.sh restore storagefolder
#  ./redis-tools.sh dump all storagefolder

action=$1 # "keys" / "values" / "delete" / "dump" / "restore"

case "$action" in
  "restore")
    directory=$2
    if [[ -z "$directory" ]]; then
      >&2 echo Error: directory not provided
    else
      for filepath in "$directory"/*; do
        key=$(basename "$filepath")
        echo Restoring "$key"
        cat "$filepath" | redis-cli -x restore "$key" 0
      done
    fi
  ;;

  "keys"|"values"|"dump"|"delete")
    # Ignores [Field Value] if "all" is passed
    field_name="$2"
    if [[ "$field_name" == "all" ]]; then
      directory="$3";
    else
      field_value="$3"
      directory="$4"
    fi

    if [[ "$action" == "dump" ]] && [[ -z "$directory" ]]; then
      >&2 echo Error: directory not provided
    else
      if [[ "$action" != "values" ]]; then
        declare -a key_array
        if [[ "$action" == keys ]] || [[ "$field_name" != "all" ]]; then
          echo Keys found:
        fi
      fi

      for key in $(redis-cli --scan); do 
        # Gets the first 8 digits fo the key to check if it belongs to Turbinia
        key_type=$(echo "$key" | sed 's/:.*//')
        if [[ "$key_type" == "TurbiniaTask" ]]; then
          # Gets the Task value and split its key:value pairs into an array
          value=$(redis-cli get "$key")
          modified_value="${value//\"/}"
          modified_value="${modified_value//\{/}"
          modified_value="${modified_value//\}/}"
          IFS=',' read -r -a array <<< "$modified_value"

          if [[ "$field_name" == "all" ]]; then
            if [[ "$action" == "values" ]]; then
              echo -e "$value\n"
            else
              if [[ "$action" == keys ]]; then echo "$key"; fi
              key_array+=( "$key" )
            fi
          else
            for pair in "${array[@]}"; do
              # Splits pair into field and value based on separating comma
              current_field=$(echo "$pair" | sed 's/:.*//' | xargs)
              current_value=$(echo "$pair" | sed 's/.*://' | xargs)
              if [[ "$current_field"  == "$field_name" ]]; then
                if [[ "$current_value" == "$field_value" ]]; then
                  if [[ "$action" == "values" ]]; then
                    echo -e "$value\n";
                  else
                    echo "$key"
                    key_array+=( "$key" )
                  fi
                fi
                break
              fi
            done
          fi
        fi
      done

      if [[ "$action" == "delete" ]] || [[ "$action" == "dump" ]]; then
        echo Do you want to "$action" "${#key_array[@]}" keys? [y/N]
        read -r answer
        if [[ "$answer" == 'y' ]] || [[ "$answer" == 'Y' ]]; then
          if [[ "$action" == "delete" ]]; then
            redis-cli DEL "${key_array[@]}"
          else
            mkdir -p "$directory"
            for key in ${key_array[@]}; do
              redis-cli --raw dump "$key" | head -c-1 > "$directory"/"$key"
            done
            echo Dumped in "$directory"
          fi
        fi
      fi
    fi
  ;;

  *) echo "$(cat redis-tools.sh | head -n 28 | tail -n 19)";;
esac
