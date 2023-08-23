#!/bin/bash
#
# This script provides tools to be used with the TurbiniaTask keys in Redis.
# There are 6 main functions: keys, values, count, delete, dump and restore.
# The first five will query over Redis to find keys that have the same value
# in a specific field, as determined by the passed arguments. Restore will
# restore all keys dumped in a directory. If "all" is used in [Field Name]
# and [Field Value] is left empty, all keys will be selected. 

usage() {
  cat << EOF
  Usage:
    ./redis-tools.sh keys [Field Name] [Field Value]
        The matching keys are printed out.
    ./redis-tools.sh values [Field Name] [Field Value]
        The values of the matching keys are printed out.
    ./redis-tools.sh count [Field Name] [Field Value]
        The amount of matching keys is printed out.
    ./redis-tools.sh delete [Field Name] [Field Value]
        The matching keys are deleted from redis.
    ./redis-tools.sh dump [Field Name] [Field Value] [Directory to Dump]
        The matching keys are dumped to the indicated directory.
    ./redis-tools.sh restore [Directory to Restore] 
        The keys dumped in the directory are restored.

  Examples: 
  ./redis-tools.sh keys all
  ./redis-tools.sh values id f5bd194d9424427c9d82a57eedc531d0
  ./redis-tools.sh count request_id 09879dbc90a44c6db80dc9f68113d8
  ./redis-tools.sh dump request_id 09879dbc90a44c6db80dc9f68113d8 storagefolder
  ./redis-tools.sh delete all
  ./redis-tools.sh restore storagefolder
  ./redis-tools.sh dump all storagefolder
EOF
}

action=$1 # "keys" / "values" / "count" / "delete" / "dump" / "restore"

case "$action" in
  "restore")
    directory=$2
    if [[ -z "$directory" ]]; then
      >&2 echo Error: Directory not provided
      exit
    fi
    for filepath in "$directory"/*; do
      key=$(basename "$filepath")
      echo Restoring "$key"
      redis-cli -x restore "$key" 0 < "$filepath"
    done
  ;;
  "keys"|"values"|"count"|"dump"|"delete")
    field_name="$2"
    # Ignores [Field Value] if "all" is passed
    if [[ "$field_name" == "all" ]]; then
      directory="$3";
    else
      field_value="$3"
      directory="$4"
    fi
    case "$action" in
      "keys")
        echo Keys found:
      ;;
      "dump")
        if [[ -z "$directory" ]]; then
          >&2 echo Error: Directory not provided
          exit
        fi
      ;;&
      "delete"|"dump")
        declare -a key_array
        if [[ "$field_name" != "all" ]]; then
          echo Keys found:
        fi
      ;;
      "count")
        declare -i keys_counter=0
      ;;
    esac
    for key in $(redis-cli --scan); do 
      # Gets the key_type by removing the characters after the colon 
      key_type=$(echo "$key" | cut -f 1 -d :)
      if [[ "$key_type" != "TurbiniaTask" ]]; then
        continue
      fi
      # Gets the Task value and split its key:value pairs into an array
      value=$(redis-cli get "$key")
      modified_value="${value//\"/}"
      modified_value="${modified_value//\{/}"
      modified_value="${modified_value//\}/}"
      IFS=',' read -r -a array <<< "$modified_value"
      if [[ "$field_name" == "all" ]]; then
        case "$action" in
          "keys")
            echo "$key"
          ;;
          "values")
            echo -e "$value\n"
          ;;
          "delete"|"dump")
            key_array+=( "$key" )
          ;;
          "count")
            keys_counter=$((keys_counter+1))
          ;;
        esac
        continue
      fi
      for pair in "${array[@]}"; do
        # Splits pair into field and value based on separating comma
        current_field=$(echo "$pair" | cut -f 1 -d : | xargs)
        current_value=$(echo "$pair" | cut -f 2 -d : | xargs)
        if [[ "$current_field"  == "$field_name" ]]; then
          if [[ "$current_value" == "$field_value" ]]; then
            case "$action" in
              "keys")
                echo "$key"
              ;;
              "values")
                echo -e "$value\n"
              ;;
              "delete"|"dump")
                echo "$key"
                key_array+=( "$key" )
              ;;
              "count")
                keys_counter=$((keys_counter+1))
              ;;
            esac
          fi
          break
        fi
      done
    done
    case "$action" in
      "count")
        echo "$keys_counter" keys found.
      ;;
      "dump"|"delete")
        echo Do you want to "$action" "${#key_array[@]}" keys? [y/N]
        read -r answer
        if [[ "$answer" == 'y' ]] || [[ "$answer" == 'Y' ]]; then
          if [[ "$action" == "delete" ]]; then
            redis-cli DEL "${key_array[@]}"
          else
            mkdir -p "$directory"
            for key in "${key_array[@]}"; do
              redis-cli --raw dump "$key" | head -c-1 > "$directory"/"$key"
            done
            echo Dumped in "$directory"
          fi
        fi
      ;;
      esac
    ;;
  *) usage
esac
