rule redis_replicaof {
    meta:
        description = "Rule to find exploitation of Redis servers"
        author = "Fry"
        date = "2022-06-21"
        score = 90
    strings:
        $attack1 = "REPLICAOF" ascii
        $attack2 = "slaveof" ascii
        $result1 = "SECURITY ATTACK" ascii
        $result2 = "killall" ascii
        $result3 = "xmrig" ascii
        $result4 = "Saving to" ascii /* wget */
   condition:
      filename matches /redis.*\.log(.[0-9]+)?/ and any of ($attack*) and any of ($result*)
}