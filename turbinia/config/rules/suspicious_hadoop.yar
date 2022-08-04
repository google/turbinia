rule suspicious_hadoop {
    meta:
        description = "Rule to find exploitation of Hadoop"
        author = "Fry"
        date = "2022-07-01"
        score = 90
    strings:
        $bad1 = "curl"
        $bad2 = "wget"
   condition:
      (filepath matches /hadoop/) and any of them
}
