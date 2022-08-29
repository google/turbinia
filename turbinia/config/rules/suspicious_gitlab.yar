rule suspicious_gitlab {
    meta:
        description = "Rule to find exploitation of Gitlab"
        author = "Fry"
        date = "2022-07-01"
        score = 90
    strings:
        $bad1 = "exiftool"
        $traversal1 = "%2F..%2F..%2F..%2F"
        $traversal2 = "/../../../"
   condition:
      (filepath matches /gitlab/) and any of them
}
