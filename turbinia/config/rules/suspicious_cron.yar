rule suspicious_cron {
    meta:
        description = "Rule to find persistance in Cron files"
        author = "Fry"
        date = "2022-07-01"
        score = 90
    strings:
        $wget = "wget" nocase
        $options1 = "-q"
        $options2 = "-O-"
        $curl1 = "curl" nocase
        $curl2 = "-fssl" nocase
        $shm = "/dev/shm"
        $pipechar = "|"
        $shell = "sh"
        $pgmem = "pg_mem"
   condition:
      (filepath matches /cron/ or filepath matches /spool\/at/) and (($wget or all of ($options*)) or any of ($curl*) or $shm or $pgmem or (for all i in (1..#shell) : ((@shell[i] > @pipechar[i]) and (@shell[i] < @pipechar[i] + 10))))
}
