rule pgsql_from_program {
   meta:
      description = "Detects COPY .. FROM PROGRAM statements"
      author = "Fry"
      date = "2022/05/31"
      modified = "2022/05/31"
      score = 100
   strings:
      $fp1 = "FROM PROGRAM" ascii
   condition:
      $fp1 and (filename matches /postgresql-([0-9])+-.*.log(.[0-9]+)?/ or filepath matches /babelfish\/log/ or filepath matches /(yugabyte|yb-data)\/(master|tserver)\/logs/ or filename matches /pg_stat_tmp\/pgss_query_texts.stat/)
}