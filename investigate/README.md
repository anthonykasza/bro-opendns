A toy example which queries the Investigate API from Bro scriptland.


Description
-----------
Monitor your network DNS queries and periodically check the queried names against the OpenDNS Investigate API. Bro scriptland notices are raised for malcious domains. 


Example Usage
-------------
Start Bro. Make DNS queries. Wait at least 10 seconds. Check the notice.log file.
```
bro -Ci eth0 ../example.bro
dig yahoo.com +short
dig songkillerbong.ru +short
dig foo.foo123 +short
...
cat notice.log
```

Known Limitations
-----------------
The categories.bro script parses JSON responses from the Investigate API with naive string splits. This is a huge hack around the fact that Bro scriptland has no JSON parser. 

Do not use this script in production.
