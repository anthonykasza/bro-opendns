Submit domains to the Investigate API and make an intelligence file for Bro to read consisting of malicious domains identified by OpenDNS.


Contents
--------
- filter contains a list of domains you'd like to avoid sending to OpenDNS. This is a good place to add things like "myInternalDomain.local"
- investigate.py is a Python script that reads domains from STDIN, applies the above "filter" file on those domains, submits the domains to the Investigate API, and creates an intelligence file for Bro to consume which contains domains Investigate knows to be malicious
- investigate.dat is the intelligence file investigate.py generates
- reader.bro is a Bro script which reads the intel file (investigate.dat) for Bro to use


Example Usage
-------------
Mine your dns.log file for domains to submit to Investigate
```
bro-cut query < dns.log | sort -u | python investigate.py
```

Simple Bash example
```
echo -e "google.com\ncnn.com\nsongkillerbong.ru\nyahoo.com" | python investigate.py
```

Caveat
------
You might be thinking "Ha! I'll milk the Investigate API for a big list of malicious domains". This is a very cunning thought. 

Remember, however, that intel (especially around domains and IP addresses) expires and changes very frequently. Nobody likes stale intel.
Besides, OpenDNS monitors API queries so play nice.

