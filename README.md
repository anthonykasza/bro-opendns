Bro and OpenDNS
===============
A few examples of how Bro and OpenDNS can play together. 


Contents
--------

###investigate
This directory contains a Bro module that uses the Investigate API by OpenDNS. 
example.bro contains a script that uses this module to identify domain names from dns requests, and every 10 seconds submit them to the Investigate API. A notice is raised and logged if any submitted domain in known to be malicious by OpenDNS.


###intel
This directory contains a few scripts that will identify domain names from Bro's standard dns.log file and submit them to the Investigate API. If any domain is found to be malicious by OpenDNS, the domain is added to an intelligence file named "investigate.dat". The intelligence file is formatted for Bro's intel framework, allowing Bro to ingest and monitoring for the malicious domains.
