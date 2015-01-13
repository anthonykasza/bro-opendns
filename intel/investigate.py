import json
import requests
import sys
import fileinput
from publicsuffix import PublicSuffixList

psl = PublicSuffixList()
domains = list()
domain_filter = set()
domain_filter_filename = "./filter"
uri = "https://investigate.api.opendns.com"
api_key = ""
headers = {'Authorization': 'Bearer ' + api_key}
statuses = {1:"Whitelisted", 0:"Unknown", -1:"Blacklisted"}


def check_domains(domains):
    ''' Submit a list of domains to the Investigate API and yield results
    '''
    url = uri + '/domains/categorization/'
    domains = json.dumps(domains)
    resp = requests.post(url, headers=headers, data=domains)
    if resp.status_code == 200:
        results = resp.json()
        for r in results:
            yield r, results[r]['status']
    else:
        raise StopIteration


def make_intel_file(domains, fname):
    ''' For a list of domains, if the status of a domain is blacklisted, add the domain to an intel file
    '''
    # add proper column headers to intel file
    with open(fname, 'w') as f:
        f.write("#%s\t%s\t%s\t%s\t%s\t%s\n" % 
            ("fields", "indicator", "indicator_type", "meta.source", "meta.do_notice", "meta.if_in"))
        for (r, status) in check_domains(domains):
            if status == -1:
                f.write("%s\t%s\t%s\t%s\t%s\n" % (r, "Intel::DOMAN", "OpenDNS::Investigate", "T", "DNS::DOMAIN"))
            else:
                pass


# Read a list of domains from STDIN and place in list
# If the domain's public suffix is in the filter file, skip it
with open (domain_filter_filename, 'r') as f:
    for line in f:
        domain_filter.add(line.strip())

for line in fileinput.input():
    domain = line.strip()
    if psl.get_public_suffix(domain) in domain_filter:
        continue
    else:
        domains.append(domain)


# Push button
make_intel_file(domains, "investigate.dat")
