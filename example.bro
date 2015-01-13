# This is an example script that uses the investigate module.
#
# Domain names seen in dns_requests events are added to a set and
# sent to the Investigate API every 10 seconds. Notices are raised 
# for each malicious domain identified.

@load ./investigate
@load base/frameworks/notice

export {
	global my_domain_cache: set[string];
	global my_investigate_period: interval = 10secs;
	global OpenDNS::do_notice: bool = T;	

	redef enum Notice::Type += {
		OpenDNS::Notice
	};
}

event my_domain_check(domain_cache: set[string])
	{
	when ( local resp = OpenDNS::categorization(domain_cache) )
		{
		local results = OpenDNS::parse_categories(resp$body);
		for (each in results)
			{
			if (results[each] == "Blacklisted")
				{
				if (OpenDNS::do_notice)
					{
					local n = Notice::Info($note=OpenDNS::Notice,
								$msg=fmt("Blacklisted domain: '%s' queried", each));
					NOTICE(n);
					}
				delete my_domain_cache[each];
				}
			}
		}
	schedule my_investigate_period { my_domain_check(my_domain_cache) };
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	add my_domain_cache[query];
	}

event bro_init() &priority=-10
	{
	schedule my_investigate_period { my_domain_check(my_domain_cache) };
	}

