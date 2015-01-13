# This file contains test functions to ensure all Investigate API calls are functioning properly.

@load ./investigate

event bro_init() &priority=-10
	{
	local name: string = "bro.org";
	local a: addr = 8.8.8.8;
       	local names: set[string] = ["google.com", "cnn.com"];
	local rr_type: string = "A";

	when (local cat_resp = OpenDNS::categorization(names))
		{
		print("categorization");
		print cat_resp;
		print("");
		}	

	when (local coo_resp = OpenDNS::cooccurences(name))
		{
		print("cooccurences");
		print coo_resp;
		print("");
		}

	when (local drr_resp = OpenDNS::domain_rr_history(name, rr_type))
		{
		print("domain_rr_history");
		print drr_resp;
		print("");
		}	

	when (local iprr_resp = OpenDNS::ip_rr_history(a, rr_type))
		{
		print("ip_rr_history");
			print iprr_resp;
		print("");
		}

	when (local lat_resp = OpenDNS::latest_domains(a))
		{
		print("latest_domains");
		print lat_resp;
		print("");
		}

	when (local rel_resp = OpenDNS::related(name))
		{
		print("related");
		print rel_resp;
		print("");
		}

	when (local sec_resp = OpenDNS::security(name))
		{
		print("security");
		print sec_resp;
		print("");
		}
		
	when (local tag_resp = OpenDNS::tags(name))
		{
		print("tags");
		print tag_resp;
		print("");
		}
	}
