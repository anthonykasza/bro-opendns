# The beef. This file contains functions which wrap each of the Investigate API calls.
# Return code 499 is used as an internal error code for ActiveHTTP responses.

@load base/utils/active-http

module OpenDNS;
export {
       # the base URL for the Investigate API - this likely shouldn't change
        const investigate_api_base: string = "https://investigate.api.opendns.com/";

	# the Investigate API key
	const api_key: string = "";

        # HTTP headers needed for authenticating to the Investigate service. This is built in the following bro_init event
	const investigate_headers: string = fmt("-H 'Authorization: Bearer %s'", api_key);

        # Supported resource record types
        const supported_rr_types: set[string] = ["MX", "NS", "A", "TXT", "CNAME"] &redef;

        # API query timeout
        const investigate_timeout: interval = 15secs &redef;

	# API calling functions
	global categorization: function(names: set[string]): ActiveHTTP::Response;
	global cooccurences: function(name: string): ActiveHTTP::Response;
	global domain_rr_history: function(name: string, rr_type: string): ActiveHTTP::Response;
	global ip_rr_history: function(a: addr, rr_type: string): ActiveHTTP::Response;
	global latest_domains: function(a: addr): ActiveHTTP::Response;
	global related: function(name: string): ActiveHTTP::Response;
	global security: function(name: string): ActiveHTTP::Response;
	global tags: function(name: string): ActiveHTTP::Response;
}

# convert a set of string to a json array of strings
function string_set_jsonify(ss: set[string]): string
	{
	local last: count = |ss|;
	local current: count = 0;

	local s: string = "[";
	for (each in ss)
		{
		current = current + 1;
		if (current == last)
			{
			s += fmt("\"%s\"", each);
			}
		else 
			{
			s += fmt("\"%s\",", each);
			}
		}
	s += "]";
	return s;
	}

function categorization(names: set[string]): ActiveHTTP::Response
	{
	local ss: string = string_set_jsonify(names);

	local _request = [$url=fmt("%s%s", investigate_api_base, "domains/categorization/"),
		$addl_curl_args=investigate_headers, 
		$method="POST", $client_data=ss];

	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function cooccurences(name: string): ActiveHTTP::Response
	{
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("recommendations/name/%s.json", name)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function domain_rr_history(name: string, rr_type: string): ActiveHTTP::Response
	{
	if (rr_type !in supported_rr_types)
		{
		return [$code=599, $msg="Bad Request"];;
		}
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("dnsdb/name/%s/%s.json", rr_type, name)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function ip_rr_history(a: addr, rr_type: string): ActiveHTTP::Response
	{
	if (rr_type !in supported_rr_types)
		{
		return [$code=599, $msg="Bad Request"];;
		}
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("dnsdb/ip/%s/%s.json", rr_type, a)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function latest_domains(a: addr): ActiveHTTP::Response
	{
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("ips/%s/latest_domains", a)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function related(name: string): ActiveHTTP::Response
	{
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("links/name/%s.json", name)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function security(name: string): ActiveHTTP::Response
	{
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("security/name/%s.json", name)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}

function tags(name: string): ActiveHTTP::Response
	{
	local _request = [$url=fmt("%s%s", investigate_api_base, fmt("domains/%s/latest_tags", name)),
		$addl_curl_args=investigate_headers];
	return when (local resp = ActiveHTTP::request(_request))
		{
		return resp;
		}
	timeout investigate_timeout
		{
		return [$code=499, $msg="Timeout Error"];
		}
	}
