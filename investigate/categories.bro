# This file contains code that parses the 'categories' Investigate API call response.

module OpenDNS;

export {
	const status_table: table[string] of string = {
		["-1"] = "Blacklisted",
		["0"]  = "Unknown",
		["1"]  = "Whitelisted",
	};

	global parse_categories: function(json_string: string): table[string] of string;
}

# !!!WARNING: This function parses JSON with string splits!!!
# This whole function needs to be rewritten when/if Bro gets JSON parsing 
# functionality in its core or through a plugin. 
function parse_categories(json_string: string): table[string] of string
	{
	local results: table[string] of string;
	local parts = split(json_string, /\}/);
	for (each in parts)
		{
		if (|parts[each]| > 1)
			{
			local entry: string = parts[each][1:];
			local domain = split(entry, /\:/)[1];
			domain = gsub(domain, /\"/, "");

			local status_s: string = find_last(entry, /\"status\":-?./);
			status_s = gsub(status_s, /\"/, "");
			status_s = split(status_s, /\:/)[2];

			results[domain] = OpenDNS::status_table[status_s];
			}
		else
			{
			next;
			}
		}
	return results;
	}
