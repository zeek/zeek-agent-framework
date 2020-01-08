
module zeek_agent;

export {
	# Interval in seconds to execute scheduled queries on hosts
	global QUERY_INTERVAL: count = 10 &redef;
}
