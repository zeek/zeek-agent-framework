#! Query processes activity.

module zeek_agent;

export {
	global log_added: event(t: time, host_id: string, event_time: int, severity: string, message: string);
	global log_removed: event(t: time, host_id: string, event_time: int, severity: string, message: string);
}

event zeek_agent::table_logger(result: zeek_agent::Result, event_time: int, severity: string, message: string)
	{
	if ( result$utype == zeek_agent::ADD )
		event zeek_agent::log_added(network_time(), result$host, event_time, severity, message);

	if ( result$utype == zeek_agent::REMOVE)
		event zeek_agent::log_removed(network_time(), result$host, event_time, severity, message);
	}

event zeek_init()
	{
	local query = zeek_agent::Query($ev=zeek_agent::table_logger, 
	                               $query="SELECT time, severity, message FROM zeek_logger",
	                               $utype=zeek_agent::BOTH);
	zeek_agent::subscribe(query);
	}
