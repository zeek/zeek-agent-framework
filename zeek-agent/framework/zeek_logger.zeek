#! Query processes activity.

module ZeekAgent;

export {
	global log_added: event(t: time, host_id: string, event_time: int, severity: string, message: string);
	global log_removed: event(t: time, host_id: string, event_time: int, severity: string, message: string);
}

event ZeekAgent::table_logger(result: ZeekAgent::Result, event_time: int, severity: string, message: string)
	{
	if ( result$utype == ZeekAgent::ADD )
		event ZeekAgent::log_added(network_time(), result$host, event_time, severity, message);

	if ( result$utype == ZeekAgent::REMOVE)
		event ZeekAgent::log_removed(network_time(), result$host, event_time, severity, message);
	}

event zeek_init()
	{
	local query = ZeekAgent::Query($ev=ZeekAgent::table_logger, 
	                               $query="SELECT time, severity, message FROM zeek_logger",
	                               $utype=ZeekAgent::BOTH);
	ZeekAgent::subscribe(query);
	}
