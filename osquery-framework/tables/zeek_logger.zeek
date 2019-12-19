#! Query processes activity.

@load osquery-framework
@load ./configuration

module osquery;

export {
	global log_added: event(t: time, host_id: string, event_time: int, severity: string, message: string);
	global log_removed: event(t: time, host_id: string, event_time: int, severity: string, message: string);
}

event osquery::table_logger(resultInfo: osquery::ResultInfo, event_time: int, severity: string, message: string)
	{
	if ( resultInfo$utype == osquery::ADD )
		event osquery::log_added(network_time(), resultInfo$host, event_time, severity, message);

	if ( resultInfo$utype == osquery::REMOVE)
		event osquery::log_removed(network_time(), resultInfo$host, event_time, severity, message);
	}

event zeek_init()
	{
	local query = [$ev=osquery::table_logger, $query="SELECT time, severity, message FROM zeek_logger", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
	}
