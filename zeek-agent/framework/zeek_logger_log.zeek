
#! Logs socket events activity

module ZeekAgent::logging::table_logger;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		host: string &log;
		event_time: int &log;
		severity: string &log;
		message: string &log;
	};
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event ZeekAgent::log_added(ts: time, host_id: string, event_time :int, severity :string, message :string)
	{
	local info = Info($ts=ts,
	                  $host=host_id,
	                  $event_time=event_time,
	                  $severity=severity,
	                  $message=message);

	Log::write(LOG, info);
	}
@endif

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="zeek-agent-logger"]);
	}
