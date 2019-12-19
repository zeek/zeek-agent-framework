#! Logs socket events activity

module zeek_agent::logging::table_logger;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		event_time: int &log;
		severity: string &log;
		message: string &log;
	};
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_agent::log_added(t: time, host_id: string, event_time :int, severity :string, message :string)
	{
	local info: Info = [$t=t,
			    $host=host_id,
			    $event_time=event_time,
			    $severity=severity,
			    $message=message
			   ];

	Log::write(LOG, info);
	}
@endif

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="osq-zeek_logger"]);
	}
