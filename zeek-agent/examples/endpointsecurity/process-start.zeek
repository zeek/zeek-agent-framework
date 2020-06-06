##! Logs process events activity

@load zeek-agent

module Agent_ProcessStart;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:         time   &log;
		host_ts:    time   &log;
		host:       string &log;
		hostname:   string &log;
		pid:        int    &log;
		path:       string &log;
		cmdline:    string &log;
		uid:        int    &log;
		gid:        int    &log;
		parent:     int    &log;
	        platform_binary:    int    &log;
	};
}

event Agent_ProcessStart::process_start(result: ZeekAgent::Result,
		pid: int, path: string, cmdline: string,
					uid: int, gid: int, host_time: int, parent: int, platform_binary: int)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	                  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
	       	          $pid = pid,
	                  $path = path,
	                  $cmdline = cmdline,
	                  $uid = uid,
	                  $gid = gid,
	                  $parent = parent,
			  $platform_binary = platform_binary);

	Log::write(LOG, info);
	}


event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-process_events"]);

	local query = ZeekAgent::Query($ev=Agent_ProcessStart::process_start,
	                                $query="SELECT process_id, path, cmdline, user_id, group_id, timestamp, parent_process_id, platform_binary FROM process_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
