##! Logs file events activity

@load zeek-agent

module Agent_FileOpen;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:         time   &log;
		host_ts:    time   &log;
		host:       string &log;
		hostname:   string &log;
		parent:     int    &log;
		pid:        int    &log;
		uid:        int    &log;
		gid:        int    &log;
		path:       string &log;
		file_path:    string &log;
		action:    string &log;
	};
}

event Agent_FileOpen::file_open(result: ZeekAgent::Result,
		parent: int, pid: int, uid: int, gid: int, path: string, file_path: string, action: string, host_time: int)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	                  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
			  $parent = parent,
	       	          $pid = pid,
			  $uid = uid,
			  $gid = gid,
	                  $path = path,
	                  $file_path = file_path,
			  $action = action);

	Log::write(LOG, info);
	}


event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-file_events"]);

	local query = ZeekAgent::Query($ev=Agent_FileOpen::file_open,
	                                $query="SELECT parent_process_id, process_id, user_id, group_id, path, file_path, type, timestamp FROM file_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
