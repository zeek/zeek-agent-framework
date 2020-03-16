##! Logs process events activity

@load zeek-agent

module Agent_ProcessStart;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:         time   &log;
		host_ts:    time   &log;
		host:       string &log;
		pid:        int    &log;
		path:       string &log;
		cmdline:    string &log;
		cwd:        string &log;
		uid:        int    &log;
		gid:        int    &log;
		parent:     int    &log;
	};
}

event Agent_ProcessStart::process_start(result: ZeekAgent::Result,
		pid: int, path: string, cmdline: string, cwd: string, 
		uid: int, gid: int, host_time: int, parent: int)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	       	          $pid = pid,
	                  $path = path,
	                  $cmdline = cmdline,
	                  $cwd = cwd,
	                  $uid = uid,
	                  $gid = gid,
	                  $parent = parent);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-process_events"]);
	
	local query = ZeekAgent::Query($ev=Agent_ProcessStart::process_start,
	                                $query="SELECT pid, path, cmdline, cwd, uid, gid, time, parent FROM process_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
