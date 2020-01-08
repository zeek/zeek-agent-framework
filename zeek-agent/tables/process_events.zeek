#! Logs process events activity

@load zeek-agent

module zeek_agent;

export {
	## Event to indicate that a new process was created on a host
	##
	## <params missing>
	global process_event_added: event(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int);
}

event zeek_agent::table_process_events(resultInfo: zeek_agent::ResultInfo,
		pid: int, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		start_time: int, parent: int) {
	if (resultInfo$utype == zeek_agent::ADD) {
		event zeek_agent::process_event_added(network_time(), resultInfo$host, pid, path, cmdline, cwd, uid, gid, start_time, parent);
	}

}

event zeek_init() {
	local query = [$ev=zeek_agent::table_process_events,$query="SELECT pid, path, cmdline, cwd, uid, gid, time, parent FROM process_events", $utype=zeek_agent::ADD, $inter=zeek_agent::QUERY_INTERVAL];
	zeek_agent::subscribe(query);
}
