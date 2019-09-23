#! Logs process events activity

@load osquery-framework
@load ./configuration

module osquery;

export {
	## Event to indicate that a new process was created on a host
	##
	## <params missing>
	global process_event_added: event(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int);
}

event osquery::table_process_events(resultInfo: osquery::ResultInfo,
		pid: int, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		start_time: int, parent: int) {
	if (resultInfo$utype == osquery::ADD) {
		event osquery::process_event_added(network_time(), resultInfo$host, pid, path, cmdline, cwd, uid, gid, start_time, parent);
	}

}

event zeek_init() {
	local query = [$ev=osquery::table_process_events,$query="SELECT pid, path, cmdline, cwd, uid, gid, time, parent FROM process_events", $utype=osquery::ADD, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
}
