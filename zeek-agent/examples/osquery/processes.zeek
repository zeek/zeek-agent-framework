#! Query processes activity.

@load zeek-agent

module zeek_agent;

export {
	## Event to indicate that a new process was created on a host
	##
	## <param missing>
	global process_added: event(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int);

	## Event to indicate that an existing process terminated on a host
	##
	## <param missing>
	global process_removed: event(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int);
}

event zeek_agent::table_processes(resultInfo: zeek_agent::ResultInfo,
		pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int)
        {
	if (resultInfo$utype == zeek_agent::ADD) {
		event zeek_agent::process_added(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
	}
	if (resultInfo$utype == zeek_agent::REMOVE) {
		#print(fmt("Raising event to remove process with pid %d", pid));
		event zeek_agent::process_removed(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
	}
}

event zeek_init() {
	local query = [$ev=zeek_agent::table_processes,$query="SELECT pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup FROM processes", $utype=zeek_agent::BOTH, $inter=zeek_agent::QUERY_INTERVAL];
	zeek_agent::subscribe(query);
}
