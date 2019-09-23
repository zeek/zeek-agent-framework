#! Query processes activity.

@load osquery-framework
@load ./configuration

module osquery;

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

event osquery::table_processes(resultInfo: osquery::ResultInfo,
		pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, 
		start_time: int, parent: int, pgroup: int)
        {
	if (resultInfo$utype == osquery::ADD) {
		event osquery::process_added(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
	}
	if (resultInfo$utype == osquery::REMOVE) {
		#print(fmt("Raising event to remove process with pid %d", pid));
		event osquery::process_removed(network_time(), resultInfo$host, pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup);
	}
}

event zeek_init() {
	local query = [$ev=osquery::table_processes,$query="SELECT pid, name, path, cmdline, cwd, root, uid, gid, on_disk, start_time, parent, pgroup FROM processes", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
}
