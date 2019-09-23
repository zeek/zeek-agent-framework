#! Query processes activity.

module osquery::logging::table_processes;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
                name: string &log;
		path: string &log;
		cmdline: string &log;
		cwd: string &log;
		root: string &log;
		uid: int &log;
		gid: int &log;
		on_disk: int &log;
		start_time: int &log;
		parent: int &log;
		pgroup: int &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::process_added(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, cwd: string, root: string, uid: int, gid: int, on_disk: int, start_time: int, parent: int, pgroup: int) {
        local info: Info = [
		$t=t,
		$host=host_id,
               	$pid = pid,
                $name = name,
                $path = path,
                $cmdline = cmdline,
                $cwd = cwd,
                $root = root,
                $uid = uid,
                $gid = gid,
                $on_disk = on_disk,
                $start_time = start_time,
                $parent = parent,
                $pgroup = pgroup
        ];

        Log::write(LOG, info);
}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-processes"]);
}
