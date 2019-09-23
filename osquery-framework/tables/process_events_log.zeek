#! Logs process events activity

module osquery::logging::table_process_events;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
		path: string &log;
		cmdline: string &log;
		cwd: string &log;
		uid: int &log;
		gid: int &log;
		start_time: int &log;
		parent: int &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::process_event_added(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int) {
        local info: Info = [
		$t=t,
		$host=host_id,
               	$pid = pid,
                $path = path,
                $cmdline = cmdline,
                $cwd = cwd,
                $uid = uid,
                $gid = gid,
                $start_time = start_time,
                $parent = parent
        ];

        Log::write(LOG, info);

}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-process_events"]);
}
