#! Logs mounts activity.

module zeek_agent::logging::table_mounts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		device: string &log;
		device_alias: string &log;
		path: string &log;
		typ: string &log;
		blocks_size: int &log;
		blocks: int &log;
		flags: string &log;
	};
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_agent::mount_added(t: time, host_id: string, device: string, device_alias: string, path: string, typ: string, blocks_size: int, blocks: int, flags: string) {
	local info: Info = [
		 $t=t,
		 $host=host_id,
                 $device = device,
                      $device_alias = device_alias,
                      $path = path,
                      $typ = typ,
                      $blocks_size = blocks_size,
                      $blocks = blocks,
                      $flags = flags
			               ];
	
	Log::write(LOG, info);
}
@endif

event zeek_init() {
	Log::create_stream(LOG, [$columns=Info, $path="agent-mounts"]);
}
