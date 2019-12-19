#! Query mounts activity.

@load zeek-agent

module zeek_agent;

export {
	## Event to indicate that a new mount was created on a host
	##
	## <params missing>
	global mount_added: event(t: time, host_id: string, device: string, device_alias: string, path: string, typ: string, blocks_size: int, blocks: int, flags: string);
	
	## Event to indicate that an existing mount was removed on a host
	##
	## <params missing>
	global mount_removed: event(t: time, host_id: string, device: string, device_alias: string, path: string, typ: string, blocks_size: int, blocks: int, flags: string);
}

event zeek_agent::table_mounts(resultInfo: zeek_agent::ResultInfo,
		device: string, device_alias: string, path: string, typ: string,
		blocks_size: int, blocks: int, flags: string) {
	if ( resultInfo$utype == zeek_agent::ADD ) {
		event zeek_agent::mount_added(network_time(), resultInfo$host, device, device_alias, path, typ, blocks_size, blocks, flags);
	}
	if ( resultInfo$utype == zeek_agent::REMOVE ) {
		event zeek_agent::mount_added(network_time(), resultInfo$host, device, device_alias, path, typ, blocks_size, blocks, flags);
	}
}

event zeek_init(){
	local ev = [$ev=zeek_agent::table_mounts,$query="SELECT device, device_alias, path, type, blocks_size, blocks, flags FROM mounts", $utype=zeek_agent::BOTH, $inter=zeek_agent::QUERY_INTERVAL];
	zeek_agent::subscribe(ev);
	}
