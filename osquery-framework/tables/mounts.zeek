#! Query mounts activity.

@load osquery-framework
@load ./configuration

module osquery;

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

event osquery::table_mounts(resultInfo: osquery::ResultInfo,
		device: string, device_alias: string, path: string, typ: string,
		blocks_size: int, blocks: int, flags: string) {
	if ( resultInfo$utype == osquery::ADD ) {
		event osquery::mount_added(network_time(), resultInfo$host, device, device_alias, path, typ, blocks_size, blocks, flags);
	}
	if ( resultInfo$utype == osquery::REMOVE ) {
		event osquery::mount_added(network_time(), resultInfo$host, device, device_alias, path, typ, blocks_size, blocks, flags);
	}
}

event zeek_init(){
	local ev = [$ev=osquery::table_mounts,$query="SELECT device, device_alias, path, type, blocks_size, blocks, flags FROM mounts", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(ev);
	}
