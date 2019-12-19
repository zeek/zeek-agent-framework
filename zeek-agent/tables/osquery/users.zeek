#! Query users activity.

@load zeek-agent

module zeek_agent;

export {
	## Event to indicate that a new user was added on a host
	##
	## <params missing>
	global user_added: event(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, description: string, directory: string, shell: string, uuid: string, user_type: string);
	
	## Event to indicate that a existing user was removed on a host
	##
	## <params missing>
	global user_removed: event(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, description: string, directory: string, shell: string, uuid: string, user_type: string);
}

event zeek_agent::table_users(resultInfo: zeek_agent::ResultInfo,
		uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, 
		description: string, directory: string, shell: string, uuid: string, user_type: string) {
	if (resultInfo$utype == zeek_agent::ADD) {
		event zeek_agent::user_added(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
	}
	if (resultInfo$utype == zeek_agent::REMOVE) {
		event zeek_agent::user_removed(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
	}
}

event zeek_init() {
	local query = [$ev=zeek_agent::table_users,$query="SELECT uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, type FROM users", $utype=zeek_agent::BOTH, $inter=zeek_agent::QUERY_INTERVAL];
	zeek_agent::subscribe(query);
}
