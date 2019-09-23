#! Query users activity.

@load osquery-framework
@load ./configuration

module osquery;

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

event osquery::table_users(resultInfo: osquery::ResultInfo,
		uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, 
		description: string, directory: string, shell: string, uuid: string, user_type: string) {
	if (resultInfo$utype == osquery::ADD) {
		event osquery::user_added(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
	}
	if (resultInfo$utype == osquery::REMOVE) {
		event osquery::user_removed(network_time(), resultInfo$host, uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, user_type);
	}
}

event zeek_init() {
	local query = [$ev=osquery::table_users,$query="SELECT uid, gid, uid_signed, gid_signed, username, description, directory, shell, uuid, type FROM users", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
}
