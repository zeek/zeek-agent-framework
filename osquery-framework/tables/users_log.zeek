#! Logs users activity.

module osquery::logging::table_users;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                uid: int &log;
                gid: int &log;
		uid_signed: int &log;
		gid_signed: int &log;
		username: string &log;
		description: string &log;
		directory: string &log;
		shell: string &log;
		uuid: string &log;
		user_type: string &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::user_added(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, description: string, directory: string, shell: string, uuid: string, user_type: string) {
        local info: Info = [
		$t=t,
		$host=host_id,
               	$uid = uid,
                $gid = gid,
                $uid_signed = uid_signed,
                $gid_signed = gid_signed,
                $username = username,
                $description = description,
                $directory = directory,
                $shell = shell,
                $uuid = uuid,
                $user_type = user_type
        ];

        Log::write(LOG, info);
}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-users"]);
}
