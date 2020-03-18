#! Query users activity.

@load zeek-agent

module AgentUsers;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:          time   &log;
		host:        string &log;
                hostname:    string &log;
		action:      string &log;
		username:    string &log;
		uid:         int    &log;
		gid:         int    &log;
		description: string &log;
		home_dir:    string &log;
		shell:       string &log;
	};
}

event AgentUsers::change(result: ZeekAgent::Result, uid: int, gid: int, username: string, description: string, directory: string, shell: string)
	{
	# Don't log existing users.  We only want the moment users are added or removed.
	if ( result$utype == ZeekAgent::INITIAL )
		return;

	local info = Info($ts = network_time(),
	                  $host = result$host,
			  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
	                  $action = (result$utype == ZeekAgent::ADD ? "add" : "remove"),
	                  $username = username,
	                  $uid = uid,
	                  $gid = gid,
	                  $description = description,
	                  $home_dir = directory,
	                  $shell = shell);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-users"]);

	local query = ZeekAgent::Query($ev=AgentUsers::change,
	                                $query="SELECT uid_signed, gid_signed, username, description, directory, shell FROM users",
	                                $utype=ZeekAgent::BOTH);
	ZeekAgent::subscribe(query);
	}
