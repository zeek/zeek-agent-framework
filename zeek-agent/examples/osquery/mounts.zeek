#! Query mounts activity.

@load zeek-agent

module AgentMounts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:     time   &log;
		host:   string &log;
		## One of "existing_mount", "new_mount" or "unmount".
		## "mount" implies that the disk was already mounted when the agent reported in.
		## "new_mount" implies that the disk was just mounted when the event was sent.
		## "umount" implies the disk was unmounted when the event was sent.
		action: string &log;
		path:   string &log;
	};
}

const mount_lookup = {
	[zeek_agent::INITIAL] = "existing_mount",
	[zeek_agent::ADD] = "new_mount",
	[zeek_agent::REMOVE] = "unmount",
};

event AgentMounts::change(result: zeek_agent::Result, path: string)
	{
	local info = Info($ts = network_time(),
	                  $host = result$host,
	                  $action = mount_lookup[result$utype],
	                  $path = path);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-mounts"]);

	local ev = zeek_agent::Query($ev=AgentMounts::change,
	                             $query="SELECT path FROM mounts",
	                             $utype=zeek_agent::BOTH);
	zeek_agent::subscribe(ev);
	}
