#! Logs interfaces activity.

module osquery::logging::table_interfaces;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
		interface: string &log;
		mac: string &log;
		ip: string &log;
		mask: string &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::interface_added(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string) {
        local info: Info = [
		$t=t,
		$host=host_id,
		$interface=interface,
		$mac=mac,
		$ip=ip,
		$mask=mask
        ];

        Log::write(LOG, info);
}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-interfaces"]);
}
