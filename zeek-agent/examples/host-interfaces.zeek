##! Get the list of interfaces on a system.

@load zeek-agent

module HostInterfaces;

event HostInterfaces::found(result: zeek_agent::Result, interface: string, address: string)
	{
	print fmt("%s: interface: %s  address: %s", result$host, interfaces, address);
	}

event zeek_init() &priority=10
	{
	local query = zeek_agent::Query($ev=HostInterfaces::found,
	                                $query="SELECT interface, address FROM interface_addresses;",
	                                $utype=zeek_agent::BOTH);
	zeek_agent::subscribe(query);
	}
