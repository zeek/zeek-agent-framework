module ZeekAgent;

export {
	## Subscribe to an event. Whenever an zeek-agent connects to us, we'll subscribe to all matching activity
	## from it.
	##
	## The query is an mandatory parameter and contains one query. It is send to the specified hosts
	## and the specified groups. If neither is given, the query is broadcasted to all hosts.
	##
	## q: The queries to subscribe to.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global insert_subscription: function(q: ZeekAgent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Unsubscribe from an events. This will get sent to all clients that are currently connected and would match
	## a similar subscribe call.
	##
	## The query is an mandatory parameter and contains one query. It is send to the specified hosts
	## and the specified groups. If neither is given, the query is broadcasted to all hosts.
	##
	## q: The queries to revoke.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global remove_subscription: function(q: ZeekAgent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Send a one-time query to all currently connected clients.
	##
	## The query is an mandatory parameter and contains one query. It is send to the specified hosts
	## and the specified groups. If neither is given, the query is broadcasted to all hosts.
	##
	## q: The queries to execute.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global insert_execution: function(q: ZeekAgent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Make subnets to be addressed by a group. Whenever an zeek-agent connects to us, we'll instruct it to join
	## the given group.
	##
	## range_list: the subnets that are addressed.
	## group: the group hosts should join.
	global insert_grouping: function(range_list: vector of subnet, group: string);
	
	## Make subnets to be no longer addressed by a group. This will get sent to all clients that are currently connected and would match
	## a similar join call
	##
	## range_list: the subnets that are addressed.
	## group: the group hosts should leave.
	global remove_grouping: function(range_list: vector of subnet, group: string);
	
	## Hook to retrieve the IP addresses of a host by its id
	##
	## host_id: The identifier of the host
	global getIPsOfHost: hook(host_id: string, addresses: vector of addr);
	
	## Peer Status of host
	##
	## host_id: The identifier of the host
	global isHostAlive: function(host_id: string): bool;
	
	# Internal record for tracking a subscription.
	type Subscription: record {
		query: ZeekAgent::Query;
		hosts: vector of string &default=vector();
		groups: vector of string &default=vector();
	};

	type Subscriptions: vector of Subscription;
	
	# Internal record for tracking groups
	type Grouping: record {
		group: string;
		ranges: vector of subnet &default=vector();
	};

	type Groupings: vector of Grouping;
}

# Internal vector of subscriptions
global subscriptions: Subscriptions;

# Internal vector of host groupins
global groupings: Groupings;

# Internal set for tracing client ids
global hosts: set[string];

# Internal set for groups of clients
global groups: set[string] = {ZeekAgent::HostBroadcastTopic};

# Internal table for tracking client (ids) and their respective groups
global host_groups: table[string] of vector of string;

# Internal mapping of broker id (peer_name) to zeek-agent id (host_id)
global peer_to_host: table[string] of string;

function insert_subscription(q: ZeekAgent::Query, host_list: vector of string, group_list: vector of string)
	{
	# Include new Subscription in the vector
	subscriptions += Subscription($query=q, $hosts=host_list, $groups=group_list);
	if ( |host_list| <= 1 && host_list[0] == "" &&
	     |group_list| <= 1 && group_list[0] == "" )
		{
		# To all if nothing specified
		ZeekAgent::send_subscribe(ZeekAgent::HostBroadcastTopic, q);
		}
	else
		{
		# To specific host
		for ( j in host_list )
			{
			if ( host_list[j] != "" )
				{
				ZeekAgent::send_subscribe(fmt("%s/%s", ZeekAgent::HostIndividualTopic,host_list[j]), q);
				}
			}
		
		# To specific group
		for ( j in group_list )
			{
			if ( group_list[j] != "" )
				{
				ZeekAgent::send_subscribe(fmt("%s/%s", ZeekAgent::HostGroupTopic,group_list[j]), q);
				}
			}
		}
	}

function remove_subscription(q: ZeekAgent::Query, host_list: vector of string, group_list: vector of string)
	{
	# Cancel internal subscription
	for ( j in subscriptions )
		{
		if ( ZeekAgent::same_event(subscriptions[j]$query, q) )
			{
			# Don't have a delete for vector, so set it to no-op by leaving the event empty.
			subscriptions[j]$query = Query($query="");
			}
		}
	
	#  Send unsubscribe
	if ( |host_list| <= 1 && host_list[0] == "" && 
	     |group_list| <= 1 && group_list[0] == "" )
		{
		# To all if nothing specified
		ZeekAgent::send_unsubscribe(ZeekAgent::HostBroadcastTopic, q);
		}
	else
		{
		# To specific host
		for ( j in host_list )
			{
			if ( host_list[j] != "" )
				{
				ZeekAgent::send_unsubscribe(fmt("%s/%s", ZeekAgent::HostIndividualTopic,host_list[j]), q);
				}
			}
			
		# To specific group
		for ( j in group_list )
			{
			if ( group_list[j] != "" )
				{
				ZeekAgent::send_unsubscribe(fmt("%s/%s", ZeekAgent::HostGroupTopic,group_list[j]), q);
				}
			}
		}
	}

function insert_execution(q: ZeekAgent::Query, host_list: vector of string, group_list: vector of string)
	{
	if ( |host_list| <= 1 && host_list[0] == "" && 
	     |group_list| <= 1 && group_list[0] == "" )
		{
		# To all if nothing specified
		ZeekAgent::send_execute(ZeekAgent::HostBroadcastTopic, q);
		}
	else
		{
		# To specific host
		for ( j in host_list )
			{
			if ( host_list[j] != "" )
				{
				ZeekAgent::send_execute(fmt("%s/%s", ZeekAgent::HostIndividualTopic, host_list[j]), q);
				}
			}
		
		# To specific group
		for ( j in group_list )
			{
			if ( group_list[j] != "" )
				{
				ZeekAgent::send_execute(fmt("%s/%s", ZeekAgent::HostGroupTopic, group_list[j]), q);
				}
			}
		}
	}

function insert_grouping(range_list: vector of subnet, group: string)
	{
	# Include new Grouping in the vector
	groupings += Grouping($group=group, $ranges=range_list);
	
	for ( host in hosts )
		{
		local host_topic = fmt("%s/%s", ZeekAgent::HostIndividualTopic,host);
		local skip_host = F;
		
		local hostIPs: vector of addr;
		hook ZeekAgent::getIPsOfHost(host, hostIPs);
		for ( j in hostIPs )
			{
			if ( skip_host )
				break;
			
			for ( i in range_list )
				{
				if ( hostIPs[j] in range_list[i] )
					{
					local new_group = group;
					ZeekAgent::log("info", host, fmt("Joining new group %s", new_group));
					ZeekAgent::send_join(host_topic, new_group);
					host_groups[host] += new_group;
					add groups[new_group];
					skip_host = T;
					break;
					}
				}
			}
		}
	}

function remove_grouping(range_list: vector of subnet, group: string)
	{
	#TODO notImplemented
	}

function isHostAlive(host_id: string): bool
	{
	return host_id in hosts;
	}
