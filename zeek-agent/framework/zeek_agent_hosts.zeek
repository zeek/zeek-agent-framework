@load base/frameworks/broker
@load base/frameworks/logging

module ZeekAgent;

export {
	## Checks the new ip address of the given host against the groupings and makes it to join respective groups.
	##
	## host_id: the id of the host
	## ip: the new ip address of the host
	global new_host_address: function(host_id: string, ip: addr): vector of string;
	
	## Checks the new group of the given host against the subscriptions and makes it to schedule respective queries.
	##
	## host_id: the id of the host
	## group: the new group of the host
	global new_host_group: function(host_id: string, group: string);
	
	## Hook that can be called by others to indicate that an IP address was added to a host
	global add_host_addr: hook(host_id: string, ip: addr);
	
	## Hook that can be called by others to indicate that an IP address was removed from a host
	global remove_host_addr: hook(host_id: string, ip: addr);
}

global connect_balance: table[string] of count;

## Sends current subscriptions to the new zeek-agent (given by client_id).
##
## This checks if any subscription matches the host restriction (or broadcast)
##
## client_id: The client ID
function send_subscriptions_new_host(host_id: string)
	{
	local host_topic = fmt("%s/%s", ZeekAgent::HostIndividualTopic, host_id);
	for ( i in subscriptions )
		{
		local s = subscriptions[i];
		local skip_subscription = F;
		
		if ( ! s$query?$ev )
			{
			# Skip Subscription because it was deleted";
			next;
			}
		
		# Check for broadcast
		local sub_hosts: vector of string = s$hosts;
		local sub_groups: vector of string = s$groups;
		if ( |sub_hosts| <= 1 && sub_hosts[0] == "" &&
		     |sub_groups| <= 1 && sub_groups[0] == "" )
			 {
			# To all if nothing specified
			ZeekAgent::send_subscribe(host_topic, s$query);
			skip_subscription = T;
			}
			
		if ( skip_subscription )
			next;
		
		# Check the hosts in the Subscriptions
		for ( j in sub_hosts )
			{
			local sub_host = sub_hosts[j];
			if ( host_id == sub_host )
				{
			    ZeekAgent::send_subscribe(host_topic, s$query);
			    skip_subscription = T;
			    break;
				}
			}
			
		if ( skip_subscription )
		    next;
		
		# Check the groups in the Subscriptions
		for ( j in host_groups[host_id] )
		{
			local host_group = host_groups[host_id][j];
			for ( k in sub_groups )
				{
				local sub_group = sub_groups[k];
				if ( |host_group| <= |sub_group| && 
				     host_group == sub_group[:|host_group|] )
					{
					ZeekAgent::send_subscribe(host_topic, s$query);
					skip_subscription = T;
					break;
					}
					}
			if ( skip_subscription )
				break;
			}
		if ( skip_subscription )
			next;
		}
	}


## Checks for subscriptions that match the recently joined group
function send_subscriptions_new_group(host_id: string, group: string)
	{
	local host_topic = fmt("%s/%s", ZeekAgent::HostIndividualTopic, host_id);
	for ( i in subscriptions )
		{
		local s = subscriptions[i];

		if ( ! s$query?$ev )
			{
			# Skip Subscription because it was deleted";
			next;
			}
		
		# Check the groups in the Subscriptions
		local sub_groups: vector of string = s$groups;
		for ( k in sub_groups )
			{
			local sub_group = sub_groups[k];
			if ( group == sub_group )
				{
				if ( |group| <= |sub_group| && group == sub_group[:|group|] )
					{
					ZeekAgent::send_subscribe(host_topic, s$query);
					break;
					}
				}
			}
		}
	}

## Checks for groups that match the recently added address
function send_joins_new_address(host_id: string, ip: addr)
	{
	local host_topic = fmt("%s/%s", ZeekAgent::HostIndividualTopic,host_id);
	local new_groups: vector of string;
	for ( i in groupings )
		{
		local c = groupings[i];
		
		if ( c$group == "" )
			{
			# Skip because Collection was deleted
			next;
			}
		
		for ( k in c$ranges )
			{
			local range = c$ranges[k];
			if ( ip in range )
				{
				local new_group: string = c$group;
				ZeekAgent::log("info", host_id, fmt("joining new group %s", new_group));
				ZeekAgent::send_join( host_topic, new_group );
				host_groups[host_id] += new_group;
				new_groups += new_group;
				break;
				}
			}
		}

	for ( g in new_groups )
		{
		local group = new_groups[g];
		send_subscriptions_new_group(host_id, group);
		}
	}

hook ZeekAgent::add_host_addr(host_id: string, ip: addr)
	{
	send_joins_new_address(host_id, ip);
	}

hook ZeekAgent::add_host_addr(host_id: string, ip: addr)
	{
	#TODO
	}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event ZeekAgent::host_new(peer_name: string, host_id: string, group_list: vector of string, zeek_agent_version: string, zeek_agent_edition: string)
	{
	# 'standalone' edition only comes with built-in tables
	# 'osquery' edition can export additional tables IF osquery is connected
	ZeekAgent::log("info", host_id, fmt("Zeek Agent v%s (%s) host connected (%s announced as: %s)", zeek_agent_version, zeek_agent_edition, peer_name, host_id));
	
	#TODO: Do not load the osquery tables if the client edition is set to 'standalone'
	# ...
	
	# Internal client tracking
	peer_to_host[peer_name] = host_id;
	add hosts[host_id];
	for ( i in group_list )
		{
		add groups[group_list[i]];
		}
	
	host_groups[host_id] = group_list;
	#TODO: that is only the topic prefix
	host_groups[host_id] += ZeekAgent::HostIndividualTopic;
	
	# Make host to join group and to schedule queries
	send_subscriptions_new_host(host_id);
	
	# raise event for new host
	event ZeekAgent::host_connected(host_id);
	}

function _reset_peer(peer_name: string)
	{
	if ( peer_name !in peer_to_host )
		return;
	
	local host_id: string = peer_to_host[peer_name];
	ZeekAgent::log("info", host_id, "Zeek Agent host disconnected");
	
	# Check if anyone else is left in the groups
	local others_groups: set[string];
	# Collect set of groups others are in
	for ( i in host_groups )
		{
		if ( i != host_id )
			{
			for ( j in host_groups[i] )
				{
				add others_groups[host_groups[i][j]];
				}
			}
		}
	
	# Remove group if no one else has the group
	for ( k in host_groups[host_id] )
		{
		local host_g: string = host_groups[host_id][k];
		if ( host_g !in others_groups )
			{
			delete groups[host_g];
			}
		}
	}

function _remove_peer(peer_name: string)
	{
	if ( peer_name !in peer_to_host )
		return;
	
	local host_id: string = peer_to_host[peer_name];
	delete peer_to_host[peer_name];
	
	# Internal client tracking
	delete hosts[host_id];
	delete host_groups[host_id];
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name = endpoint$id;
	
	# Connect balance
	if ( peer_name !in connect_balance )
		{
		connect_balance[peer_name] = 0;
		}
	
	if ( connect_balance[peer_name] > 0 )
		{
		_reset_peer(peer_name);
		}
	connect_balance[peer_name] += 1;
	}


event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name = endpoint$id;
	
	if ( peer_name in peer_to_host )
		{
		local host_id: string = peer_to_host[peer_name];
		ZeekAgent::log("info", host_id, "Zeek Agent host disconnected");
		
		# raise event for the disconnected host
		event ZeekAgent::host_disconnected(host_id);
		}
	
	# Connect balance
	if ( connect_balance[peer_name] == 1 )
		{
		_reset_peer(peer_name);
		_remove_peer(peer_name);
		}
	connect_balance[peer_name] -= 1;
	
	if ( connect_balance[peer_name] == 0 )
		{
		delete connect_balance[peer_name];
		}
	}

event zeek_init()
	{
	# Listen on host announce topic
	local topic: string = ZeekAgent::HostAnnounceTopic;
	ZeekAgent::log_local("info", fmt("Subscribing to host announce topic %s", topic));
	Broker::subscribe(topic);
	} 
@endif
