@load base/frameworks/cluster

@load ./framework_commons
@load ./hosts_send
@load ./osquery_subscriptions

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./osquery_hosts
@load ./bro_backend
@load ./osquery_framework
@endif
