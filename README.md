
# About

This Zeek script framework communicates with the [Zeek
Agent](https://github.com/zeek/osquery-extension) to perform live
queries against the agent's tables and then incorporat the results
back into Zeek's processing & logging. In addition to tables built in,
the agent can connect to [osquery](https://osquery.io) to retrieve any
of the host data provided there.

*Note*: This framework is still a work in progress and expected to
change further in terms of API, functionality, and implementation.
It's not also not been fully "Zeekified" yet.

# Prerequisites

The framework requires Zeek 3.0, which you can download and install
per the instructions on the [Zeek web site](https://zeek.org/download).

You will also need to install the Zeek Agent itself, as well as
optionally osquery, according to [these
instructions](https://github.com/zeek/zeek-agent-framework).

# Installation

The easiest way to install the `zeek-agent` framework is through the
[Zeek package
manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).
If you have not installed the package manager yet, do that first:

    # pip install zkg
    # zkg autoconfig

    # zkg install zeek/zeek-agent-framework

Alternatively, you can clone the repository manually and copy it over
into Zeek's `site` folder:

    # git clone https://github.com/zeek/zeek-agent-framework
    # cp -a zeek-agent-framework/zeek-agent $(zeek-config --site_dir)

If you'd rather run it directly out of the local repository clone
(rather than `site`), set your `ZEEKPATH` accordingly:

    # export ZEEKPATH=<path/to/zeek-agent-framework>:$(zeek-config --zeekpath)

# Usage

Using any of the three installation methods above, you can now load
the framework when you start Zeek:

    # zeek zeek-agent

Once you start up any agents, you should start seeing a new Zeek log
file `zeek-agent.log` that records the hosts connecting to Zeek:

    # cat zeek-agent.log
    #fields    ts       source  peer        level   message
    1576768875.018249	local	BroMaster	info	Subscribing to bro announce topic /zeek/zeek-agent/bro_announce
    1576768875.018249	local	BroMaster	info	Subscribing to bro individual topic /zeek/zeek-agent/bro/C6EAF3CFDF46831E2D9103E5A1C48F78AD873A00#10223
    1576768877.709030	local	BroMaster	info	Incoming connection established from C6EAF3CFDF46831E2D9103E5A1C48F78AD873A3C#7503

You won't see much more at first as there's nothing sending queries to
the endhost yet. However, there's an additional set of scripts coming
with the framework that installs queries against selected tables and
turns the results into Zeek log files.

To enable the querying the agent's built-in tables (which are
currently all audit-based), load the `zeek-agent/tables` module:

    # zeek zeek-agent/tables

To enable these permanently, put `@load zeek-agent/tables` into your
`local.zeek` file.

Once enabled, you'll start seeing these additional Zeek log files:

- `agent-process_events.log`: Records processes running on the hosts, as reported by Linux's audit system.
- `agent-socket_events.log`: Records sockets being opened, as reported by Linux's audit system.

If you have osquery installed and built the Zeek Agent with
corresponding support, you can enable additional osquery-based tables
by loading `zeek-agent/tables/osquery`. You'll then start seeing:

- `agent-interface.log`: Records network interfaces added to the hosts
- `agent-listening_ports.log`: Records network ports listening for incoming connections.
- `agent-mounts.log`: Records devices being mounted.
- `agent-prcocesses.log`: Records new processes (non-evented, meaning short-lived instances may be missed)
- `agent-process_open_sockets`: Records sockets being opened (non-evented, meaning short-lived instances may be missed)
- `agent-users`: Records users being added to a host.

In addition to all these, there are two more logs recording Zeek Agent
activity once the framework is loaded:

- `zeek-agent-hosts.log`: Records the hosts connecting to Zeek with their subscriptions.
- `zeek-agent-logger.log`: Aggregates the agent-side logs, as also recorded by the Zeek Agent on the endhosts themselves.

# Credits

This Zeek framework is based on an earlier implementation by [Steffan
Haas](https://github.com/iBigQ), with recent work contributed by
[Corelight](https://www.corelight.com) and [Trail of
Bits](https://www.trailofbits.com).
