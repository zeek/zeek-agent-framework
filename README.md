
# About

This Zeek script framework communicates with the [Zeek
Agent](https://github.com/zeek/zeek-agent) to perform live
queries against the agent's tables and then incorporate the results
back into Zeek's processing & logging. In addition to tables built in,
the agent can connect to [Osquery](https://osquery.io) to retrieve any
of the host data provided there.

*Note*: This framework is still a work in progress and expected to
change further in terms of API, functionality, and implementation.

# Prerequisites

The framework requires Zeek 3.0+, which you can download and install
per the instructions on the [Zeek web site](https://zeek.org/download).

You will also need to install the Zeek Agent itself, as well as
optionally Osquery, according to [these
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
    1576768875.018249	local	ZeekMaster	info	Subscribing to zeek announce topic /zeek/zeek-agent/zeek_announce
    1576768875.018249	local	ZeekMaster	info	Subscribing to zeek individual topic /zeek/zeek-agent/zeek/C6EAF3CFDF46831E2D9103E5A1C48F78AD873A00#10223
    1576768877.709030	local	ZeekMaster	info	Incoming connection established from C6EAF3CFDF46831E2D9103E5A1C48F78AD873A3C#7503

You won't see much more at first as there's nothing sending queries to
the endhost yet. Check out the `examples/` directory for scripts that
are using the built in (currently Linux audit based) and Osquery based
functionality.

# Examples

The framework ships with examples that currently use Osquery derived tables
and Linux auditd based tables.  Use the follow lines to load all of the
associated examples.

To load the Osquery examples:

    @load zeek-agent/examples/osquery

To load the auditd examples:

    @load zeek-agent/examples/auditd

To load the EndpointSecurity (MacOS) examples:

    @load zeek-agent/examples/endpointsecurity


# Credits

This Zeek framework is based on an earlier implementation by [Steffen
Haas](https://github.com/iBigQ), with recent work contributed by
[Corelight](https://www.corelight.com) and [Trail of
Bits](https://www.trailofbits.com).
