#!/usr/bin/env python3

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    StringTable,
)


def discover_win_defender(section: StringTable) -> DiscoveryResult:
    yield Service(item="Windows Defender")


def check_win_defender(item: str, params, section: StringTable) -> CheckResult:
    ignore_rt = params['ignore_realtime']
    av_age_warn = params['av_definition_age'][1][0]
    av_age_crit = params['av_definition_age'][1][1]
    for rtprot_status, as_age, av_age, am_productversion, am_engineversion in section:
        as_age = int((as_age.replace(" ", "")), 10)
        av_age = int((av_age.replace(" ", "")), 10)
        age = max(av_age, as_age) # just use the oldest definition
        rtprot_status = rtprot_status.strip()
        if age > av_age_crit:
            mystate=State.CRIT
            age_msg=f"AV database age: {age} days(!!)"
        elif age > av_age_warn:
            mystate=State.WARN
            age_msg=f"AV database age: {age} days(!)"
        else:
            mystate=State.OK
            age_msg=f"AV database age: {age} days"

        if rtprot_status == "True":
            rt_msg=f"RealTime Protection: Enabled"
        else:
            if ignore_rt == True:
                rt_msg=f"RealTime Protection: Disabled (ignored)"
            else:
                mystate=State.CRIT
                rt_msg=f"RealTime Protection: Disabled(!!)"



        yield Result(
            state=mystate,
            summary=f"{rt_msg}, {age_msg}, AMProductVersion: {am_productversion}, AMEngineVersion: {am_engineversion}",
        )
        return


check_plugin_win_defender = CheckPlugin(
    name="win_defender",
    service_name="%s",
    discovery_function=discover_win_defender,
    check_function=check_win_defender,
    check_default_parameters = {'av_definition_age': ('fixed', (1.0, 3.0)), 'ignore_realtime': False},
    check_ruleset_name = "win_defender",

)


def parse(string_table: StringTable) -> StringTable:
    return string_table


agent_section_win_defender = AgentSection(
    name="win_defender",
    parse_function=parse,
)
