"""AWS Network Firewall rule evaluation.

Given a flow (source IP, destination IP, port, protocol), read the firewall
policy and its rule groups and say whether the flow is allowed or blocked, and
by which rule. This complements the reachability trace: the trace detects when
traffic is routed through an inspection VPC, and this checks whether the firewall
policy actually permits it.

What it evaluates precisely: stateless rules, structured stateful rules (the
5-tuple Header form), domain allow/deny lists (named, not matched to an IP), and
the stateless and stateful default actions. For a stateful rule group written as
a raw Suricata string, it parses the rule header (action, protocol, source,
ports, destination) best effort and flags that the rule options (flow, content,
and so on) are not evaluated, rather than asserting a verdict it cannot prove.

    python tracerai/tools/firewall.py
"""

import ipaddress
import re

import boto3

from tracerai.aws_session import get_session

_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
_NUM_PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}


def _norm(account_id, me):
    return None if (not account_id or account_id == me) else account_id


def _ip_in(ip, cidr):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _addr_match(ip, token, ipsets=None):
    """A Network Firewall / Suricata address token: 'any', a CIDR, an IP, or a
    Suricata variable like $HOME_NET resolved from the rule group's IP sets."""
    if not token or token.lower() == "any":
        return True
    if token.startswith("$"):
        name = token[1:]
        defs = (ipsets or {}).get(name)
        if defs is None:
            return False  # undefined variable; caller notes it
        return any(_addr_match(ip, c) for c in defs)
    token = token.strip("[]")
    for part in token.split(","):
        part = part.strip()
        if part.startswith("!"):
            continue  # negation: skip (best effort), handled as non-match
        if "/" not in part:
            part = part + "/32"
        if _ip_in(ip, part):
            return True
    return False


def _port_match(port, token, portsets=None):
    """A port token: 'any', 'N', a range 'N:M', or a Suricata variable."""
    if port is None or not token or token.lower() == "any":
        return True
    if token.startswith("$"):
        defs = (portsets or {}).get(token[1:])
        if defs is None:
            return False
        return any(_port_match(port, p) for p in defs)
    token = token.strip("[]")
    for part in token.split(","):
        part = part.strip()
        if ":" in part:
            lo, hi = part.split(":", 1)
            lo = int(lo) if lo else 0
            hi = int(hi) if hi else 65535
            if lo <= port <= hi:
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def _proto_match(proto, token):
    if not token or token.lower() in ("any", "ip"):
        return True
    t = token.lower()
    return t == proto.lower() or _NUM_PROTO.get(t) == proto.lower()


def _eval_stateless(rules, src, dst, port, proto):
    """Return (action, rule) for the first stateless rule that matches, by
    priority, or (None, None)."""
    pnum = _PROTO_NUM.get(proto.lower())
    for pr, rule in sorted(rules, key=lambda x: x[0]):
        m = rule.get("RuleDefinition", {}).get("MatchAttributes", {})
        srcs = [s["AddressDefinition"] for s in m.get("Sources", [])]
        dsts = [d["AddressDefinition"] for d in m.get("Destinations", [])]
        dports = m.get("DestinationPorts", [])
        protos = m.get("Protocols", [])
        if srcs and not any(_ip_in(src, c) for c in srcs):
            continue
        if dsts and not any(_ip_in(dst, c) for c in dsts):
            continue
        if protos and pnum not in protos:
            continue
        if dports and not any(p["FromPort"] <= (port or 0) <= p["ToPort"] for p in dports):
            continue
        actions = rule["RuleDefinition"].get("Actions", [])
        act = next((a for a in actions if a.startswith("aws:")), actions[0] if actions else None)
        return act, {"priority": pr, "actions": actions}
    return None, None


def _parse_suricata(line):
    """Parse a Suricata rule header: action proto src sport dir dst dport (opts)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    head = line.split("(", 1)[0].strip()
    parts = head.split()
    if len(parts) < 7:
        return None
    return {"action": parts[0].lower(), "protocol": parts[1], "source": parts[2],
            "source_port": parts[3], "direction": parts[4], "destination": parts[5],
            "destination_port": parts[6], "raw": line}


def _match_stateful_header(h, src, dst, port, proto, ipsets=None, portsets=None):
    """Does a structured or parsed-Suricata header match the flow (forward)?"""
    if not _proto_match(proto, h.get("Protocol") or h.get("protocol", "")):
        return False
    s = h.get("Source") or h.get("source", "any")
    d = h.get("Destination") or h.get("destination", "any")
    dp = h.get("DestinationPort") or h.get("destination_port", "any")
    if not _addr_match(src, s, ipsets) or not _addr_match(dst, d, ipsets):
        return False
    if not _port_match(port, dp, portsets):
        return False
    return True


def _rule_variables(rg):
    """Extract IP-set and port-set variable maps from a rule group's
    RuleVariables so Suricata-style $HOME_NET tokens can be resolved."""
    rv = rg.get("RuleVariables") or {}
    ipsets = {k: v.get("Definition", []) for k, v in (rv.get("IPSets") or {}).items()}
    portsets = {k: v.get("Definition", []) for k, v in (rv.get("PortSets") or {}).items()}
    return ipsets, portsets


def _unresolved_vars(header, ipsets, portsets):
    """Return the $variables referenced by a header that are not defined in the
    rule group's variable sets, so the caller can flag an incomplete evaluation."""
    missing = []
    for key, sets in (("source", ipsets), ("destination", ipsets),
                      ("source_port", portsets), ("destination_port", portsets)):
        tok = header.get(key, "")
        if isinstance(tok, str) and tok.startswith("$") and tok[1:] not in (sets or {}):
            missing.append(tok)
    return missing


def check_firewall_rules(src_ip: str, dst_ip: str, port: int, protocol: str = "tcp",
                         region: str = None, account_id: str = None,
                         firewall_name: str = None, firewall_arn: str = None) -> dict:
    """Evaluate whether an AWS Network Firewall allows a flow.

    Finds the firewall (by name or arn, or the only one in the region), reads its
    policy and rule groups, and reports whether src_ip can reach dst_ip on the
    port and protocol, naming the rule and action. account_id reads another
    account via the read-only role.
    """
    if not region:
        return {"needs_region": True}
    me = boto3.client("sts").get_caller_identity()["Account"]
    try:
        nf = get_session(account_id=_norm(account_id, me), region=region).client(
            "network-firewall", region_name=region)
    except Exception as e:
        return {"region": region, "account_id": account_id, "error": str(e)}

    if not firewall_arn and not firewall_name:
        fws = nf.list_firewalls().get("Firewalls", [])
        if not fws:
            return {"region": region, "note": "no AWS Network Firewall found in this account/region"}
        if len(fws) > 1:
            return {"region": region, "needs_firewall": True,
                    "firewalls": [f["FirewallName"] for f in fws]}
        firewall_arn = fws[0]["FirewallArn"]

    kw = {"FirewallArn": firewall_arn} if firewall_arn else {"FirewallName": firewall_name}
    fw = nf.describe_firewall(**kw)["Firewall"]
    policy = nf.describe_firewall_policy(FirewallPolicyArn=fw["FirewallPolicyArn"])["FirewallPolicy"]
    rule_order = (policy.get("StatefulEngineOptions") or {}).get("RuleOrder", "DEFAULT_ACTION_ORDER")

    notes, steps = [], []
    verdict = matched = None

    # 1. Stateless rules.
    stateless = []
    for ref in sorted(policy.get("StatelessRuleGroupReferences", []), key=lambda r: r.get("Priority", 0)):
        rg = nf.describe_rule_group(RuleGroupArn=ref["ResourceArn"])["RuleGroup"]
        for r in rg["RulesSource"].get("StatelessRulesAndCustomActions", {}).get("StatelessRules", []):
            stateless.append((r.get("Priority", 0), r))
    act, rule = _eval_stateless(stateless, src_ip, dst_ip, port, protocol)
    to_stateful = False
    if act == "aws:pass":
        verdict, matched = "allowed", {"engine": "stateless", "action": "pass", "rule": rule}
    elif act == "aws:drop":
        verdict, matched = "blocked", {"engine": "stateless", "action": "drop", "rule": rule}
    elif act == "aws:forward_to_sfe":
        to_stateful = True
        steps.append("matched a stateless forward-to-stateful rule")
    else:
        sd = policy.get("StatelessDefaultActions", [])
        steps.append(f"no stateless rule matched; stateless default = {sd}")
        if "aws:drop" in sd:
            verdict = "blocked"; matched = {"engine": "stateless-default", "action": "drop"}
        elif "aws:pass" in sd:
            verdict = "allowed"; matched = {"engine": "stateless-default", "action": "pass"}
        else:
            to_stateful = "aws:forward_to_sfe" in sd

    # 2. Stateful rules.
    if verdict is None and to_stateful:
        matches = []  # (action, source, detail)
        for ref in policy.get("StatefulRuleGroupReferences", []):
            arn = ref["ResourceArn"]
            name = arn.split("/")[-1]
            if ":aws-managed:" in arn:
                notes.append(f"managed rule group {name} (AWS-maintained threat signatures) "
                             "was not evaluated; its contents are not readable via DescribeRuleGroup")
                continue
            try:
                rg = nf.describe_rule_group(RuleGroupArn=arn)["RuleGroup"]
            except Exception as e:
                if "Managed rule groups" in str(e) or "InvalidRequest" in type(e).__name__:
                    notes.append(f"managed rule group {name} (AWS-maintained threat signatures) "
                                 "was not evaluated; its contents are not readable via DescribeRuleGroup")
                    continue
                raise
            ipsets, portsets = _rule_variables(rg)
            src = rg["RulesSource"]
            if src.get("StatefulRules"):
                for r in src["StatefulRules"]:
                    if _match_stateful_header(r["Header"], src_ip, dst_ip, port, protocol, ipsets, portsets):
                        matches.append((r["Action"].lower(), name, dict(r["Header"])))
            elif src.get("RulesString"):
                for line in src["RulesString"].splitlines():
                    p = _parse_suricata(line)
                    if not p:
                        continue
                    missing = _unresolved_vars(p, ipsets, portsets)
                    if _match_stateful_header(p, src_ip, dst_ip, port, protocol, ipsets, portsets):
                        matches.append((p["action"], name, {"suricata": p["raw"]}))
                        note = (f"Suricata rule in {name} matched on header only; its options "
                                "(flow, content, etc.) were not evaluated")
                        if missing:
                            note += f"; unresolved variables {missing} were treated as non-matching"
                        notes.append(note)
                    elif missing:
                        notes.append(f"Suricata rule in {name} references unresolved variables "
                                     f"{missing}; it could not be evaluated for this flow")
            elif src.get("RulesSourceList"):
                rsl = src["RulesSourceList"]
                notes.append(f"{name} is a domain {rsl.get('GeneratedRulesType')} "
                             f"({len(rsl.get('Targets', []))} targets); domain rules match by name, "
                             "not by IP, so this flow was not evaluated against it")

        # Resolve the matches into a verdict.
        drops = [m for m in matches if m[0] in ("drop", "reject")]
        passes = [m for m in matches if m[0] == "pass"]
        if rule_order == "STRICT_ORDER":
            first = matches[0] if matches else None
            if first and first[0] in ("drop", "reject"):
                verdict, matched = "blocked", {"engine": "stateful", "action": first[0], "group": first[1], "rule": first[2]}
            elif first and first[0] == "pass":
                verdict, matched = "allowed", {"engine": "stateful", "action": "pass", "group": first[1], "rule": first[2]}
        else:  # action order: pass evaluated before drop
            if passes:
                verdict, matched = "allowed", {"engine": "stateful", "action": "pass", "group": passes[0][1], "rule": passes[0][2]}
            elif drops:
                verdict, matched = "blocked", {"engine": "stateful", "action": "drop", "group": drops[0][1], "rule": drops[0][2]}

        if verdict is None:
            sd = policy.get("StatefulDefaultActions", [])
            steps.append(f"no stateful rule matched; stateful default = {sd}")
            if any("drop" in a for a in sd):
                verdict, matched = "blocked", {"engine": "stateful-default", "action": sd}
            else:
                verdict, matched = "allowed", {"engine": "stateful-default", "action": sd or ["(none; forwarded)"]}

    return {
        "region": region, "account_id": account_id,
        "firewall": fw.get("FirewallName"), "vpc_id": fw.get("VpcId"),
        "flow": {"src": src_ip, "dst": dst_ip, "port": port, "protocol": protocol},
        "rule_order": rule_order,
        "stateless_default": policy.get("StatelessDefaultActions"),
        "stateful_default": policy.get("StatefulDefaultActions"),
        "verdict": verdict or "undetermined",
        "matched": matched,
        "steps": steps,
        "notes": notes,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(check_firewall_rules("172.20.1.10", "172.21.1.10", 443, "tcp",
                                           region="eu-west-1"), indent=2, default=str))
