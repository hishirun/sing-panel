"""Non-overridable isolation between proxy customers and internal services.

These are destination checks on accepted proxy traffic. They do not change the
administrator's upstream server addresses or the panel's own API connections.
"""
import ipaddress


_V4_CIDRS = (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
)
BLOCKED_CIDRS = _V4_CIDRS + (
    '::/96', 'fc00::/7', 'fe80::/10', 'ff00::/8',
) + tuple('::ffff:' + str(network.network_address) + '/' + str(96 + network.prefixlen)
          for network in map(ipaddress.ip_network, _V4_CIDRS))
_NETWORKS = tuple(map(ipaddress.ip_network, BLOCKED_CIDRS))


def protected_ports(document):
    """Statistics has no authentication; reject its destination port outright."""
    ports = {18889}
    experimental = document.get('experimental', {})
    for kind, key in (('v2ray_api', 'listen'), ('clash_api', 'external_controller')):
        address = experimental.get(kind, {}).get(key, '')
        try:
            port = int(address.rsplit(':', 1)[1])
        except (AttributeError, IndexError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.add(port)
            # The runtime adds the default Clash controller after compilation.
            if kind == 'v2ray_api' and port < 65535:
                ports.add(port + 1)
    return sorted(ports)


def blocked_destination(destination, port=None, document=None):
    """True/False for literal IPs; None for domains requiring actual DNS facts."""
    if port is not None and port in protected_ports(document or {}):
        return True
    value = str(destination).strip().strip('[]').lower().rstrip('.')
    if value == 'localhost' or value.endswith('.localhost'):
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return any(address.version == network.version and address in network for network in _NETWORKS)


def protection_rules(document):
    """The mandatory prefix; no production setting can disable these rules."""
    return [
        {'port': protected_ports(document), 'action': 'reject'},
        {'ip_cidr': list(BLOCKED_CIDRS), 'action': 'reject'},
        {'action': 'resolve', 'strategy': 'prefer_ipv4'},
        {'ip_cidr': list(BLOCKED_CIDRS), 'action': 'reject'},
    ]


def protect(document):
    route = document.setdefault('route', {})
    prefix = protection_rules(document)
    rules = list(route.get('rules', []))
    if rules[:len(prefix)] == prefix:
        rules = rules[len(prefix):]
    # A later resolve could replace the already checked addresses with a
    # private answer for a zero-TTL/rebinding domain. Every rule can reuse the
    # initial resolution, and direct dialing consumes those pinned addresses.
    rules = [rule for rule in rules if rule.get('action') != 'resolve']
    route['rules'] = prefix + rules
    return document
