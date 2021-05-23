import ipaddress
import logging
import os
import sys
import time

from configparser import ConfigParser
from dataclasses import dataclass, field, asdict

import click
import jinja2
import unificontrol

ENV_PREFIX = "UNIFILOCAL_"
ENV_FILE_SUFFIX = "__FILE"

DEFAULT_DOMAIN = "localdomain"
DEFAULT_INVALID_HOSTS = "localhost"
DEFAULT_UNIFI_SITE = "default"
DEFAULT_UNIFI_PORT = 8443
DEFAULT_NETWORKS = "0.0.0.0/0,::0/0"

logging.basicConfig()
logger = logging.getLogger(__name__ if __name__ != "__main__" else "unifilocal")


class TypeMC(type):
    def __repr__(self):
        return self.__name__


class Type(metaclass=TypeMC):
    pass


class Reservation(Type):
    base_priority: int = 0


class Lease(Type):
    base_priority: int = 2


@dataclass(order=True)
class ZoneRecord:
    host: str
    ip: str
    mac: str
    type: Type = field(compare=False)
    priority: int = field(compare=False)

    @property
    def effective_priority(self):
        return self.priority + self.type.base_priority


@dataclass
class Host:
    mac: str
    ip: str
    names: list[str]
    type: Type


def compare_zones(zone1: list, zone2: list):
    j = 0
    changed = False

    for i, this in enumerate(zone1):
        for that in zone2[j:]:
            j += 1
            if (this["host"], this["ip"]) == (that["host"], that["ip"]):
                break
            changed = True
            if this["host"] == that["host"]:
                logger.warning("Changed: %s -> %s", this, that)
                break
            elif this["host"] < that["host"]:
                logger.warning("Removed: %s", this)
                j -= 1
                break
            else:
                logger.warning("Added: %s", that)

    return changed


def configure_environment(ctx):
    options = {}

    for key, value in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        if key.endswith(ENV_FILE_SUFFIX):
            value = open(value).read().strip()
            key = key[: -len(ENV_FILE_SUFFIX)]
        key = key[len(ENV_PREFIX) :].lower()
        options[key] = value

    if not ctx.default_map:
        ctx.default_map = {}
    ctx.default_map.update(options)


def configure(ctx, param, filename):
    configure_environment(ctx)

    filename = filename or ctx.default_map.get("config")
    if filename:
        parser = ConfigParser()
        with open(filename) as config:
            parser.read_string("[options]\n" + config.read())
        try:
            options = {k.replace("-", "_"): v for k, v in parser["options"].items()}
        except KeyError:
            options = {}

        if not ctx.default_map:
            ctx.default_map = {}
        ctx.default_map.update(options)

    for param in ctx.command.params:
        if isinstance(param, click.Option) and param.required and param.name in ctx.default_map:
            param.required = False


@click.command()
@click.version_option()
@click.option(
    "-c",
    "--config",
    help="Config file to read all other options",
    type=click.Path(dir_okay=False),
    callback=configure,
    is_eager=True,
    expose_value=False,
    metavar="CONFIG",
)
@click.option("-d", "--domain", default=DEFAULT_DOMAIN, show_default=True, help="Domain to generate", metavar="DOMAIN")
@click.option(
    "--invalid",
    default=DEFAULT_INVALID_HOSTS,
    help="List of invalid hosts that will be ignored (comma separated)",
    show_default=True,
    metavar="INVALID[,INVALID...]",
)
@click.option(
    "-n",
    "--networks",
    default=DEFAULT_NETWORKS,
    help="Allowed networks, comma separated",
    show_default=True,
    metavar="NETWORK[,NETWORK...]",
)
@click.option("-h", "--unifi-host", required=True, help="HOST[:PORT] of the Unifi controller", metavar="HOST[:PORT]")
@click.option("-u", "--unifi-user", required=True, help="Username to connect to Unifi controller", metavar="USER")
@click.option("-p", "--unifi-password", required=True, help="Password to connect to Unifi controller", metavar="PASSWORD")
@click.option("-s", "--unifi-site", default=DEFAULT_UNIFI_SITE, help="Managed Unifi site", show_default=True, metavar="SITE")
@click.option("-t", "--template", required=True, help="Template to generate the zone file", metavar="TEMPLATE")
@click.option("-i", "--interval", help="How often should the zone file be generated in seconds", type=int)
@click.option(
    "-o", "--output", default="-", help="Output zone file", type=click.Path(dir_okay=False, writable=True), show_default=True
)
@click.option(
    "-l",
    "--log-level",
    default="WARNING",
    help="Log level",
    type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], case_sensitive=False),
    show_default=True,
)
def main(
    domain: str,
    invalid: list[str],
    networks: str,
    unifi_host: str,
    unifi_site: str,
    unifi_user: str,
    unifi_password: str,
    template: str,
    interval: int,
    output: str,
    log_level: str,
    **kwargs
):
    logging.getLogger().setLevel(getattr(logging, log_level, None))

    if ":" in unifi_host:
        unifi_host, unifi_port = unifi_host.split(":", 1)
    else:
        unifi_port = DEFAULT_UNIFI_PORT

    invalid = set([x.strip() for x in invalid.split(",")])
    zone = []
    unifi = None
    networks = [ipaddress.ip_network(network.strip(), strict=True) for network in networks.split(",")]

    while True:
        if not unifi:
            try:
                unifi = unificontrol.UnifiClient(
                    host=unifi_host, port=unifi_port, username=unifi_user, password=unifi_password, site=unifi_site
                )
                unifi.login()
            except unificontrol.exceptions.UnifiTransportError:
                logger.exception("Error logging into the Unifi controller. Bad username/password?")
                sys.exit()

        try:
            new_zone = [{**asdict(x), "type": repr(x.type)} for x in sorted(get_unifi_data(unifi, invalid, domain, networks))]
            for subsystem in unifi.list_health():
                if subsystem.get("subsystem") == "wan":
                    wan_ip = ipaddress.ip_address(subsystem.get("wan_ip"))
        except unificontrol.exceptions.UnifiError:
            unifi = None
            new_zone = []

        if new_zone and (not zone or (compare_zones(zone, new_zone))):
            zone = new_zone
            atomic = True if os.path.isfile(output) else False
            with click.open_file(output, "w", atomic=atomic) as f:
                f.write(
                    jinja2.Template(open(template).read()).render(
                        serial=str(int(time.time())), domain=domain, zone=zone, wan=str(wan_ip)
                    )
                )

        if interval is None:
            break

        time.sleep(interval)


def get_unifi_data(unifi: unificontrol.UnifiClient, invalid: list[str], domain: str, networks: list):
    hosts = []

    hosts.extend(
        [
            Host(x.get("mac"), x.get("fixed_ip"), (x.get("name"), x.get("hostname")), Reservation)
            for x in unifi.list_configured_clients()
            if x.get("use_fixedip") and any(ipaddress.ip_address(x.get("fixed_ip")) in network for network in networks)
        ]
    )
    hosts.extend(
        [
            Host(x.get("mac"), x.get("ip"), (x.get("name"), x.get("hostname")), Lease)
            for x in unifi.list_clients()
            if x.get("ip") and any(ipaddress.ip_address(x.get("ip")) in network for network in networks)
        ]
    )

    zone = {}

    for host in hosts:
        if not host.ip:
            continue

        for i, hostname in enumerate(host.names):
            if not hostname:
                continue
            hostname = hostname.lower()
            if hostname in invalid:
                continue
            if hostname.endswith("." + domain):
                hostname = hostname[: -len(domain) - 1]
            hostdata = ZoneRecord(hostname, host.ip, host.mac, host.type, i)
            if hostname in zone and zone[hostname] != hostdata:
                if hostdata.effective_priority < zone[hostname].effective_priority:
                    zone[hostname] = hostdata
                else:
                    logger.info("Conflicting data for '%s': %s - %s", hostname, hostdata, zone[hostname])
            else:
                zone[hostname] = hostdata

    return list(zone.values())


if __name__ == "__main__":
    main()
