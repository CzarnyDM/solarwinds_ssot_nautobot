"""Nautobot SSoT SolarWinds IPAM Adapter.

Loads Prefixes and IPAddresses from the SolarWinds IPAM module
(IPAM.Subnet / IPAM.IPNode / IPAM.IPInfo) rather than deriving them from
monitored node interfaces. Used by the SolarWindsIPAMDataSource Job.
"""
import re
from datetime import datetime

from diffsync import Adapter
from diffsync.exceptions import ObjectNotFound

from nautobot_ssot.integrations.solarwinds.diffsync.models.solarwinds import (
    SolarWindsIPAMIPAddress,
    SolarWindsIPAMPrefix,
)
from nautobot_ssot.integrations.solarwinds.utils.solarwinds import SolarWindsClient

# Map IPAM.IPInfo IPStatusText values to Nautobot Status names. Anything not
# listed falls back to "Active". 'Available' rows are excluded at query time.
IPAM_STATUS_MAP = {
    "Used": "Active",
    "Reserved": "Reserved",
    "Transient": "Deprecated",
    "Blocked": "Deprecated",
}

DNS_NAME_ALLOWED = re.compile(r"[^0-9A-Za-z._-]")

def sanitize_dns_name(name: str) -> str:
    """Strip characters Nautobot disallows in dns_name (control chars, spaces, etc.)."""
    if not name:
        return ""
    cleaned = DNS_NAME_ALLOWED.sub("", name).strip(".")
    return cleaned

class SolarWindsIPAMAdapter(Adapter):
    """DiffSync adapter for the SolarWinds IPAM module."""

    prefix = SolarWindsIPAMPrefix
    ipaddress = SolarWindsIPAMIPAddress

    top_level = [
        "prefix",
        "ipaddress",
    ]

    def __init__(self, job, client: SolarWindsClient, sync=None, tenant=None, namespace=None):
        """Initialize the SolarWinds IPAM adapter.

        Args:
            job (object): The running SolarWindsIPAMDataSource Job.
            client (SolarWindsClient): SolarWinds API client connection object.
            sync (object, optional): SolarWindsIPAMDataSource Sync.
            tenant (Tenant, optional): Tenant to associate with imported IPAM data.
            namespace (Namespace, optional): Namespace to assign imported Prefixes
                and IPAddresses to. Defaults to 'Global'.
        """
        super().__init__()
        self.job = job
        self.sync = sync
        self.conn = client
        self.tenant = tenant
        self.namespace = namespace
        self.skipped_ips = []

    @property
    def namespace_name(self) -> str:
        """Return the Namespace name to load objects under."""
        return self.namespace.name if self.namespace else "Global"

    def load(self):
        """Load IPAM data from SolarWinds into DiffSync models."""
        self.load_prefixes()
        self.load_ipaddresses()
        if self.skipped_ips:
            self.job.logger.warning(
                "Skipped %s IPAM addresses whose parent subnet was not loaded: %s",
                len(self.skipped_ips),
                ", ".join(self.skipped_ips[:25]) + ("..." if len(self.skipped_ips) > 25 else ""),
            )

    def load_prefixes(self):
        """Load Prefixes from IPAM.Subnet."""
        subnets = self.conn.get_ipam_subnets()
        self.job.logger.info("Loading %s subnets from SolarWinds IPAM.", len(subnets))
        for subnet in subnets:
            if not subnet.get("Address") or subnet.get("CIDR") in (None, ""):
                self.job.logger.warning("Skipping IPAM subnet with missing Address/CIDR: %s", subnet)
                continue
            if int(subnet["CIDR"]) == 0:
                self.job.logger.warning("Skipping IPAM subnet with CIDR 0: %s", subnet.get("Address"))
                continue
            self.get_or_instantiate(
                self.prefix,
                ids={
                    "network": subnet["Address"],
                    "prefix_length": int(subnet["CIDR"]),
                    "namespace__name": self.namespace_name,
                },
                attrs={
                    "description": subnet.get("FriendlyName") or "",
                    "status__name": "Active",
                    "tenant__name": self.tenant.name if self.tenant else None,
                    "last_synced_from_sor": datetime.today().date().isoformat(),
                    "system_of_record": "SolarWinds",
                },
            )
def load_ipaddresses(self):
        """Load IPAddresses from IPAM.IPNode joined to IPAM.IPInfo and IPAM.Subnet."""
        ipaddrs = self.conn.get_ipam_ipaddresses()
        self.job.logger.info("Loading %s IP addresses from SolarWinds IPAM.", len(ipaddrs))
        for ipaddr in ipaddrs:
            host = ipaddr.get("IPAddress")
            subnet_addr = ipaddr.get("SubnetAddress")
            subnet_cidr = ipaddr.get("SubnetCIDR")
            if not host or not subnet_addr or subnet_cidr in (None, ""):
                self.job.logger.warning("Skipping IPAM address with missing data: %s", ipaddr)
                continue
            subnet_cidr = int(subnet_cidr)

            raw_dns = ipaddr.get("DnsBackward") or ""
            dns_name = sanitize_dns_name(raw_dns)
            if dns_name != raw_dns:
                self.job.logger.debug("Sanitized dns_name %r -> %r for %s", raw_dns, dns_name, host)

            # Only attach IPs to prefixes we actually loaded; anything else
            # would reference a parent Prefix the diff can't resolve.
            try:
                self.get(
                    self.prefix,
                    {
                        "network": subnet_addr,
                        "prefix_length": subnet_cidr,
                        "namespace__name": self.namespace_name,
                    },
                )
            except ObjectNotFound:
                self.skipped_ips.append(f"{host} ({subnet_addr}/{subnet_cidr})")
                continue
            self.get_or_instantiate(
                self.ipaddress,
                ids={
                    "host": host,
                    "parent__network": subnet_addr,
                    "parent__prefix_length": subnet_cidr,
                    "parent__namespace__name": self.namespace_name,
                },
                attrs={
                    "mask_length": subnet_cidr,
                    "dns_name": dns_name,
                    "status__name": IPAM_STATUS_MAP.get(ipaddr.get("IPStatusText"), "Active"),
                    "ip_version": 6 if ":" in host else 4,
                    "tenant__name": self.tenant.name if self.tenant else None,
                    "last_synced_from_sor": datetime.today().date().isoformat(),
                    "system_of_record": "SolarWinds",
                },
            )