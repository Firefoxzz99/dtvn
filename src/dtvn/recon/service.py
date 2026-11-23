from dataclasses import dataclass


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
}


@dataclass(frozen=True)
class ServiceInfo:
    port: int
    protocol: str
    service: str
    identification_method: str


def identify_service(port: int) -> ServiceInfo:
    service = COMMON_SERVICES.get(port, "Unknown")

    return ServiceInfo(
        port=port,
        protocol="tcp",
        service=service,
        identification_method="port-based guess",
    )