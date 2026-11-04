"""Fixed study sites and their supplied provider labels."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class Domain:
    id: str
    name: str
    hostname: str
    provider: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


DOMAINS = (
    Domain("chronoscrate", "Chronoscrate", "chronoscrate.xyz", "Dynadot"),
    Domain("la_jolla_seals", "La Jolla Seals", "protectlajollaseals.xyz", "Namecheap"),
)
DOMAIN_IDS = tuple(domain.id for domain in DOMAINS)
DEFAULT_DOMAIN = "chronoscrate"


def get_domain(domain_id: str = DEFAULT_DOMAIN) -> Domain:
    for domain in DOMAINS:
        if domain.id == domain_id:
            return domain
    raise ValueError("domain_id must be chronoscrate or la_jolla_seals.")
