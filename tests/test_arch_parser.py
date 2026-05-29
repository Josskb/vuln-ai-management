from vuln_ai.parser.arch_parser import ArchitectureParser


def test_parse_mediconnect_components():
    description = """
    MediConnect Corp est une plateforme.
    Serveur web Nginx 1.18 expose sur Internet (ports 80/443)
    Serveur d'integration Mirth Connect 4.4.0 via proxy
    Pas de segmentation reseau (flat network)
    """
    arch = ArchitectureParser().parse(description)
    assert arch.name == "MediConnect Corp"
    assert arch.network_topology == "flat_network"
    assert len(arch.components) == 12


def test_parse_generic_lines():
    description = """
    Custom Platform
    API REST /api/v1 on port 443
    Redis 6.0 internal port 6379
    SSH Server exposed internet port 22
    """
    arch = ArchitectureParser().parse(description)
    assert arch.name == "Unknown Organisation"
    assert len(arch.components) >= 3
    names = [c.name for c in arch.components]
    assert any("API REST" in n for n in names)
    assert any("Redis" in n for n in names)
    assert any("SSH" in n for n in names)
