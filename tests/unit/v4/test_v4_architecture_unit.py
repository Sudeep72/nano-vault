"""Unit tests — Architecture Explorer + Threat Model (no DB needed)."""
from app.services.v4.architecture_service import architecture_service
from app.services.v4.threat_model_service import threat_model_service


def test_full_graph_has_nodes_and_edges():
    graph = architecture_service.get_full_graph()
    assert graph["node_count"] > 0
    assert graph["edge_count"] > 0
    assert len(graph["nodes"]) == graph["node_count"]


def test_get_node_returns_real_component():
    node = architecture_service.get_node("transit_engine")
    assert node is not None
    assert node["label"] == "Transit Secrets Engine"
    assert "POST /api/v3/transit/keys" in node["apis"]


def test_get_node_unknown_returns_none():
    assert architecture_service.get_node("nonexistent_node") is None


def test_node_dependencies_resolve():
    deps = architecture_service.get_node_dependencies("kv_secrets")
    dep_ids = [d["id"] for d in deps["depends_on"]]
    assert "encryption_core" in dep_ids
    assert "audit" in dep_ids


def test_get_by_category():
    engines = architecture_service.get_by_category("engine")
    assert len(engines) >= 4
    assert all(n["category"] == "engine" for n in engines)


def test_search_nodes():
    results = architecture_service.search_nodes("certificate")
    assert any("pki" in n["id"] for n in results)


def test_export_dot_valid_graphviz_syntax():
    dot = architecture_service.export_dot()
    assert dot.startswith("digraph NanoVault {")
    assert dot.strip().endswith("}")
    assert "->" in dot


def test_export_mermaid_valid_syntax():
    mermaid = architecture_service.export_mermaid()
    assert mermaid.startswith("graph LR")
    assert "-->" in mermaid


def test_every_node_has_required_fields():
    graph = architecture_service.get_full_graph()
    for node in graph["nodes"]:
        assert "id" in node and "label" in node and "description" in node
        assert "responsibilities" in node and "dependencies" in node


def test_every_edge_references_real_nodes():
    graph = architecture_service.get_full_graph()
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["from"] in node_ids, f"Edge references unknown node: {edge['from']}"
        assert edge["to"] in node_ids, f"Edge references unknown node: {edge['to']}"


# ── Threat Model ──────────────────────────────────────────────────────────────

def test_threat_model_flow():
    flow = threat_model_service.get_flow()
    assert flow["stages"][0] == "User"
    assert flow["stages"][-1] == "Audit"


def test_all_threats_have_mitigations():
    threats = threat_model_service.get_all_threats()
    assert len(threats) > 0
    for t in threats:
        assert len(t["mitigations"]) > 0
        for m in t["mitigations"]:
            assert "control" in m and "location" in m


def test_threats_by_stride_category():
    spoofing = threat_model_service.get_threats_by_stride("Spoofing")
    assert len(spoofing) >= 1
    assert all(t["stride_category"] == "Spoofing" for t in spoofing)


def test_threats_by_stage():
    secrets_threats = threat_model_service.get_threats_by_stage("Secrets")
    assert len(secrets_threats) >= 1


def test_get_specific_threat():
    threat = threat_model_service.get_threat("spoofing_credentials")
    assert threat is not None
    assert threat["stride_category"] == "Spoofing"


def test_get_unknown_threat_returns_none():
    assert threat_model_service.get_threat("does_not_exist") is None


def test_coverage_summary():
    summary = threat_model_service.get_coverage_summary()
    assert summary["total_threats"] > 0
    assert summary["total_mitigations"] > 0
    assert "Spoofing" in summary["by_stride_category"]


def test_export_markdown_contains_all_threats():
    md = threat_model_service.export_markdown()
    threats = threat_model_service.get_all_threats()
    for t in threats:
        assert t["id"] in md
