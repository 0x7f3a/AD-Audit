"""Graph engine tests: typed edges, direction, cycles and every search limit."""

from __future__ import annotations

from typing import Iterable

from adaudit.graph import DirectoryGraph
from adaudit.models import (
    DirObject,
    DirectoryDataset,
    Edge,
    EvidenceItem,
    EvidenceQuality,
    ObjectType,
)


def node(object_id: str, object_type: ObjectType, name: str) -> DirObject:
    return DirObject(id=object_id, type=object_type, name=name, domain="corp.example")


def edge(
    edge_type: str,
    source: str,
    target: str,
    quality: EvidenceQuality = EvidenceQuality.EXPLICIT,
    inherited: bool = False,
) -> Edge:
    return Edge(
        type=edge_type,
        source=source,
        target=target,
        quality=quality,
        inherited=inherited,
        evidence=[EvidenceItem(detail=f"{edge_type} evidence", quality=quality)],
    )


def build_dataset(
    nodes: Iterable[DirObject],
    edges: Iterable[Edge],
) -> DirectoryDataset:
    dataset = DirectoryDataset()
    for item in nodes:
        dataset.add_object(item)
    for item in edges:
        dataset.add_edge(item)
    return dataset


def path_dicts(result):
    return [
        [(step.type, step.source, step.target) for step in path.steps]
        for path in result.paths
    ]


def test_direct_membership_edge_is_a_one_hop_path():
    dataset = build_dataset(
        [node("u", ObjectType.USER, "analyst"), node("g", ObjectType.GROUP, "Domain Admins")],
        [edge("MemberOf", "u", "g")],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["u"], ["g"])
    assert path_dicts(result) == [[("MemberOf", "u", "g")]]
    assert result.paths[0].confidence is not None
    assert result.stats.cycles_pruned == 0


def test_indirect_path_through_nested_groups():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("helpdesk", ObjectType.GROUP, "Helpdesk"),
            node("tier0", ObjectType.GROUP, "Tier0"),
        ],
        [
            edge("MemberOf", "u", "helpdesk"),
            edge("MemberOf", "helpdesk", "tier0"),
        ],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["u"], ["tier0"])
    assert path_dicts(result) == [
        [("MemberOf", "u", "helpdesk"), ("MemberOf", "helpdesk", "tier0")]
    ]


def test_edge_direction_is_respected():
    dataset = build_dataset(
        [node("u", ObjectType.USER, "analyst"), node("g", ObjectType.GROUP, "Domain Admins")],
        [edge("MemberOf", "u", "g")],
    )
    graph = DirectoryGraph(dataset)
    assert graph.find_paths(["g"], ["u"]).paths == []
    assert graph.find_paths(["u"], ["u"]).paths == []


def test_cycle_does_not_loop_and_is_counted():
    dataset = build_dataset(
        [
            node("a", ObjectType.GROUP, "A"),
            node("b", ObjectType.GROUP, "B"),
            node("c", ObjectType.GROUP, "C"),
        ],
        [edge("MemberOf", "a", "b"), edge("MemberOf", "b", "a"), edge("MemberOf", "b", "c")],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["a"], ["c"], max_depth=10)
    assert path_dicts(result) == [[("MemberOf", "a", "b"), ("MemberOf", "b", "c")]]
    assert result.stats.cycles_pruned >= 1
    assert result.stats.truncated is False


def test_duplicate_edges_are_collapsed_in_the_graph():
    dataset = build_dataset(
        [node("u", ObjectType.USER, "analyst"), node("g", ObjectType.GROUP, "DA")],
        [edge("MemberOf", "u", "g"), edge("MemberOf", "u", "g")],
    )
    graph = DirectoryGraph(dataset)
    assert graph.edge_count == 1
    result = graph.find_paths(["u"], ["g"])
    assert len(result.paths) == 1


def test_max_depth_prevents_longer_paths():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("g1", ObjectType.GROUP, "G1"),
            node("g2", ObjectType.GROUP, "G2"),
        ],
        [edge("MemberOf", "u", "g1"), edge("MemberOf", "g1", "g2")],
    )
    graph = DirectoryGraph(dataset)
    assert graph.find_paths(["u"], ["g2"], max_depth=1).paths == []
    result = graph.find_paths(["u"], ["g2"], max_depth=2)
    assert len(result.paths) == 1
    assert result.stats.depth_limited == 0


def test_max_paths_limit_sets_truncation():
    nodes = [node("u", ObjectType.USER, "analyst")] + [
        node(f"g{index}", ObjectType.GROUP, f"G{index}") for index in range(1, 6)
    ]
    edges = [edge("MemberOf", "u", f"g{index}") for index in range(1, 6)]
    graph = DirectoryGraph(build_dataset(nodes, edges))
    result = graph.find_paths(["u"], [f"g{index}" for index in range(1, 6)], max_paths=2)
    assert len(result.paths) == 2
    assert result.stats.truncated is True
    assert "path limit" in result.stats.truncation_reason


def test_expansion_budget_stops_search():
    nodes = [node("u", ObjectType.USER, "analyst")]
    edges = []
    for index in range(1, 30):
        nodes.append(node(f"g{index}", ObjectType.GROUP, f"G{index}"))
        edges.append(edge("MemberOf", "u", f"g{index}"))
        nodes.append(node(f"h{index}", ObjectType.GROUP, f"H{index}"))
        edges.append(edge("MemberOf", f"g{index}", f"h{index}"))
    graph = DirectoryGraph(build_dataset(nodes, edges))
    result = graph.find_paths(
        ["u"], [f"h{index}" for index in range(1, 30)], budget=5, max_depth=4
    )
    assert result.stats.truncated is True
    assert "expansions" in result.stats.truncation_reason


def test_no_path_returns_empty_result():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("v", ObjectType.USER, "other"),
            node("g", ObjectType.GROUP, "Domain Admins"),
            node("h", ObjectType.GROUP, "Helpdesk"),
        ],
        [edge("MemberOf", "u", "h"), edge("MemberOf", "v", "g")],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["u"], ["g"])
    assert result.paths == []
    assert result.stats.paths_found == 0


def test_missing_source_is_reported():
    dataset = build_dataset(
        [node("u", ObjectType.USER, "analyst"), node("g", ObjectType.GROUP, "DA")],
        [edge("MemberOf", "u", "g")],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["nope"], ["g"])
    assert result.missing_sources == ["nope"]
    assert result.stats.sources_requested == 1
    assert result.stats.sources_found == 0


def test_equivalent_paths_are_deduplicated():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("a", ObjectType.GROUP, "A"),
            node("g", ObjectType.GROUP, "DA"),
        ],
        [edge("MemberOf", "u", "a"), edge("MemberOf", "a", "g")],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["u"], ["g"])
    signatures = {path.signature for path in result.paths}
    assert len(result.paths) == len(signatures) == 1


def test_multiple_distinct_paths_are_kept_and_sorted():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("a", ObjectType.GROUP, "A"),
            node("b", ObjectType.GROUP, "B"),
            node("g", ObjectType.GROUP, "DA"),
        ],
        [
            edge("MemberOf", "u", "g"),
            edge("MemberOf", "u", "a"),
            edge("MemberOf", "a", "g"),
            edge("GenericAll", "u", "b"),
            edge("MemberOf", "b", "g"),
        ],
    )
    graph = DirectoryGraph(dataset)
    result = graph.find_paths(["u"], ["g"])
    assert len(result.paths) == 3
    lengths = [path.length for path in result.paths]
    assert lengths == sorted(lengths)
    assert lengths[0] == 1


def test_inherited_edge_lowers_path_confidence():
    dataset = build_dataset(
        [
            node("u", ObjectType.USER, "analyst"),
            node("g", ObjectType.GROUP, "DA"),
        ],
        [edge("GenericAll", "u", "g", EvidenceQuality.DERIVED, inherited=True)],
    )
    graph = DirectoryGraph(dataset)
    path = graph.find_paths(["u"], ["g"]).paths[0]
    assert path.steps[0].inherited is True
    assert path.confidence.value == "likely"


def test_unknown_nodes_are_never_created():
    dataset = build_dataset(
        [node("u", ObjectType.USER, "analyst")],
        [edge("MemberOf", "u", "missing-group")],
    )
    graph = DirectoryGraph(dataset)
    assert graph.has_node("missing-group") is False
    assert graph.find_paths(["u"], ["missing-group"]).paths == []
