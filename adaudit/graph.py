"""Relationship graph and bounded privilege-path search.

The graph is a plain adjacency structure built from a normalised dataset. It
has no knowledge of where the data came from: LDAP collection and offline
imports both produce the same nodes and edges.

Search is breadth-first over *simple* paths (a node may not repeat inside one
path), which makes cycle handling explicit: a cycle is pruned and counted, and
no traversal can loop. Every limit (depth, path count, expansion budget) is
configurable and a run that hits one says so instead of silently returning an
incomplete result.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import DirectoryDataset, DirObject, Edge, ObjectType, PrivilegePath
from .relationships import RELATIONSHIP_ORDER, edge_weight


@dataclass
class PathSearchStats:
    """Counters describing what the search actually did."""

    sources_requested: int = 0
    sources_found: int = 0
    nodes_expanded: int = 0
    edges_examined: int = 0
    cycles_pruned: int = 0
    depth_limited: int = 0
    paths_found: int = 0
    duplicate_paths: int = 0
    truncated: bool = False
    truncation_reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "sources_requested": self.sources_requested,
            "sources_found": self.sources_found,
            "nodes_expanded": self.nodes_expanded,
            "edges_examined": self.edges_examined,
            "cycles_pruned": self.cycles_pruned,
            "depth_limited": self.depth_limited,
            "paths_found": self.paths_found,
            "duplicate_paths": self.duplicate_paths,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
        }


@dataclass
class PathSearchResult:
    paths: List[PrivilegePath] = field(default_factory=list)
    stats: PathSearchStats = field(default_factory=PathSearchStats)
    missing_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "count": len(self.paths),
            "stats": self.stats.to_dict(),
            "missing_sources": list(self.missing_sources),
        }


class DirectoryGraph:
    """Adjacency view over a normalised dataset."""

    def __init__(self, dataset: DirectoryDataset) -> None:
        self.dataset = dataset
        self.nodes: Dict[str, DirObject] = dict(dataset.objects)
        self.out_edges: Dict[str, List[Edge]] = {}
        self.in_edges: Dict[str, List[Edge]] = {}
        self._edge_index: Dict[Tuple[str, str, str], Edge] = {}

        for edge in dataset.edges:
            if edge.key in self._edge_index:
                continue
            self._edge_index[edge.key] = edge
            self.out_edges.setdefault(edge.source, []).append(edge)
            self.in_edges.setdefault(edge.target, []).append(edge)

        for edges in self.out_edges.values():
            edges.sort(key=self._sort_key)

    # -- basic access -----------------------------------------------------

    @property
    def edge_count(self) -> int:
        return len(self._edge_index)

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def object_for(self, node_id: str) -> Optional[DirObject]:
        return self.nodes.get(node_id)

    def label(self, node_id: str) -> str:
        obj = self.nodes.get(node_id)
        return obj.label if obj else node_id

    def labels(self) -> Dict[str, str]:
        return {node_id: obj.label for node_id, obj in self.nodes.items()}

    def out(self, node_id: str) -> List[Edge]:
        return self.out_edges.get(node_id, [])

    def incoming(self, node_id: str) -> List[Edge]:
        return self.in_edges.get(node_id, [])

    def nodes_of_type(self, *types: ObjectType) -> List[DirObject]:
        wanted = set(types)
        return sorted(
            (obj for obj in self.nodes.values() if obj.type in wanted),
            key=lambda obj: obj.id,
        )

    def require_nodes(self, ids: Iterable[str]) -> List[str]:
        return [node for node in ids if node in self.nodes]

    @staticmethod
    def _sort_key(edge: Edge):
        return (
            RELATIONSHIP_ORDER.get(edge.type, len(RELATIONSHIP_ORDER)),
            -edge_weight(edge.type),
            edge.target,
            edge.source,
        )

    # -- search -----------------------------------------------------------

    def find_paths(
        self,
        sources: Sequence[str],
        targets: Sequence[str],
        max_depth: int = 6,
        max_paths: int = 50,
        budget: int = 200_000,
        excluded: Sequence[str] = (),
    ) -> PathSearchResult:
        """Enumerate simple paths from ``sources`` to ``targets``.

        ``excluded`` lists relationship types that are collected and worth
        showing but must not be traversed, because they do not by themselves
        confer leverage (``Contains`` is structural, not a privilege).

        Paths are returned shortest-first. Each path is unique by its ordered
        sequence of relationships, so two different relationship chains between
        the same nodes are both kept, while an identical chain found twice is
        not.
        """
        result = PathSearchResult()
        stats = result.stats
        stats.sources_requested = len(sources)
        excluded_types = set(excluded)

        target_set = {target for target in targets if target in self.nodes}
        stats.sources_found = sum(1 for source in sources if source in self.nodes)
        if not target_set:
            return result

        neighbours: Dict[str, List[Edge]] = {
            node_id: [
                edge
                for edge in self.out(node_id)
                if edge.target in self.nodes and edge.type not in excluded_types
            ]
            for node_id in self.nodes
        }

        seen_signatures = set()

        for source in sources:
            if source not in self.nodes:
                result.missing_sources.append(source)
                continue
            if source in target_set:
                # A privileged principal is not its own finding.
                continue

            queue = deque([(source, (source,), ())])
            while queue:
                node, nodes, steps = queue.popleft()

                if len(steps) >= max_depth:
                    if neighbours.get(node):
                        stats.depth_limited += 1
                    continue

                for edge in neighbours.get(node, ()):
                    if stats.nodes_expanded >= budget:
                        stats.truncated = True
                        stats.truncation_reason = (
                            f"search stopped after {budget} expansions "
                            f"(max_depth={max_depth}, max_paths={max_paths})"
                        )
                        return self._finish(result, seen_signatures)
                    stats.edges_examined += 1

                    if edge.target in nodes:
                        stats.cycles_pruned += 1
                        continue

                    new_nodes = nodes + (edge.target,)
                    new_steps = steps + (edge,)

                    if edge.target in target_set:
                        signature = "|".join(
                            f"{step.type}:{step.source}->{step.target}" for step in new_steps
                        )
                        if signature in seen_signatures:
                            stats.duplicate_paths += 1
                            continue
                        seen_signatures.add(signature)
                        result.paths.append(
                            PrivilegePath(
                                source=source,
                                target=edge.target,
                                nodes=new_nodes,
                                steps=new_steps,
                            )
                        )
                        if len(result.paths) >= max_paths:
                            stats.truncated = True
                            stats.truncation_reason = (
                                f"path limit reached ({max_paths} paths); "
                                "raise --max-paths to see more"
                            )
                            return self._finish(result, seen_signatures)
                        continue

                    queue.append((edge.target, new_nodes, new_steps))
                    stats.nodes_expanded += 1

        return self._finish(result, seen_signatures)

    def _finish(
        self,
        result: PathSearchResult,
        seen_signatures: set,
    ) -> PathSearchResult:
        result.paths.sort(key=lambda path: (path.length, path.source, path.target, path.signature))
        result.stats.paths_found = len(result.paths)
        return result

    # -- helpers ----------------------------------------------------------

    def direct_member_count(self, group_id: str) -> int:
        return sum(
            1
            for edge in self.incoming(group_id)
            if edge.type == "MemberOf"
        )

    def describe_node(self, node_id: str) -> str:
        obj = self.nodes.get(node_id)
        if obj is None:
            return node_id
        if obj.type is ObjectType.UNKNOWN:
            return f"{node_id} (unresolved)"
        return obj.label
