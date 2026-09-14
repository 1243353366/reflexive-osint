"""Entity-relationship graph model for Investigate Mode v2.

Clean-room reimplementation. The multi-source aggregation → entity-relationship
graph pattern is architecture inspired by Palantir-OSINT (JehanPatel); NO code
from that repository is incorporated (it carries no license). See NOTICE/credits
in the repository root.

Stdlib-only, no third-party dependencies.
"""

import json
from typing import Any, Dict, List, Optional


class Graph:
    """A simple directed multigraph with node/edge provenance."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    # -- nodes -----------------------------------------------------------

    def add_node(self, node_type: str, key: str, **attrs: Any) -> str:
        """Idempotently add a node; merges attributes on re-add."""
        if key not in self.nodes:
            self.nodes[key] = {"type": node_type, "key": key, **attrs}
        else:
            node = self.nodes[key]
            for k, v in attrs.items():
                if k == "sources":
                    node.setdefault("sources", []).extend(
                        s for s in v if s not in node["sources"]
                    )
                elif k not in node or node[k] in (None, "", []):
                    node[k] = v
        return key

    # -- edges -----------------------------------------------------------

    def add_edge(
        self,
        edge_type: str,
        source_key: str,
        target_key: str,
        source: Optional[str] = None,
        **attrs: Any,
    ) -> None:
        """Add a typed, provenance-tagged edge; duplicates by (type, src, tgt, source) are skipped."""
        for e in self.edges:
            if (
                e["type"] == edge_type
                and e["source"] == source_key
                and e["target"] == target_key
                and e.get("via") == source
            ):
                return
        self.edges.append(
            {
                "type": edge_type,
                "source": source_key,
                "target": target_key,
                "via": source,
                **attrs,
            }
        )

    # -- export ----------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    def to_cytoscape(self) -> List[Dict[str, Any]]:
        """Export elements in Cytoscape.js format."""
        elements: List[Dict[str, Any]] = []
        for n in self.nodes.values():
            data = dict(n)
            data.setdefault("label", n.get("name", n["key"]))
            elements.append({"data": data})
        for e in self.edges:
            data = dict(e)
            data.setdefault("id", f"{e['type']}:{e['source']}->{e['target']}")
            elements.append({"data": data})
        return elements

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
