import networkx as nx
from typing import List, Dict, Any, Optional
import structlog

from src.domain.models.code_graph import GraphNode, GraphEdge, CodeGraphSummary, NodeKind, EdgeKind

logger = structlog.get_logger()


class NetworkXGraphBuilder:
    """Motor GraphRAG que constrói um Grafo Dirigido do Código Fonte usando NetworkX."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, nodes: List[GraphNode], edges: List[GraphEdge]) -> CodeGraphSummary:
        self.graph.clear()

        # Adiciona nós
        for n in nodes:
            self.graph.add_node(
                n.id,
                label=n.label,
                kind=n.kind.value,
                file_path=n.file_path,
                line_number=n.line_number,
                **n.properties
            )

        # Adiciona arestas
        for e in edges:
            self.graph.add_edge(
                e.source_id,
                e.target_id,
                kind=e.kind.value,
                **e.properties
            )

        endpoints = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == NodeKind.ENDPOINT.value]
        pii_fields = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == NodeKind.MODEL_FIELD.value and d.get("is_pii")]

        logger.info(
            "code_graph_built",
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
            endpoints_count=len(endpoints)
        )

        return CodeGraphSummary(
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
            endpoints_count=len(endpoints),
            pii_fields_count=len(pii_fields)
        )

    def get_context_for_endpoint(self, endpoint_node_id: str) -> Dict[str, Any]:
        """Extrai o contexto conexo de um endpoint no grafo para enriquecer os prompts da IA."""
        if not self.graph.has_node(endpoint_node_id):
            return {}

        endpoint_data = self.graph.nodes[endpoint_node_id]
        neighbors = list(self.graph.neighbors(endpoint_node_id))
        predecessors = list(self.graph.predecessors(endpoint_node_id))

        connected_nodes = []
        for n_id in neighbors + predecessors:
            connected_nodes.append({
                "id": n_id,
                "label": self.graph.nodes[n_id].get("label"),
                "kind": self.graph.nodes[n_id].get("kind"),
                "file_path": self.graph.nodes[n_id].get("file_path")
            })

        return {
            "endpoint": endpoint_data,
            "connected_elements": connected_nodes
        }
