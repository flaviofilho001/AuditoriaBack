from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    FILE = "FILE"
    CLASS = "CLASS"
    METHOD = "METHOD"
    ENDPOINT = "ENDPOINT"
    MODEL_FIELD = "MODEL_FIELD"
    CONFIG_KEY = "CONFIG_KEY"
    DATABASE = "DATABASE"


class EdgeKind(str, Enum):
    CONTAINS = "CONTAINS"
    EXPOSES_ROUTE = "EXPOSES_ROUTE"
    CALLS = "CALLS"
    USES_MODEL = "USES_MODEL"
    HAS_PII = "HAS_PII"
    ACCESSES_DB = "ACCESSES_DB"
    DEPENDS_ON = "DEPENDS_ON"


class GraphNode(BaseModel):
    id: str
    label: str
    kind: NodeKind
    file_path: str
    line_number: Optional[int] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    kind: EdgeKind
    properties: Dict[str, Any] = Field(default_factory=dict)


class CodeGraphSummary(BaseModel):
    total_nodes: int
    total_edges: int
    endpoints_count: int
    pii_fields_count: int
    files_scanned: List[str] = Field(default_factory=list)
