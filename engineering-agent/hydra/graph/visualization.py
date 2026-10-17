"""
╔══════════════════════════════════════════════════════════════╗
║  Attack Graph Visualization — Export to DOT, JSON, HTML     ║
║  Visual attack chain rendering for reports and dashboards   ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import logging
import html as html_lib
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("hydra.graph.visualization")

# Severity → color mapping for visualization
SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFD700",
    "low": "#00CC00",
    "info": "#4488FF",
}

NODE_TYPE_SHAPES = {
    "asset": "box",
    "service": "ellipse",
    "endpoint": "parallelogram",
    "vuln": "octagon",
    "credential": "diamond",
    "attack_step": "hexagon",
}

NODE_TYPE_ICONS = {
    "asset": "🖥️",
    "service": "🌐",
    "endpoint": "📍",
    "vuln": "🔓",
    "credential": "🔑",
    "attack_step": "⚔️",
}


class GraphVisualizer:
    """Export attack graphs to various visual formats."""

    def __init__(self, attack_graph):
        self.graph = attack_graph

    def to_dot(self, highlight_paths: Optional[List[List[str]]] = None) -> str:
        """
        Export the graph to DOT format (Graphviz).
        
        Args:
            highlight_paths: Optional paths to highlight in red.
        """
        highlight_edges = set()
        if highlight_paths:
            for path in highlight_paths:
                for i in range(len(path) - 1):
                    highlight_edges.add((path[i], path[i + 1]))

        lines = [
            'digraph AttackGraph {',
            '  rankdir=LR;',
            '  fontname="Helvetica";',
            '  node [fontname="Helvetica", fontsize=10];',
            '  edge [fontname="Helvetica", fontsize=8];',
            '',
        ]

        # Nodes
        for nid, node in self.graph._nodes.items():
            color = SEVERITY_COLORS.get(node.severity, "#CCCCCC")
            shape = NODE_TYPE_SHAPES.get(node.node_type, "box")
            label = node.label[:40].replace('"', '\\"')
            icon = NODE_TYPE_ICONS.get(node.node_type, "")
            display = f"{icon} {label}" if icon else label
            safe_id = nid.replace(":", "_").replace("-", "_").replace(".", "_")

            lines.append(
                f'  {safe_id} ['
                f'label="{display}", '
                f'shape={shape}, '
                f'style=filled, '
                f'fillcolor="{color}30", '
                f'color="{color}", '
                f'tooltip="{node.node_type}: {label}"'
                f'];'
            )

        lines.append('')

        # Edges
        for edge in self.graph._edges:
            src = edge.source_id.replace(":", "_").replace("-", "_").replace(".", "_")
            tgt = edge.target_id.replace(":", "_").replace("-", "_").replace(".", "_")
            is_highlighted = (edge.source_id, edge.target_id) in highlight_edges
            color = "#FF0000" if is_highlighted else "#666666"
            width = "2.5" if is_highlighted else "1.0"
            label = edge.label[:30] if edge.label else edge.edge_type[:20]

            lines.append(
                f'  {src} -> {tgt} ['
                f'label="{label}", '
                f'color="{color}", '
                f'penwidth={width}, '
                f'arrowsize=0.7'
                f'];'
            )

        lines.append('}')
        return '\n'.join(lines)

    def to_json_graph(self) -> Dict[str, Any]:
        """Export as a JSON graph structure (for D3.js, Cytoscape, etc.)."""
        nodes = []
        for nid, node in self.graph._nodes.items():
            nodes.append({
                "id": nid,
                "label": node.label,
                "type": node.node_type,
                "severity": node.severity,
                "color": SEVERITY_COLORS.get(node.severity, "#CCCCCC"),
                "properties": node.properties,
            })

        edges = []
        for edge in self.graph._edges:
            edges.append({
                "source": edge.source_id,
                "target": edge.target_id,
                "type": edge.edge_type,
                "label": edge.label,
                "weight": edge.weight,
                "confidence": edge.confidence,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
            },
        }

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """Export as Cytoscape.js-compatible JSON."""
        elements = []

        for nid, node in self.graph._nodes.items():
            elements.append({
                "data": {
                    "id": nid,
                    "label": node.label[:50],
                    "type": node.node_type,
                    "severity": node.severity,
                    "color": SEVERITY_COLORS.get(node.severity, "#CCCCCC"),
                },
                "classes": f"{node.node_type} {node.severity}",
            })

        for i, edge in enumerate(self.graph._edges):
            elements.append({
                "data": {
                    "id": f"e{i}",
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "label": edge.label or edge.edge_type,
                    "confidence": edge.confidence,
                },
            })

        return {"elements": elements}

    def to_html(
        self,
        title: str = "HYDRA Attack Graph",
        highlight_paths: Optional[List[List[str]]] = None,
    ) -> str:
        """Generate a standalone HTML page with an interactive graph visualization."""
        graph_json = json.dumps(self.to_cytoscape_json(), indent=2)
        safe_title = html_lib.escape(title)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{safe_title}</title>
    <script src="https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0a0a1a;
            color: #e0e0e0;
        }}
        #header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px 30px;
            border-bottom: 1px solid #333;
        }}
        #header h1 {{
            font-size: 1.5em;
            background: linear-gradient(90deg, #00d2ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        #cy {{
            width: 100%;
            height: calc(100vh - 80px);
            background: #0d0d20;
        }}
        #legend {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(26, 26, 46, 0.95);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 15px;
            font-size: 12px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 4px 0;
        }}
        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>🔥 {safe_title}</h1>
    </div>
    <div id="cy"></div>
    <div id="legend">
        <strong>Severity</strong>
        <div class="legend-item"><span class="legend-dot" style="background:#FF0000"></span> Critical</div>
        <div class="legend-item"><span class="legend-dot" style="background:#FF6600"></span> High</div>
        <div class="legend-item"><span class="legend-dot" style="background:#FFD700"></span> Medium</div>
        <div class="legend-item"><span class="legend-dot" style="background:#00CC00"></span> Low</div>
        <div class="legend-item"><span class="legend-dot" style="background:#4488FF"></span> Info</div>
    </div>
    <script>
        const graphData = {graph_json};
        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: graphData.elements,
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'background-color': 'data(color)',
                        'label': 'data(label)',
                        'color': '#fff',
                        'text-valign': 'bottom',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'text-margin-y': 5,
                        'width': 30,
                        'height': 30,
                        'border-width': 2,
                        'border-color': 'data(color)',
                        'text-outline-width': 1,
                        'text-outline-color': '#000',
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 1.5,
                        'line-color': '#555',
                        'target-arrow-color': '#555',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '8px',
                        'color': '#999',
                        'text-outline-width': 1,
                        'text-outline-color': '#000',
                    }}
                }},
                {{
                    selector: ':selected',
                    style: {{
                        'border-width': 4,
                        'border-color': '#00d2ff',
                    }}
                }}
            ],
            layout: {{
                name: 'breadthfirst',
                directed: true,
                spacingFactor: 1.5,
                animate: true,
            }}
        }});
    </script>
</body>
</html>"""

    def save(
        self,
        output_dir: str,
        formats: Optional[List[str]] = None,
        highlight_paths: Optional[List[List[str]]] = None,
    ) -> Dict[str, str]:
        """
        Save the graph in multiple formats.
        
        Args:
            output_dir: Directory to save files.
            formats: List of formats ('dot', 'json', 'html', 'cytoscape').
            highlight_paths: Optional paths to highlight.
            
        Returns:
            Dict mapping format → file path.
        """
        formats = formats or ["dot", "json", "html"]
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        saved = {}

        if "dot" in formats:
            dot_file = out_path / "attack_graph.dot"
            dot_file.write_text(self.to_dot(highlight_paths), encoding="utf-8")
            saved["dot"] = str(dot_file)

        if "json" in formats:
            json_file = out_path / "attack_graph.json"
            json_file.write_text(
                json.dumps(self.to_json_graph(), indent=2), encoding="utf-8"
            )
            saved["json"] = str(json_file)

        if "cytoscape" in formats:
            cyto_file = out_path / "attack_graph_cytoscape.json"
            cyto_file.write_text(
                json.dumps(self.to_cytoscape_json(), indent=2), encoding="utf-8"
            )
            saved["cytoscape"] = str(cyto_file)

        if "html" in formats:
            html_file = out_path / "attack_graph.html"
            html_file.write_text(
                self.to_html(highlight_paths=highlight_paths), encoding="utf-8"
            )
            saved["html"] = str(html_file)

        logger.info(f"Graph exported: {list(saved.keys())} → {output_dir}")
        return saved
