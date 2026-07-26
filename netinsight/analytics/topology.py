import os
import logging
from datetime import timedelta
import networkx as nx
from pyvis.network import Network
import pyvis
from django.utils import timezone
from netinsight.dashboard.models import Agent

logger = logging.getLogger(__name__)

def generate_topology_pyvis() -> str:
    """Generates an interactive HTML graph representing the network topology of connected agents.

    Returns:
        str: PyVis-generated HTML snippet containing vis.js visualization with inlined utils.js.
    """
    try:
        G = nx.Graph()

        # Add Core Network Nodes
        # Add Central Mobile Hotspot Gateway node
        G.add_node(
            "hotspot",
            label="Phone Hotspot\n(Gateway)",
            title="Mobile Hotspot & WAN Gateway Link",
            color="#10b981",
            shape="dot",
            size=26,
            x=0,
            y=0,
            fixed=True
        )

        # Get all registered agents
        agents = Agent.objects.all()

        now = timezone.now()
        active_threshold = timedelta(seconds=15)

        # Filter online agents only to keep map clean and relevant!
        online_agents = [a for a in agents if (now - a.last_seen) < active_threshold]

        import math
        num_agents = len(online_agents)
        for idx, agent in enumerate(online_agents):
            angle = (2 * math.pi * idx) / num_agents if num_agents > 0 else 0
            radius = 120
            ax = int(radius * math.cos(angle))
            ay = int(radius * math.sin(angle))

            agent_label = f"{agent.hostname}\n({agent.ip_address})"
            agent_title = (
                f"Hostname: {agent.hostname}\n"
                f"IP: {agent.ip_address}\n"
                f"MAC: {agent.mac_address}\n"
                f"Status: Online\n"
                f"CPU: {agent.cpu_usage}%\n"
                f"RAM: {agent.memory_usage}%\n"
                f"Active Connections: {agent.active_connections}"
            )

            G.add_node(
                agent.mac_address,
                label=agent_label,
                title=agent_title,
                color="#3b82f6",
                shape="dot",
                size=16,
                x=ax,
                y=ay,
                fixed=True
            )
            G.add_edge("hotspot", agent.mac_address, color="#475569", width=1.5)

        # Build PyVis Network
        net = Network(
            height="450px",
            width="100%",
            bgcolor="#0d111c",
            font_color="#f1f5f9"
        )
        net.from_nx(G)

        # Configure vis.js physics options for stable graph layout
        net.set_options("""
        var options = {
          "physics": {
            "enabled": false
          }
        }
        """)

        # Generate HTML content
        html_content = net.generate_html(notebook=False)

        # Inline local utils.js script to prevent relative path 404 loading errors
        try:
            pyvis_dir = os.path.dirname(pyvis.__file__)
            utils_js_path = os.path.join(pyvis_dir, "templates", "lib", "bindings", "utils.js")
            if not os.path.exists(utils_js_path):
                utils_js_path = os.path.join(pyvis_dir, "lib", "bindings", "utils.js")

            with open(utils_js_path, "r", encoding="utf-8") as f:
                utils_js_content = f.read()

            relative_tag = '<script src="lib/bindings/utils.js"></script>'
            inlined_tag = f'<script type="text/javascript">{utils_js_content}</script>'
            html_content = html_content.replace(relative_tag, inlined_tag)
        except Exception as js_err:
            logger.warning(f"Could not inline pyvis utils.js: {js_err}. Falling back to default.")

        return html_content

    except Exception as e:
        logger.error(f"Error generating topology graph: {e}", exc_info=True)
        return """
        <div style='background-color:#0d111c; color:#ef4444; padding:20px; font-family:sans-serif;'>
            <h3>Error generating network topology</h3>
            <p>Please check the server logs for more details.</p>
        </div>
        """
