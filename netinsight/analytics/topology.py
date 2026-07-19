import logging
from datetime import timedelta
import networkx as nx
from pyvis.network import Network
from django.utils import timezone
from netinsight.dashboard.models import Agent

logger = logging.getLogger(__name__)

def generate_topology_pyvis() -> str:
    """Generates an interactive HTML graph representing the network topology of connected agents.

    Returns:
        str: PyVis-generated HTML snippet containing vis.js visualization.
    """
    try:
        G = nx.Graph()

        # Add Core Network Nodes
        G.add_node(
            "router",
            label="DSS Router",
            title="NetInsight-X Monitor Core Router",
            color="#3b82f6",
            shape="dot",
            size=25
        )
        G.add_node(
            "wan",
            label="WAN Gateway",
            title="External Internet Gateway",
            color="#10b981",
            shape="dot",
            size=20
        )
        G.add_edge("router", "wan", color="#64748b", width=2)

        # Get all registered agents
        agents = Agent.objects.all()

        now = timezone.now()
        active_threshold = timedelta(seconds=15)

        for agent in agents:
            # Determine online status dynamically
            is_online = (now - agent.last_seen) < active_threshold
            color = "#ef4444" if is_online else "#64748b"
            status_text = "Online" if is_online else "Offline"

            agent_label = f"{agent.hostname}\n({agent.ip_address})"
            agent_title = (
                f"Hostname: {agent.hostname}<br>"
                f"IP: {agent.ip_address}<br>"
                f"MAC: {agent.mac_address}<br>"
                f"Status: {status_text}<br>"
                f"CPU: {agent.cpu_usage}%<br>"
                f"RAM: {agent.memory_usage}%<br>"
                f"Active Connections: {agent.active_connections}"
            )

            G.add_node(
                agent.mac_address,
                label=agent_label,
                title=agent_title,
                color=color,
                shape="dot",
                size=16
            )
            # Edge connects agent to router
            G.add_edge("router", agent.mac_address, color="#475569", width=1.5)

        # Build PyVis Network
        net = Network(
            height="400px",
            width="100%",
            bgcolor="#0d111c",
            font_color="#f1f5f9"
        )
        net.from_nx(G)

        # Configure vis.js physics options for stable graph layout
        net.set_options("""
        var options = {
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -12000,
              "centralGravity": 0.4,
              "springLength": 95,
              "springConstant": 0.04,
              "damping": 0.09
            },
            "minVelocity": 0.75
          }
        }
        """)

        # Generate HTML content
        html_content = net.generate_html(notebook=False)
        return html_content

    except Exception as e:
        logger.error(f"Error generating topology graph: {e}", exc_info=True)
        return """
        <div style='background-color:#0d111c; color:#ef4444; padding:20px; font-family:sans-serif;'>
            <h3>Error generating network topology</h3>
            <p>Please check the server logs for more details.</p>
        </div>
        """
