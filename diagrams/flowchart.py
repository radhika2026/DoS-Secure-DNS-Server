from graphviz import Digraph

# Create a Digraph object
flowchart = Digraph("DNS_Gatekeeper", filename="dns_gatekeeper_flowchart", format="png")
flowchart.attr(rankdir="LR", size="10")

# Nodes
flowchart.node("Start", "Start DNS Gatekeeper", shape="ellipse", style="filled", fillcolor="lightblue")
flowchart.node("Receive", "Receive DNS Request", shape="box", style="filled", fillcolor="lightgreen")
flowchart.node("Validate", "Validate Sender IP", shape="diamond", style="filled", fillcolor="lightyellow")
flowchart.node("Blocked", "IP is Blocked", shape="box", style="filled", fillcolor="orange")
flowchart.node("Process", "Process DNS Request", shape="box", style="filled", fillcolor="lightgreen")
flowchart.node("Forward", "Forward Query", shape="box", style="filled", fillcolor="lightgreen")
flowchart.node("Resolve", "Resolve Request via Primary/Secondary", shape="box", style="filled", fillcolor="lightpink")
flowchart.node("Ban", "Block IP for Excessive Requests", shape="box", style="filled", fillcolor="orange")
flowchart.node("Reset", "Reset Request History", shape="box", style="filled", fillcolor="lightblue")
flowchart.node("ZoneTransfer", "Perform Zone Transfer", shape="box", style="filled", fillcolor="lightblue")
flowchart.node("Response", "Send Response to Client", shape="box", style="filled", fillcolor="lightgreen")
flowchart.node("End", "End Process", shape="ellipse", style="filled", fillcolor="lightblue")

# Edges
flowchart.edge("Start", "Receive")
flowchart.edge("Receive", "Validate")
flowchart.edge("Validate", "Blocked", label="No (IP Blocked)")
flowchart.edge("Blocked", "End")
flowchart.edge("Validate", "Process", label="Yes (Valid IP)")
flowchart.edge("Process", "Resolve", label="Is Query Local?")
flowchart.edge("Resolve", "Forward", label="No (Forward Query)")
flowchart.edge("Forward", "Response")
flowchart.edge("Resolve", "Response", label="Yes (Resolve Internally)")
flowchart.edge("Process", "Ban", label="Exceeds Threshold?")
flowchart.edge("Ban", "End")
flowchart.edge("Response", "End")
flowchart.edge("End", "Reset", label="Timeout")
flowchart.edge("Reset", "Start")
flowchart.edge("End", "ZoneTransfer", label="Scheduled")
flowchart.edge("ZoneTransfer", "Start")

# Render the flowchart
flowchart.render(view=True)
