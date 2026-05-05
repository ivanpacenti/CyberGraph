# This script demonstrates the structure of the system knowledge graph by creating
# a small sample graph and generating a visual representation. It showcases how
# vulnerabilities (CVEs) from NVD are linked to software products, weaknesses (CWEs)
# from CWE dataset, and external references, forming a semantic web of cybersecurity data.
#
# The visualization uses NetworkX and Matplotlib to create an interactive graph
# that highlights the relationships defined in the project ontology.

#!/usr/bin/env python3

from rdflib import Graph, Literal, RDF, RDFS, URIRef
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from kg.ontology import CG, CVE, PRODUCT, CWE


def create_sample_graph() -> Graph:
    """
    Create a minimal sample RDF graph to illustrate the ontology.

    This function builds a tiny knowledge graph with one vulnerability (CVE-2023-12345),
    one affected software product (Apache HTTP Server), one weakness (CWE-79 for XSS),
    and one external reference. This represents a typical slice of the full dataset.

    The graph uses the ontology classes and properties to model real-world
    cybersecurity relationships, making it easy to understand the data structure.
    """
    graph = Graph()

    # Define URIs for our sample entities using the ontology namespaces
    cve_uri = CVE["CVE-2023-12345"]  # Vulnerability instance
    product_uri = PRODUCT["apache-http-server"]  # Software product instance
    weakness_uri = CWE["CWE-79"]  # Weakness instance
    ref_uri = URIRef("https://example.com/advisory")  # External reference (using generic URI)

    # Add the vulnerability node with its type and key attributes
    # This represents a CVE entry from the NVD dataset
    graph.add((cve_uri, RDF.type, CG.Vulnerability))  # Classify as Vulnerability
    graph.add((cve_uri, RDFS.label, Literal("CVE-2023-12345")))  # Human-readable ID
    graph.add((cve_uri, CG.hasSeverity, Literal("HIGH")))  # Severity level
    graph.add((cve_uri, CG.hasScore, Literal("7.5")))  # CVSS score (as string for simplicity)

    # Add the software product node
    # This represents an affected product extracted from NVD's CPE data
    graph.add((product_uri, RDF.type, CG.SoftwareProduct))  # Classify as SoftwareProduct
    graph.add((product_uri, RDFS.label, Literal("Apache HTTP Server")))  # Product name
    graph.add((cve_uri, CG.affects, product_uri))  # Link: CVE affects this product

    # Add the weakness node
    # This represents a CWE entry from the CWE dataset, linked to the vulnerability
    graph.add((weakness_uri, RDF.type, CG.Weakness))  # Classify as Weakness
    graph.add((weakness_uri, RDFS.label, Literal("CWE-79")))  # CWE ID
    graph.add((weakness_uri, CG.description, Literal("Cross-site Scripting")))  # Description from CWE
    graph.add((cve_uri, CG.hasWeakness, weakness_uri))  # Link: CVE exhibits this weakness

    # Add the reference node
    # This represents an external resource like an advisory or patch from NVD
    graph.add((ref_uri, RDF.type, CG.Reference))  # Classify as Reference
    graph.add((ref_uri, RDFS.label, Literal("Advisory Link")))  # Descriptive label
    graph.add((cve_uri, CG.hasReference, ref_uri))  # Link: CVE has this reference

    return graph


def node_label(graph: Graph, node) -> str:
    """
    Generate a human-readable label for a graph node.

    For entities with rdfs:label (like CVE IDs or product names), use that.
    Otherwise, extract the last part of the URI for brevity (e.g., 'CVE-2023-12345' from full URI).

    This ensures the visualization shows meaningful names instead of long URIs.
    """
    label = graph.value(node, RDFS.label)  # Check if node has a label property

    if label:
        return str(label)

    # Fallback: parse URI to get a short identifier
    value = str(node)

    if "/" in value:
        return value.rstrip("/").split("/")[-1]  # Last segment after '/'

    return value


def predicate_label(predicate) -> str:
    """
    Generate a short label for a predicate (relationship type).

    Extracts the property name from the full URI (e.g., 'affects' from CG.affects).
    This makes edge labels in the graph readable and concise.
    """
    return str(predicate).rstrip("/").split("/")[-1]


def visualize_graph(graph: Graph) -> None:
    """
    Convert the RDF graph to a NetworkX directed graph and create a visual plot.

    This function filters the RDF triples to show only domain-relevant relationships
    (e.g., affects, hasWeakness), ignoring ontology metadata. It then uses Matplotlib
    to draw a colorful graph with nodes colored by type and edges labeled by relationship.

    The result is saved as a PNG image and displayed, providing an intuitive view
    of how the knowledge graph connects cybersecurity concepts.
    """
    G = nx.DiGraph()  # Directed graph for relationships

    # Define which predicates to visualize (focus on domain relationships, not schema)
    # Exclude RDF.type, RDFS.label, etc., to show meaningful connections
    visible_predicates = {
        CG.affects,      # Vulnerability -> Product
        CG.hasWeakness,  # Vulnerability -> Weakness
        CG.hasReference, # Vulnerability -> Reference
        CG.hasSeverity,  # Vulnerability -> Severity (literal)
        CG.hasScore,     # Vulnerability -> Score (literal)
        CG.description,  # Any entity -> Description (literal)
    }

    edge_labels = {}  # Dictionary to store labels for edges

    # Iterate through RDF triples and add visible ones to NetworkX graph
    for subject, predicate, obj in graph:
        if predicate not in visible_predicates:
            continue  # Skip ontology/schema triples

        s_label = node_label(graph, subject)  # Get readable subject label
        o_label = node_label(graph, obj)      # Get readable object label
        p_label = predicate_label(predicate)  # Get readable predicate label

        G.add_edge(s_label, o_label)  # Add directed edge
        edge_labels[(s_label, o_label)] = p_label  # Store label for this edge

    # Assign colors to nodes based on their type/content for visual distinction
    node_colors = []

    for node in G.nodes:
        node_lower = node.lower()

        if node.startswith("CVE"):
            node_colors.append("red")  # Vulnerabilities
        elif "apache" in node_lower:  # Example product
            node_colors.append("skyblue")  # Software products
        elif node.startswith("CWE") or "scripting" in node_lower:  # Weaknesses
            node_colors.append("lightgreen")
        elif "advisory" in node_lower:  # References
            node_colors.append("orange")
        else:
            node_colors.append("lightgray")  # Literals or others

    # Set up the plot with a large figure for clarity
    plt.figure(figsize=(12, 7), facecolor='none')  # Transparent background

    # Use spring layout for natural node positioning (force-directed)
    pos = nx.spring_layout(G, seed=42, k=1.2)  # Seed for reproducible layout

    # Draw the main graph elements
    nx.draw(
        G,
        pos,
        with_labels=True,      # Show node labels
        node_color=node_colors, # Color nodes by type
        node_size=2600,        # Large nodes for readability
        font_size=9,           # Readable font
        font_weight="bold",    # Emphasize labels
        arrows=True,           # Show direction of relationships
        arrowsize=20,          # Prominent arrows
    )

    # Add labels to edges showing the relationship type
    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        font_size=8,  # Smaller font for edges
    )

    # Add title and remove axes for clean look
    plt.title("Knowledge Graph Sample")
    plt.axis("off")
    plt.tight_layout()

    # Save high-resolution image

    # Create a legend to explain node colors
    legend_elements = [
        mpatches.Patch(color='red', label='Vulnerability (CVE) - NVD'),
        mpatches.Patch(color='skyblue', label='Software Product - NVD'),
        mpatches.Patch(color='lightgreen', label='Weakness (CWE) - CWE Dataset'),
        mpatches.Patch(color='orange', label='Reference - NVD'),
        mpatches.Patch(color='lightgray', label='Attributes / Literals')
    ]

    plt.legend(handles=legend_elements, loc="best")  # Place legend in best position

    # Save the image before showing it. In some backends, plt.show() can clear or close
    # the figure, causing the saved PNG to miss elements such as the legend.
    # Save both PNG and SVG with transparent background
    plt.savefig("kg_sample.png", dpi=300, bbox_inches="tight", transparent=True)
    plt.savefig("kg_sample.svg", bbox_inches="tight", transparent=True)
    plt.show()  # Display the plot (in interactive environments)


if __name__ == "__main__":
    # Main execution: create sample, print stats, visualize, and save
    sample_graph = create_sample_graph()
    print(f"Sample graph has {len(sample_graph)} triples")  # Show graph size

    visualize_graph(sample_graph)  # Generate and display visualization

    print("Visualization saved as 'kg_sample.png'")  # Confirm save
