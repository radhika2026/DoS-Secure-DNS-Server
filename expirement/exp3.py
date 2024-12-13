import time
import dns.resolver
import matplotlib.pyplot as plt
from collections import Counter

# Simulate queries at a fixed QPS
def simulate_fixed_qps(qps, duration, resolver, fail_primary_at=None):
    """
    Simulates queries to Gatekeeper at a fixed QPS, tracking distribution between servers
    and failed queries.

    Args:
        qps (int): Queries per second to send.
        duration (int): Duration of the simulation in seconds.
        resolver (Resolver): DNS resolver instance.
        fail_primary_at (int): Time (in seconds) when the primary server fails.

    Returns:
        dict: Distribution counter (e.g., {"primary": 50, "secondary": 50, "failed": 10}).
    """
    distribution = Counter()
    total_queries = qps * duration
    query_interval = 1 / qps
    start_time = time.time()

    for i in range(total_queries):
        current_time = time.time() - start_time
        try:
            # Simulate primary server failure
            if fail_primary_at and current_time >= fail_primary_at:
                server = "secondary"
            else:
                server = "primary" if distribution["primary"] <= distribution["secondary"] else "secondary"

            # Send a query
            resolver.resolve('ns1.example.com', dns.rdatatype.A)
            distribution[server] += 1
        except Exception as e:
            # Log failed queries
            distribution["failed"] += 1

        # Wait until the next query
        time.sleep(max(0, query_interval - (time.time() - (start_time + i * query_interval))))

    return distribution

# Plotting function with QPS
def plot_fixed_qps(distributions, failover=False):
    """
    Plots query distribution between primary, secondary, and failed queries.

    Args:
        distributions (dict): Distribution counters at different QPS levels.
        failover (bool): Whether the graph includes failover scenarios.
    """
    qps_levels = list(distributions.keys())
    primary_counts = [distributions[qps]["primary"] for qps in qps_levels]
    secondary_counts = [distributions[qps]["secondary"] for qps in qps_levels]
    failed_counts = [distributions[qps]["failed"] for qps in qps_levels]

    plt.figure(figsize=(10, 6))
    bar_width = 0.25
    x = range(len(qps_levels))

    # Plot bars for primary, secondary, and failed queries
    plt.bar(x, primary_counts, width=bar_width, label="Primary Server", alpha=0.7)
    plt.bar([p + bar_width for p in x], secondary_counts, width=bar_width, label="Secondary Server", alpha=0.7)
    plt.bar([p + 2 * bar_width for p in x], failed_counts, width=bar_width, label="Failed Queries", alpha=0.7, color='red')

    plt.xlabel("QPS Levels")
    plt.ylabel("Query Count")
    plt.title("Query Distribution Between Primary, Secondary, and Failed Queries" + (" with Failover" if failover else ""))
    plt.xticks([p + bar_width for p in x], qps_levels)
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.show()

# Main execution
if __name__ == "__main__":
    resolver = dns.resolver.Resolver()
    resolver.port = 31110
    resolver.nameservers = ["127.0.0.1"]

    qps_levels = [10, 50, 100]  # Test different QPS levels
    duration = 5  # Duration of each test (in seconds)

    # Run fixed QPS distribution test
    distributions = {}
    for qps in qps_levels:
        print(f"Running fixed QPS test for QPS={qps}...")
        distributions[qps] = simulate_fixed_qps(qps, duration, resolver)

    # Plot normal distribution results
    plot_fixed_qps(distributions)

    # Run failover test
    failover_distributions = {}
    for qps in qps_levels:
        print(f"Running failover test for QPS={qps} with primary failure...")
        failover_distributions[qps] = simulate_fixed_qps(qps, duration, resolver, fail_primary_at=5)

    # Plot failover distribution results
    plot_fixed_qps(failover_distributions, failover=True)
