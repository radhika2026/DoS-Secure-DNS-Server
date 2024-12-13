import time
import dns.resolver
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Function to simulate queries
def simulate_queries(qps, duration, resolver, host="127.0.0.1", port=31110):
    total_queries = 0
    successful_queries = 0
    response_times = []

    end_time = time.time() + duration
    while time.time() < end_time:
        begin = time.time()
        try:
            resolver.resolve('www.example.com', dns.rdatatype.A)
            response_times.append(time.time() - begin)
            successful_queries += 1
        except Exception:
            pass
        total_queries += 1

        # Adjust query interval to maintain QPS
        time.sleep(max(0, 1 / qps - (time.time() - begin)))

    return total_queries, successful_queries, response_times

# Function to run the simulation at different QPS levels
def test_performance(qps_levels, duration, resolver, host="127.0.0.1", port=31110):
    metrics = {
        "qps": [],
        "success_rate": [],
        "avg_response_time": [],
        "throughput": []
    }
    for qps in qps_levels:
        print(f"Testing at {qps} QPS...")
        total_queries, successful_queries, response_times = simulate_queries(qps, duration, resolver, host, port)
        success_rate = (successful_queries / total_queries) * 100 if total_queries > 0 else 0
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        throughput = successful_queries / duration

        metrics["qps"].append(qps)
        metrics["success_rate"].append(success_rate)
        metrics["avg_response_time"].append(avg_response_time)
        metrics["throughput"].append(throughput)

    return metrics

# Plotting results
def plot_results(metrics):
    plt.figure(figsize=(10, 6))

    # Success rate
    plt.subplot(2, 1, 1)
    plt.plot(metrics["qps"], metrics["success_rate"], label="Success Rate (%)", marker="o")
    plt.title("System Performance under Various QPS")
    plt.ylabel("Success Rate (%)")
    plt.grid(True)

    # Avg response time
    plt.subplot(2, 1, 2)
    plt.plot(metrics["qps"], metrics["avg_response_time"], label="Avg Response Time (s)", marker="o", color="r")
    plt.xlabel("Queries Per Second (QPS)")
    plt.ylabel("Avg Response Time (s)")
    plt.grid(True)

    plt.tight_layout()
    plt.show()

    # Throughput vs QPS
    plt.figure(figsize=(8, 5))
    plt.plot(metrics["qps"], metrics["throughput"], label="Throughput (QPS)", marker="o", color="g")
    plt.title("System Throughput under Various QPS")
    plt.xlabel("Queries Per Second (QPS)")
    plt.ylabel("Throughput (QPS)")
    plt.grid(True)
    plt.show()

# Main execution
if __name__ == "__main__":
    resolver = dns.resolver.Resolver()
    resolver.port = 31110
    resolver.nameservers = ["127.0.0.1"]

    qps_levels = [10, 50, 100, 200, 500]  # Define QPS levels to test
    duration = 10  # Duration for each QPS test (seconds)

    metrics = test_performance(qps_levels, duration, resolver)
    plot_results(metrics)
