import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import matplotlib.pyplot as plt

def dns_query(i, resolver, timer, results, unique_ip):
    times = []
    successes = 0
    failures = 0

    while time.time() < timer:
        begin = time.time()
        try:
            resolver.nameservers = [unique_ip]
            resolver.resolve('ns1.example.com', dns.rdatatype.A)
            times.append(time.time() - begin)
            successes += 1
        except Exception:
            failures += 1

    results.append({
        "thread_id": i,
        "successes": successes,
        "failures": failures,
        "response_times": times,
    })

def attack(host="127.0.0.1", port=31110, timeout=100, num_threads=5):
    timer = time.time() + timeout
    results = []

    executor = ThreadPoolExecutor(num_threads)
    for i in range(num_threads):
        unique_ip = f"127.0.{i}.1"
        resolver = dns.resolver.Resolver()
        resolver.port = port
        executor.submit(dns_query, i, resolver, timer, results, unique_ip)
    executor.shutdown()

    return results

def analyze_results(results):
    metrics = []
    for result in results:
        thread_id = result["thread_id"]
        successes = result["successes"]
        failures = result["failures"]
        response_times = result["response_times"]

        success_rate = (successes / (successes + failures)) * 100 if successes + failures > 0 else 0
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        metrics.append({
            "thread_id": thread_id,
            "success_rate": success_rate,
            "avg_response_time": avg_response_time,
            "successes": successes,
            "failures": failures,
        })
    return metrics

def experiment_dos_resilience(host, port, timeout, thread_counts):
    all_metrics = {}

    for num_threads in thread_counts:
        print(f"Running DoS simulation with {num_threads} threads...")
        results = attack(host, port, timeout, num_threads)
        all_metrics[num_threads] = analyze_results(results)

    return all_metrics

def plot_dos_resilience(all_metrics):
    thread_counts = list(all_metrics.keys())
    overall_success_rates = []
    avg_response_times = []
    total_failures = []

    for thread_count in thread_counts:
        metrics = all_metrics[thread_count]
        overall_success_rate = sum(m["successes"] for m in metrics) / sum(
            m["successes"] + m["failures"] for m in metrics
        ) * 100
        avg_response_time = sum(m["avg_response_time"] for m in metrics) / len(metrics)
        total_failure = sum(m["failures"] for m in metrics)

        overall_success_rates.append(overall_success_rate)
        avg_response_times.append(avg_response_time)
        total_failures.append(total_failure)

    plt.figure(figsize=(10, 6))
    plt.plot(thread_counts, overall_success_rates, marker='o', label="Success Rate (%)")
    plt.xlabel("Number of Threads")
    plt.ylabel("Success Rate (%)")
    plt.title("System Resilience: Success Rate vs Threads")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 6))
    plt.plot(thread_counts, avg_response_times, marker='o', color='orange', label="Avg Response Time (s)")
    plt.xlabel("Number of Threads")
    plt.ylabel("Avg Response Time (s)")
    plt.title("System Resilience: Response Time vs Threads")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 6))
    plt.plot(thread_counts, total_failures, marker='o', color='red', label="Failed Queries")
    plt.xlabel("Number of Threads")
    plt.ylabel("Number of Failed Queries")
    plt.title("System Resilience: Failed Queries vs Threads")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default="127.0.0.1", help="Host IP address")
    parser.add_argument('--port', type=int, default=31110, help="Host port")
    parser.add_argument('--timeout', type=int, default=10, help='Attack duration')
    parser.add_argument('--threads', type=int, nargs="+", default=[5, 10, 20, 50], help='List of thread counts for testing')

    args = parser.parse_args()
    all_metrics = experiment_dos_resilience(args.host, args.port, args.timeout, args.threads)
    plot_dos_resilience(all_metrics)
