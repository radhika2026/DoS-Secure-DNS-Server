import time
import dns.resolver
import matplotlib.pyplot as plt

def simulate_rate_limited_ip(qps, duration, resolver):
    timestamps = []
    statuses = [] 

    end_time = time.time() + duration
    while time.time() < end_time:
        start_time = time.time()
        try:
            resolver.resolve('ns1.example.com', dns.rdatatype.A)
            timestamps.append(time.time())
            statuses.append("Allowed")
        except Exception:
            timestamps.append(time.time())
            statuses.append("Blocked")
        print(f"Query at {time.time()} - Status: {statuses[-1]}")
        time.sleep(max(0, 1 / qps - (time.time() - start_time)))

    return timestamps, statuses

def experiment_rate_limiting(qps_levels, duration, host="127.0.0.1", port=31110):
    results = {}

    resolver = dns.resolver.Resolver()
    resolver.port = port
    resolver.nameservers = [host]

    for qps in qps_levels:
        print(f"Running experiment for QPS={qps}...")
        timestamps, statuses = simulate_rate_limited_ip(qps, duration, resolver)
        results[qps] = {"timestamps": timestamps, "statuses": statuses}

    return results

def plot_experiment_2(results):
    plt.figure(figsize=(10, 6))

    for qps, data in results.items():
        timestamps = data["timestamps"]
        statuses = data["statuses"]
        
        allowed_times = [t for t, s in zip(timestamps, statuses) if s == "Allowed"]
        blocked_times = [t for t, s in zip(timestamps, statuses) if s == "Blocked"]

        plt.plot(
            allowed_times, [qps] * len(allowed_times), 'go', label=f"Allowed (QPS={qps})" if qps == list(results.keys())[0] else ""
        )
        plt.plot(
            blocked_times, [qps] * len(blocked_times), 'ro', label=f"Blocked (QPS={qps})" if qps == list(results.keys())[0] else ""
        )

    plt.title("Rate Limiting: Allowed vs Blocked Queries")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Queries Per Second (QPS)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    qps_levels = [10, 50, 100]  
    duration = 10

    results = experiment_rate_limiting(qps_levels, duration)
    plot_experiment_2(results)
