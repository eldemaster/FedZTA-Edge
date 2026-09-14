import asyncio
import aiohttp
import time

TOTAL_REQUESTS = 1000
CONCURRENCY = 10
URL = "http://192.168.1.147:8080/api/v1/sensors/temp"

async def fetch(session):
    start = time.time()
    try:
        async with session.get(URL, timeout=5) as response:
            await response.read()
            return response.status, time.time() - start
    except Exception:
        return 0, time.time() - start

async def worker(session, queue, results):
    while True:
        try:
            req_id = queue.get_nowait()
        except asyncio.QueueEmpty:
            break
        status, latency = await fetch(session)
        results.append((status, latency))
        queue.task_done()

async def main():
    print(f"[*] Starting Stress Test: {TOTAL_REQUESTS} requests, {CONCURRENCY} concurrency...")
    queue = asyncio.Queue()
    for i in range(TOTAL_REQUESTS):
        queue.put_nowait(i)
    
    results = []
    start_time = time.time()
    
    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(worker(session, queue, results)) for _ in range(CONCURRENCY)]
        await asyncio.gather(*tasks)
        
    total_time = time.time() - start_time
    rps = TOTAL_REQUESTS / total_time
    
    latencies = sorted([lat for status, lat in results if status != 0])
    p50 = latencies[int(len(latencies)*0.5)] * 1000 if latencies else 0
    p95 = latencies[int(len(latencies)*0.95)] * 1000 if latencies else 0
    p99 = latencies[int(len(latencies)*0.99)] * 1000 if latencies else 0
    
    successes = sum(1 for status, _ in results if status == 200)
    failures = len(results) - successes
    
    print("\n" + "="*30)
    print("      STRESS TEST RESULTS")
    print("="*30)
    print(f"Total Requests:      {TOTAL_REQUESTS}")
    print(f"Concurrency Level:   {CONCURRENCY}")
    print(f"Time taken for tests:{total_time:.2f} seconds")
    print(f"Requests per second: {rps:.2f} RPS")
    print(f"Successful Requests: {successes}")
    print(f"Failed Requests:     {failures}")
    print("\n--- Latency Percentiles (ms) ---")
    print(f"50th percentile:     {p50:.2f} ms")
    print(f"95th percentile:     {p95:.2f} ms")
    print(f"99th percentile:     {p99:.2f} ms")
    print("="*30)

asyncio.run(main())
