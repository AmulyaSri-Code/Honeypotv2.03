import threading
import requests
import time

def make_request(i):
    try:
        response = requests.get('http://localhost:8080', timeout=5)
        print(f"Request {i}: {response.status_code}")
    except Exception as e:
        print(f"Request {i} failed: {e}")

threads = []
print("Starting stress test with 20 concurrent requests...")
start_time = time.time()

for i in range(20):
    t = threading.Thread(target=make_request, args=(i,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print(f"Stress test completed in {time.time() - start_time:.2f} seconds")
