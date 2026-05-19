
# Railway friendly background worker example
import time

def run_worker():
    while True:
        print("Worker running...")
        time.sleep(10)

if __name__ == "__main__":
    run_worker()
