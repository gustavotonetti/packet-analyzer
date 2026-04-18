from datetime import datetime

LOG_FILE = "capture.log"

def log(data: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}]\n{data}\n{'-'*50}\n")