from datetime import datetime

LOG_FILE = "capture.log"

def log(data: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #encoding="utf-8" evita UnicodeEncodeError no Windows (cp1252) ao gravar
    #caracteres como '→' usados na saída do parser.
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}]\n{data}\n{'-'*50}\n")