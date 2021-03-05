from pythonping import ping


result = ping('192.168.1.1', verbose=True)
test = str(result)
if test.startswith("Request timed out"):
    print("Network error")
else:
    print("Network active")