"""Keep the UDP router and FreeRADIUS alive together; exit if either dies."""
import os
import signal
import subprocess
import sys
import time

children = []


def stop(signum, frame):
    for child in children:
        if child.poll() is None:
            child.terminate()


for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, stop)

children.append(subprocess.Popen([sys.argv[1], '-fxx', '-l', 'stdout']))
children.append(subprocess.Popen([sys.executable, '/usr/local/sbin/downstream_runtime.py']))
while all(child.poll() is None for child in children):
    time.sleep(.25)
stop(None, None)
for child in children:
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
sys.exit(1)
