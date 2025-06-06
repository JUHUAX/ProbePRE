import subprocess
import time
import os
import signal
import psutil


def start_instrument(binary_path):
    print("插桩开启")
    process = subprocess.Popen(["./run", "run", "taint", binary_path])
    time.sleep(3)
    return process

def reboot_instrument(binary_path):
    time.sleep(3)
    print("插桩重启")
    process = subprocess.Popen(["./run", "run", "taint", binary_path])
    time.sleep(3)
    return process

def stop_instrument(process):
    psutil_process = psutil.Process(process.pid)
    for child in psutil_process.children(recursive=True):
        child.kill()
    psutil_process.kill()
    time.sleep(3)

def get_instrument_status(process):
    psutil_process = psutil.Process(process.pid)
    if psutil_process.is_running():
        return True
    else:
        return False