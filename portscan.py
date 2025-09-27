#!/usr/bin/env python3
"""
Realtime TCP SYN scanner with ephemeral source ports (RandShort).
Includes Stop Scan button to cancel an in-progress scan.
Save and run with appropriate privileges.
"""

import socket
import time
import threading
import queue
import tkinter as tk
from tkinter import ttk
from scapy.all import IP, TCP, sr1, send, conf, RandShort

# ----------------- Config -----------------
MAX_CONCURRENT = 80        # concurrent worker threads (tune to your machine)
QUEUE_POLL_MS = 40         # how often GUI polls the result queue (ms)
WORKER_START_SLEEP = 0.002 # small delay between starting worker threads
SR1_TIMEOUT = 1.0          # timeout for sr1 calls (seconds) - small so cancellation is snappy

# ----------------- Network helpers -----------------
def detect_interface_and_ip():
    dst = "8.8.8.8"
    try:
        route_info = conf.route.route(dst)
        src_ip = route_info[1]
        iface = route_info[0]
        return iface, src_ip
    except Exception:
        return None, None

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except:
        return None

# ----------------- Queue and GUI update -----------------
result_queue = queue.Queue()

def queue_put(result_text, color="black", is_open=False, open_text=None):
    """Place a GUI update item into the queue for the GUI thread."""
    result_queue.put((result_text, color, is_open, open_text))

def poll_queue():
    """GUI thread: flush the result queue into the Listboxes."""
    try:
        while True:
            result_text, color, is_open, open_text = result_queue.get_nowait()
            idx = result_box.size()
            result_box.insert(tk.END, result_text)
            try:
                result_box.itemconfig(idx, fg=color)
            except Exception:
                pass

            if is_open and open_text:
                idx2 = open_box.size()
                open_box.insert(tk.END, open_text)
                try:
                    open_box.itemconfig(idx2, fg="green")
                except Exception:
                    pass

            result_queue.task_done()
    except queue.Empty:
        pass
    root.after(QUEUE_POLL_MS, poll_queue)

# ----------------- Cancellation state -----------------
scan_stop_event = threading.Event()
scan_running_lock = threading.Lock()
scan_threads = []  # keep references so watcher can join

def set_ui_running(running: bool):
    """Enable/disable buttons depending on scan state (called on GUI thread)."""
    if running:
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
    else:
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

# ----------------- Worker -----------------
def syn_probe_worker(target_ip, port, iface, src_ip, profile, sem):
    """
    Worker thread: send SYN with chosen ephemeral source port (RandShort),
    wait for response, send RST using same sport, and queue GUI update.
    """
    try:
        # If stop requested before starting probe, exit early
        if scan_stop_event.is_set():
            return

        conf.verb = 0
        conf.iface = iface

        # Choose explicit ephemeral source port
        sport = int(RandShort())

        # Build and send SYN
        syn_pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
        try:
            response = sr1(syn_pkt, timeout=SR1_TIMEOUT)
        except Exception as e:
            # If cancellation requested, skip reporting errors
            if not scan_stop_event.is_set():
                queue_put(f"Port {port}: ERROR ({e})", "orange")
            return

        # Respect stop event: don't post further results if user cancelled
        if scan_stop_event.is_set():
            return

        if response is None:
            queue_put(f"Port {port}: FILTERED or NO RESPONSE", "gray")
            return

        if response.haslayer(TCP):
            flags = response[TCP].flags
            # SYN-ACK => open
            if flags == 0x12:
                # send RST to close the half-open connection (use same sport)
                try:
                    rst_pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="R", seq=response[TCP].ack)
                    send(rst_pkt, verbose=0)
                except Exception:
                    pass

                banner = ""
                if profile == "Aggressive":
                    # banner grab may take time; check stop_event before and after
                    if not scan_stop_event.is_set():
                        banner = grab_banner(target_ip, port) or ""
                    else:
                        banner = ""

                display = f"Port {port}: OPEN" + (f" -> {banner}" if banner else "")
                open_display = f"Port {port}" + (f" | {banner}" if banner else "")
                queue_put(display, "green", is_open=True, open_text=open_display)
                return

            # RST => closed
            elif flags == 0x14:
                queue_put(f"Port {port}: CLOSED", "red")
                return
            else:
                queue_put(f"Port {port}: UNKNOWN RESPONSE (Flags: {hex(flags)})", "orange")
                return

        queue_put(f"Port {port}: UNKNOWN RESPONSE", "black")

    finally:
        # Always release semaphore slot
        try:
            sem.release()
        except Exception:
            pass

# ----------------- Scan control -----------------
def acquire_sem_or_stop(sem):
    """Try to acquire semaphore but return False immediately if stop requested."""
    while not scan_stop_event.is_set():
        acquired = sem.acquire(timeout=0.1)
        if acquired:
            return True
    return False

def start_scan():
    # Prevent concurrent start attempts
    if scan_running_lock.locked():
        queue_put("Scan already running.", "orange")
        return

    target_ip = ip_entry.get().strip()
    profile = profile_var.get()

    try:
        start = int(start_port.get())
        end = int(end_port.get())
        if start < 1 or end > 65535 or start > end:
            raise ValueError
        ports = list(range(start, end + 1))
    except ValueError:
        queue_put("Invalid port range. Please enter valid numbers.", "orange")
        return

    # clear GUI
    result_box.delete(0, tk.END)
    open_box.delete(0, tk.END)

    iface, src_ip = detect_interface_and_ip()
    if not iface or not src_ip:
        queue_put("Could not determine network interface. Please check your network connection.", "orange")
        return

    # initialize cancellation event and thread list
    scan_stop_event.clear()
    global scan_threads
    scan_threads = []

    sem = threading.Semaphore(MAX_CONCURRENT)

    # mark UI as running (must run on GUI thread)
    set_ui_running(True)
    # lock to indicate a scan is running
    scan_running_lock.acquire()

    def launcher():
        try:
            for p in ports:
                # If user pressed stop, break launching more workers
                if scan_stop_event.is_set():
                    break

                # try acquiring semaphore but break if stop requested
                ok = acquire_sem_or_stop(sem)
                if not ok:
                    break

                # Before starting the worker, check stop again
                if scan_stop_event.is_set():
                    sem.release()
                    break

                t = threading.Thread(target=syn_probe_worker, args=(target_ip, p, iface, src_ip, profile, sem), daemon=True)
                scan_threads.append(t)
                t.start()
                time.sleep(WORKER_START_SLEEP)
        finally:
            # After launching (or stoppage), start watcher to join and finalize
            def watcher():
                # wait for all worker threads to finish (they should exit quickly after stop_event)
                for t in scan_threads:
                    t.join()
                # Post final message
                if scan_stop_event.is_set():
                    queue_put("Scan stopped by user.", "black")
                else:
                    queue_put("Scan complete.", "black")
                # reset UI (must be done on GUI thread)
                root.after(0, lambda: (set_ui_running(False), scan_running_lock.release()))
            threading.Thread(target=watcher, daemon=True).start()

    threading.Thread(target=launcher, daemon=True).start()

def stop_scan():
    # Request cancellation
    if not scan_running_lock.locked():
        return
    scan_stop_event.set()
    # immediately disable stop button to avoid multiple presses
    stop_button.config(state=tk.DISABLED)
    queue_put("Stopping scan...", "black")

# ----------------- GUI Setup -----------------
iface, src_ip = detect_interface_and_ip()

root = tk.Tk()
root.title("TCP SYN Scanner (Realtime) - Stopable")

tk.Label(root, text="Target IP:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

tk.Label(root, text="Interface:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
tk.Label(root, text=iface or "N/A").grid(row=1, column=1, padx=5, pady=2, sticky="w")

tk.Label(root, text="Source IP:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
tk.Label(root, text=src_ip or "N/A").grid(row=2, column=1, padx=5, pady=2, sticky="w")

tk.Label(root, text="Start Port:").grid(row=3, column=0, padx=5, pady=2, sticky="w")
start_port = tk.Entry(root)
start_port.insert(0, "20")
start_port.grid(row=3, column=1, padx=5, pady=2, sticky="ew")

tk.Label(root, text="End Port:").grid(row=4, column=0, padx=5, pady=2, sticky="w")
end_port = tk.Entry(root)
end_port.insert(0, "102")
end_port.grid(row=4, column=1, padx=5, pady=2, sticky="ew")

tk.Label(root, text="Scan Profile:").grid(row=5, column=0, padx=5, pady=2, sticky="w")
profile_var = tk.StringVar(value="Stealth")
profile_menu = ttk.Combobox(root, textvariable=profile_var, values=["Stealth", "Aggressive"])
profile_menu.grid(row=5, column=1, padx=5, pady=2, sticky="ew")

start_button = tk.Button(root, text="Start Scan", command=start_scan)
start_button.grid(row=6, column=0, padx=5, pady=8, sticky="ew")

stop_button = tk.Button(root, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
stop_button.grid(row=6, column=1, padx=5, pady=8, sticky="ew")

tk.Label(root, text="Scan Results:").grid(row=7, column=0, columnspan=2, padx=5, pady=2, sticky="w")
result_box = tk.Listbox(root, width=90, height=14)
result_box.grid(row=8, column=0, columnspan=2, padx=5, pady=2, sticky="ew")

tk.Label(root, text="Open Ports & Banners:").grid(row=9, column=0, columnspan=2, padx=5, pady=2, sticky="w")
open_box = tk.Listbox(root, width=90, height=6)
open_box.grid(row=10, column=0, columnspan=2, padx=5, pady=2, sticky="ew")

root.grid_columnconfigure(1, weight=1)

# start queue polling and run GUI
root.after(QUEUE_POLL_MS, poll_queue)
root.mainloop()
