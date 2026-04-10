#!/usr/bin/python3
import argparse
import asyncio
import multiprocessing
import nest_asyncio
import os
import pyshark
import subprocess
import time
import signal
import resource
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

nest_asyncio.apply()
multiprocessing.set_start_method('spawn', force=True)  # FIX 2: tránh fork copy asyncio state

# --- CONFIGURATION ---
INTERFACE = "eth0"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
PROXY_ENDPOINT = "162.159.198.1:443"
INPUT_WEBSITES_FILE = "./target_websites.txt"
# ---------------------

parser = argparse.ArgumentParser(description="Capture network traffic.")
parser.add_argument("--trace_file_dir", dest="trace_file_dir", default="./traces/")
parser.add_argument("--target_websites", dest="target_websites", default=INPUT_WEBSITES_FILE)
parser.add_argument("--websites_count", dest="websites_count", default=10, type=int)
parser.add_argument("--gap_count", dest="gap_count", default=0, type=int)
parser.add_argument("--access_count", dest="access_count", default=2, type=int)
parser.add_argument('--filter', action='store_true', default=False)
args = parser.parse_args()


# ─── CHROME ───────────────────────────────────────────────────────────────────

def open_website(url):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--incognito")
    options.add_argument("--disk-cache-size=0")
    options.add_argument(f"--proxy-server=socks5://{PROXY_HOST}:{PROXY_PORT}")
    options.add_argument("--ignore-certificate-errors")
    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        print(f"-----Chrome launch failed: {e}")
        return
    try:
        driver.set_page_load_timeout(10)
        driver.get(url)
        print(f"-----Loaded: {driver.title}")
        time.sleep(5)
    except Exception as e:
        print(f"-----Browser Error: {e}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass


# ─── TCPDUMP ──────────────────────────────────────────────────────────────────

def _run_tcpdump(trace_file):
    # os.execv thay thế process hiện tại — không tạo child process
    os.execv("/usr/bin/tcpdump", [
        "tcpdump", "-i", INTERFACE,
        "-w", trace_file,
        "port", "80", "or", "port", "443", "or", "port", "853"
    ])

def start_tcpdump(trace_file):
    print("-----Running tcpdump")
    proc = multiprocessing.Process(target=_run_tcpdump, args=(trace_file,))
    proc.start()
    return proc

def stop_tcpdump(proc):
    print("-----Stopping tcpdump")
    if proc is not None and proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)


# ─── MASQUE PROXY ─────────────────────────────────────────────────────────────

def _run_proxy():
    # os.execv thay thế process hiện tại — không tạo child process
    os.execv("./masque-plus", ["./masque-plus", "--endpoint", PROXY_ENDPOINT])

def stop_proxy(proc):
    print("-----Stopping Masque Proxy")
    # Kill process đang giữ port 1080
    os.system("fuser -k 1080/tcp 2>/dev/null")
    os.system("pkill -9 usque 2>/dev/null")
    if proc is not None and proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
    time.sleep(1)

def start_proxy():
    print("-----Starting Masque Proxy")
    # Dọn sạch trước khi start
    os.system("fuser -k 1080/tcp 2>/dev/null")
    os.system("pkill -9 usque 2>/dev/null")
    time.sleep(1)
    proc = multiprocessing.Process(target=_run_proxy)
    proc.start()
    time.sleep(3)
    return proc
# ─── PACKET CAPTURE ───────────────────────────────────────────────────────────

def packet_capture(url, index, pcap_base_dir):
    tcp_proc = None
    proxy_proc = None
    web_proc = None
    trace_file = ""

    domain = url.split("//")[1]
    dir_name = "_".join(domain.split("."))
    dir_name = "_".join(dir_name.split("/"))[:-1]

    website_pcap_dir = os.path.join(pcap_base_dir, dir_name)
    os.makedirs(website_pcap_dir, exist_ok=True)

    try:
        trace_file = os.path.join(website_pcap_dir, f"{index + 1}_{dir_name}.pcap")
        subprocess.run(["touch", trace_file])
        subprocess.run(["chmod", "o=rw", trace_file])

        tcp_proc = start_tcpdump(trace_file)
        time.sleep(1)

        proxy_proc = start_proxy()

        web_proc = multiprocessing.Process(target=open_website, args=(url,))
        web_proc.start()
        web_proc.join(timeout=20)
        if web_proc.is_alive():
            print("-----Chrome timeout, terminating...")
            web_proc.terminate()
            web_proc.join(timeout=5)
            if web_proc.is_alive():
                web_proc.kill()
                web_proc.join(timeout=2)

    except Exception as e:
        print(f"Error during capture: {e}")
        if trace_file and os.path.exists(trace_file):
            os.remove(trace_file)
    finally:
        if web_proc is not None and web_proc.is_alive():
            web_proc.terminate()
            web_proc.join(timeout=3)
        stop_proxy(proxy_proc)
        stop_tcpdump(tcp_proc)
        os.system("pkill -9 chromedriver 2>/dev/null")
        os.system("pkill -9 chrome 2>/dev/null")
        time.sleep(1)

    return trace_file, dir_name


# ─── PYSHARK ──────────────────────────────────────────────────────────────────

def contains_quic(trace_file):
    cap = None
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        cap = pyshark.FileCapture(trace_file, display_filter="quic")
        for packet in cap:
            for layer in packet:
                if layer.layer_name == 'quic':
                    if hasattr(packet, 'udp') and (packet.udp.srcport == "443" or packet.udp.dstport == "443"):
                        return True
        return False
    except Exception as e:
        print(f"Pyshark read error: {e}")
        return False
    finally:
        if cap is not None:
            try:
                cap.close()
            except Exception:
                pass
        os.system("pkill -9 tshark 2>/dev/null")
        time.sleep(0.5)
        asyncio.set_event_loop(asyncio.new_event_loop())


def parse_pcap(trace_file_path):
    features = list()
    trace_file = None
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        host_ip = os.popen("hostname -i").read().strip().split(" ")[0]
        trace_file = pyshark.FileCapture(trace_file_path, keep_packets=False)

        for packet in trace_file:
            try:
                feature = dict()
                if hasattr(packet, 'ip'):
                    src_ip = str(packet.ip.src_host)
                    dst_ip = str(packet.ip.dst_host)
                else:
                    continue
                if not hasattr(packet, 'transport_layer') or packet.transport_layer is None:
                    continue
                transport_layer = packet.transport_layer
                feature["protocol"] = "1" if transport_layer in ("QUIC", "UDP") else "0"
                feature["length"] = str(packet.length)
                feature["relative_time"] = str("{:.9f}".format(float(getattr(packet.frame_info, "time_delta"))))
                feature["direction"] = "1" if src_ip == host_ip else "0"
                feature["src_ip"] = src_ip
                feature["src_port"] = str(packet[transport_layer].srcport)
                feature["dst_ip"] = dst_ip
                feature["dst_port"] = str(packet[transport_layer].dstport)
                features.append(feature)
            except Exception:
                continue

    except Exception as e:
        import traceback
        print(f"-----Error parsing PCAP: {e}")
        traceback.print_exc()
    finally:
        if trace_file is not None:
            try:
                trace_file.close()
            except Exception:
                pass
        os.system("pkill -9 tshark 2>/dev/null")
        time.sleep(0.5)
        asyncio.set_event_loop(asyncio.new_event_loop())
        return features


# ─── MAIN LOOP ────────────────────────────────────────────────────────────────

def generate_traces(target_websites_dir):
    pcap_dir = os.path.join(args.trace_file_dir, "pcap")
    csv_dir = os.path.join(args.trace_file_dir, "csv")
    os.makedirs(pcap_dir, exist_ok=True)
    os.makedirs(csv_dir, exist_ok=True)

    for i in range(0, args.access_count):
        with open(target_websites_dir) as target_websites:
            websites_count = 0
            gap_count = 0
            for url in target_websites:
                gap_count += 1
                if gap_count <= args.gap_count:
                    continue
                url = url.rstrip("\n")
                print(f"\n[+] Processing {url} (Attempt {i+1}/{args.access_count})")

                trace_file_path, dir_name = packet_capture(url, i, pcap_dir)

                if not os.path.exists(trace_file_path):
                    continue

                has_quic = False
                if args.filter:
                    has_quic = contains_quic(trace_file_path)

                features = parse_pcap(trace_file_path)

                if len(features) != 0:
                    if not args.filter or has_quic:
                        website_csv_dir = os.path.join(csv_dir, dir_name)
                        os.makedirs(website_csv_dir, exist_ok=True)

                        dataset_file_path = os.path.join(website_csv_dir, f"{i + 1}_{dir_name}.csv")
                        print(f"--> Saved PCAP to: {trace_file_path}")
                        print(f"--> Saved CSV to: {dataset_file_path}")

                        with open(dataset_file_path, mode='w') as dataset_file:
                            dataset_file.write(";".join(features[0].keys()) + '\n')
                            for feature in features:
                                dataset_file.write(";".join(feature.values()) + '\n')

                websites_count += 1
                if websites_count == args.websites_count:
                    break


if __name__ == '__main__':
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, hard))
    soft_proc, hard_proc = resource.getrlimit(resource.RLIMIT_NPROC)
    resource.setrlimit(resource.RLIMIT_NPROC, (65536, hard_proc))

    start_time = time.time()
    generate_traces(args.target_websites)
    end_time = time.time()
    print(f"\nElapsed time: {end_time - start_time} seconds")
    subprocess.run(["chmod", "-R", "777", args.trace_file_dir], stderr=subprocess.DEVNULL)