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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Resolve async event loop
nest_asyncio.apply()

# --- CONFIGURATION ---
INTERFACE = "eth0"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
PROXY_ENDPOINT = "162.159.198.1:443" # Change to your actual proxy endpoint
INPUT_WEBSITES_FILE = "./target_websites.txt" 
# ---------------------

# Prepare arguements
parser = argparse.ArgumentParser(description="Capture network traffic.")
parser.add_argument("--trace_file_dir", dest="trace_file_dir", default="./traces/",
                    help="Base trace files directory")
parser.add_argument("--target_websites", dest="target_websites", default=INPUT_WEBSITES_FILE,
                    help="target hosts file path")
parser.add_argument("--websites_count", dest="websites_count", default=10, type=int,
                    help="total websites to keep")
parser.add_argument("--gap_count", dest="gap_count", default=0, type=int,
                    help="mark the start of target websites capture")
parser.add_argument("--access_count", dest="access_count", default=2, type=int,
                    help="numbers of access for each host")
parser.add_argument('--filter', action='store_true', default=False,
                    help='enable filter over target websites with QUIC traces')
args = parser.parse_args()

# Chrome/Chromium web driver
def open_website(url):
    options = Options()
    
    # --- MANDATORY FLAGS FOR RUNNING CHROME IN DOCKER ---
    options.add_argument("--headless") 
    options.add_argument("--no-sandbox") 
    options.add_argument("--disable-dev-shm-usage") 
    options.add_argument("--incognito") 
    options.add_argument("--disk-cache-size=0") 
    
    # Configure SOCKS5 Proxy for Chrome
    options.add_argument(f"--proxy-server=socks5://{PROXY_HOST}:{PROXY_PORT}")
    
    # Ignore certificate errors (if proxy intercepts)
    options.add_argument("--ignore-certificate-errors")
    
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        print(f"-----Loaded: {driver.title}")
        time.sleep(5) # Wait for the website to fully load
    except Exception as e:
        print(f"-----Browser Error: {e}")
    finally:
        driver.quit()

# tcpdump trace capture
def start_tcpdump(trace_file):
    print("-----Running tcpdump")
    cmd = [
        "tcpdump", "-i", INTERFACE,
        "-w", trace_file,
        "port", "80", "or", "port", "443", "or", "port", "853"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc

def stop_tcpdump(proc):
    print("-----Stopping tcpdump")
    if proc:
        proc.terminate()
        proc.wait(timeout=3)
    subprocess.run(["pkill", "tcpdump"], stderr=subprocess.DEVNULL)

# Masque Proxy
def start_proxy():
    print("-----Starting Masque Proxy")
    subprocess.run(["pkill", "-9", "masque-plus"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    cmd = ["./masque-plus", "--endpoint", PROXY_ENDPOINT] 
    
    proc = subprocess.Popen(
        cmd, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    time.sleep(3)
    return proc

def stop_proxy(proc):
    print("-----Stopping Masque Proxy")
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    subprocess.run(["pkill", "-9", "masque-plus"], stderr=subprocess.DEVNULL)
    time.sleep(1)

# Process packet capture and save PCAP
def packet_capture(url, index, pcap_base_dir):
    tcp_proc = None
    proxy_proc = None
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
        
        # 1. Start tcpdump
        tcp_proc = start_tcpdump(trace_file)
        time.sleep(1)
        
        # 2. Start Proxy
        proxy_proc = start_proxy()
        
        # 3. Visit target website with Chrome
        process_web_driver = multiprocessing.Process(target=open_website, args=(url,))
        process_web_driver.start()
        process_web_driver.join()

    except Exception as e:
        print(f"Error during capture: {e}")
        if os.path.exists(trace_file): os.remove(trace_file)
    finally:
        stop_proxy(proxy_proc)
        stop_tcpdump(tcp_proc)
        
    return trace_file, dir_name

def contains_quic(trace_file):
    cap = None
    try:
        # Reset event loop before pyshark usage
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.FileCapture(trace_file, display_filter="quic")
        for packet in cap:
            for layer in packet:
                if layer.layer_name == 'quic':
                    if packet.udp.srcport == "443" or packet.udp.dstport == "443":
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
        # Dọn rác tshark process còn sót lại
        subprocess.run(["pkill", "-9", "tshark"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def parse_pcap(trace_file_path):
    features = list()
    trace_file = None
    try:
        # Reset event loop for each parse call to avoid nest_asyncio/pyshark conflict
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Get host IP. Docker might have multiple IPs (space-separated), extract the first one
        host_ip = os.popen("hostname -i").read().strip().split(" ")[0]
        
        # Adding keep_packets=False ensures smooth processing and prevents RAM overflow
        trace_file = pyshark.FileCapture(trace_file_path, keep_packets=False)
        
        for packet in trace_file:
            try:
                feature = dict()
                
                # 1. Check IP/IPv6 layer
                if hasattr(packet, 'ip'):
                    src_ip = str(packet.ip.src_host)
                    dst_ip = str(packet.ip.dst_host)
                elif hasattr(packet, 'ipv6'):
                    src_ip = str(packet.ipv6.src_host)
                    dst_ip = str(packet.ipv6.dst_host)
                else:
                    continue # Skip packets without IP structure (e.g., ARP)

                # 2. Check Transport layer (TCP/UDP/QUIC)
                if not hasattr(packet, 'transport_layer') or packet.transport_layer is None:
                    continue # Skip packets without a Port (e.g., ICMP)
                    
                transport_layer = packet.transport_layer
                
                if transport_layer == "QUIC" or transport_layer == "UDP":
                    feature["protocol"] = "1"
                else:
                    feature["protocol"] = "0"
                    
                feature["length"] = str(packet.length)
                feature["relative_time"] = str("{:.9f}".format(float(getattr(packet.frame_info, "time_delta"))))
                feature["direction"] = "1" if src_ip == host_ip else "0"
                feature["src_ip"] = src_ip
                feature["src_port"] = str(packet[transport_layer].srcport)
                feature["dst_ip"] = dst_ip
                feature["dst_port"] = str(packet[transport_layer].dstport)
                
                features.append(feature)
            except Exception as packet_err:
                # Silently ignore abnormally malformed packets to prevent script crashes
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
                pass  # Bỏ qua TSharkCrashException khi close
        # Dọn rác tshark process còn sót lại
        subprocess.run(["pkill", "-9", "tshark"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return features

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
                        
                        with open(dataset_file_path, mode ='w') as dataset_file:
                            dataset_file.write(";".join(features[0].keys()) + '\n')
                            for feature in features:
                                dataset_file.write(";".join(feature.values()) + '\n')
                        
                websites_count += 1
                if websites_count == args.websites_count:
                    break

if __name__ == '__main__':
    start_time = time.time()
    generate_traces(args.target_websites)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nElapsed time: {elapsed_time} seconds")
    # Automatically grant read/write/delete permissions (777) to the entire output directory
    subprocess.run(["chmod", "-R", "777", args.trace_file_dir], stderr=subprocess.DEVNULL)