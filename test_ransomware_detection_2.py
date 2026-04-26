#!/usr/bin/env python3
"""
SAFE Ransomware Simulation for Testing ML Score
- Triggers high network_burst_60s
- Triggers high family_file_deletes / rapid file ops
- Uses safe, temporary paths only
- NO real encryption, NO real deletion, NO real C2
"""

import socket
import json
import time
import random
import uuid


COLLECTOR_REACHABLE = None


def build_event(event_id, ev_type, pid, base=None, **kwargs):
    evt = dict(base or {})
    evt.update(kwargs)
    evt.update({
        "EventID": int(event_id),
        "EventId": int(event_id),
        "event_id": int(event_id),
        "type": str(ev_type),
        "Type": str(ev_type),
        "ProcessID": int(pid),
        "ProcessId": int(pid),
        "process_id": int(pid),
        "pid": int(pid),
    })
    if "ParentProcessId" in evt:
        try:
            ppid = int(evt["ParentProcessId"])
            evt["parent_process_id"] = ppid
            evt["ppid"] = ppid
        except Exception:
            pass
    if "Image" in evt:
        evt["image"] = evt["Image"]
        evt["ImagePath"] = evt["Image"]
        evt["image_path"] = evt["Image"]
    if "TargetFilename" in evt:
        evt["target_filename"] = evt["TargetFilename"]
        evt["TargetFile"] = evt["TargetFilename"]
    if "timestamp" in evt:
        evt["Timestamp"] = evt["timestamp"]
        evt["TimeCreated"] = evt["timestamp"]
    return evt

def send_event(host="127.0.0.1", port=5050, event=None):
    global COLLECTOR_REACHABLE

    if event is None:
        return False

    if COLLECTOR_REACHABLE is None:
        try:
            with socket.create_connection((host, port), timeout=0.35):
                pass
            COLLECTOR_REACHABLE = True
        except OSError as e:
            COLLECTOR_REACHABLE = False
            print(f"→ Collector {host}:{port} unreachable ({e}). Running in dry-run mode.")

    if not COLLECTOR_REACHABLE:
        return False

    try:
        with socket.create_connection((host, port), timeout=0.35) as sock:
            sock.sendall((json.dumps(event) + "\n").encode("utf-8"))
        return True
    except OSError as e:
        # If collector goes away mid-run, disable sending to keep simulation responsive.
        COLLECTOR_REACHABLE = False
        print(f"→ Collector disconnected ({e}). Continuing in dry-run mode.")
        return False


def safe_high_score_simulation():
    print("SAFE HIGH-SCORE Ransomware Simulation")
    print("Goal: trigger top features your model cares about")
    print("───────────────────────────────────────────────")
    print("• Heavy network burst (network_burst_60s)")
    print("• Rapid file create + rename/delete churn")
    print("• Suspicious path + high entropy files + ransom notes")
    print("• Nothing harmful is actually done")
    print()

    base_time = time.time()
    pid = random.randint(5000, 12000)
    ppid = random.randint(1200, 3800)
    image = r"C:\Users\Public\Updates\svch0st.exe"   # suspicious name & path
    worker_image = r"C:\Users\Public\Updates\enc_worker.exe"

    # ───────────────────────────────────────────────
    # 1. Suspicious process starts
    # ───────────────────────────────────────────────
    print("[1] Starting suspicious processes...")
    send_event(event=build_event(1, "PROCESS_CREATE", pid,
        ParentProcessId=ppid,
        Image=image,
        CommandLine=f'"{image}" --mode=quiet --batch',
        timestamp=base_time,
        UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(base_time)),
        __event_uuid=str(uuid.uuid4()),
    ))
    time.sleep(0.2)
    send_event(event=build_event(1, "PROCESS_CREATE", pid + 7,
        ParentProcessId=pid,
        Image=worker_image,
        CommandLine=f'"{worker_image}" --encrypt --threads=6',
        timestamp=base_time + 0.3,
        UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(base_time + 0.3)),
        __event_uuid=str(uuid.uuid4()),
    ))
    time.sleep(0.2)
    send_event(event=build_event(1, "PROCESS_CREATE", pid + 9,
        ParentProcessId=pid,
        Image=r"C:\\Windows\\System32\\vssadmin.exe",
        CommandLine="vssadmin delete shadows /all /quiet",
        timestamp=base_time + 0.6,
        UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(base_time + 0.6)),
        __event_uuid=str(uuid.uuid4()),
    ))
    send_event(event=build_event(1, "PROCESS_CREATE", pid + 11,
        ParentProcessId=pid,
        Image=r"C:\\Windows\\System32\\bcdedit.exe",
        CommandLine="bcdedit /set {default} recoveryenabled No",
        timestamp=base_time + 0.9,
        UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(base_time + 0.9)),
        __event_uuid=str(uuid.uuid4()),
    ))
    time.sleep(0.6)

    # ───────────────────────────────────────────────
    # 2. Simulate fast outbound connections (C2 / exfil burst)
    #    → should strongly activate network_burst_60s
    # ───────────────────────────────────────────────
    print("[2] Simulating rapid outbound connections (96 in ~35 seconds)...")
    destinations = [
        "45.32.12.147", "185.220.101.12", "104.244.42.1",
        "172.67.88.99", "198.51.100.45", "203.0.113.88"
    ]

    for i in range(96):
        t = base_time + 1.0 + (i * 0.36)          # sub-second cadence for stronger burst feature
        dst = random.choice(destinations)
        api_call = random.choice([
            "CryptEncrypt",
            "BCryptEncrypt",
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ])
        send_event(event=build_event(3, "NETWORK_CONNECT", pid + 7,
            Image=worker_image,
            DestinationIp=dst,
            DestinationPort=random.choice([80, 443, 8080]),
            Initiated=True,
            Protocol="tcp",
            ApiCall=api_call,
            ThreadCount=18 + (i % 24),
            HandleCount=260 + (i * 2),
            timestamp=t,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t)),
            __event_uuid=str(uuid.uuid4()),
            __reasons=["suspicious_powershell_cmdline"],
        ))
        # Keep file activity interleaved with network so Stage3 gets mixed event context.
        if i % 3 == 0:
            pulse_file = f"C:\\Users\\Public\\Documents\\net_pulse_{i:03d}.tmp"
            send_event(event=build_event(11, "FILE_CREATE", pid + 7,
                Image=worker_image,
                TargetFilename=pulse_file,
                entropy=round(random.uniform(7.5, 7.98), 3),
                bytes_written=random.randint(2 * 1024 * 1024, 8 * 1024 * 1024),
                timestamp=t + 0.05,
                UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.05)),
                __event_uuid=str(uuid.uuid4()),
            ))
        if (i + 1) % 24 == 0:
            print(f"  → Sent {i+1}/96 connections")
    time.sleep(1.0)

    # ───────────────────────────────────────────────
    # 3. Rapid high-entropy file creation
    # ───────────────────────────────────────────────
    print("[3] Creating many high-entropy files quickly...")
    base_path = r"C:\Users\Public\Documents\temp_test_"
    for i in range(180):
        t = base_time + 6.0 + (i * 0.12)     # much denser file activity for rate features
        fname = f"{base_path}{i:03d}.dat"
        send_event(event=build_event(11, "FILE_CREATE", pid + 7,
            Image=worker_image,
            TargetFilename=fname,
            entropy=round(random.uniform(7.6, 7.98), 3),
            bytes_written=random.randint(512 * 1024, 4 * 1024 * 1024),
            timestamp=t,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t)),
            __event_uuid=str(uuid.uuid4()),
            __reasons=["suspicious_powershell_cmdline"],
        ))
        send_event(event=build_event(15, "FILE_WRITE", pid + 7,
            Image=worker_image,
            TargetFilename=fname,
            bytes_written=random.randint(256 * 1024, 2 * 1024 * 1024),
            ApiCall=random.choice(["CryptEncrypt", "BCryptEncrypt", "WriteProcessMemory"]),
            ThreadCount=22 + (i % 26),
            HandleCount=280 + (i * 2),
            timestamp=t + 0.03,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.03)),
            __event_uuid=str(uuid.uuid4()),
        ))
        if (i + 1) % 45 == 0:
            print(f"  → {i+1}/180 files")

    # ───────────────────────────────────────────────
    # 4. Simulate rapid rename/delete churn
    #    → create .locked files + delete originals within 60s window
    # ───────────────────────────────────────────────
    print("[4] Simulating mass file churn (encrypt + delete)...")
    for i in range(160):
        t = base_time + 31.0 + (i * 0.11)
        fname = f"{base_path}{i:03d}.dat"
        locked = f"{fname}.locked.enc"
        send_event(event=build_event(13, "REGISTRY_SET_VALUE", pid + 7,
            Image=worker_image,
            TargetObject=r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svch0st",
            timestamp=t - 0.15,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t - 0.15)),
            __event_uuid=str(uuid.uuid4()),
            __reasons=["suspicious_powershell_cmdline"],
        ))
        send_event(event=build_event(23, "FILE_DELETE", pid + 7,
            Image=worker_image,
            TargetFilename=fname,
            timestamp=t,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t)),
            __event_uuid=str(uuid.uuid4()),
        ))
        send_event(event=build_event(11, "FILE_RENAME", pid + 7,
            Image=worker_image,
            SourceFilename=fname,
            TargetFilename=locked,
            ApiCall="WriteProcessMemory",
            timestamp=t + 0.02,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.02)),
            __event_uuid=str(uuid.uuid4()),
        ))
        send_event(event=build_event(11, "FILE_CREATE", pid + 7,
            Image=worker_image,
            TargetFilename=locked,
            entropy=round(random.uniform(7.7, 7.99), 3),
            bytes_written=random.randint(128 * 1024, 2 * 1024 * 1024),
            timestamp=t + 0.05,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.05)),
            __event_uuid=str(uuid.uuid4()),
        ))
        send_event(event=build_event(15, "FILE_WRITE", pid + 7,
            Image=worker_image,
            TargetFilename=locked,
            bytes_written=random.randint(256 * 1024, 1536 * 1024),
            ApiCall=random.choice(["CryptEncrypt", "VirtualAlloc", "CreateRemoteThread"]),
            ThreadCount=30 + (i % 20),
            HandleCount=350 + (i * 3),
            timestamp=t + 0.08,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.08)),
            __event_uuid=str(uuid.uuid4()),
        ))
        if (i + 1) % 40 == 0:
            print(f"  → {i+1}/160 files churned")

    # ───────────────────────────────────────────────
    # 5. Honeypot access + DNS noise + module load
    # ───────────────────────────────────────────────
    print("[5] Simulating honeypot access + DNS + module load...")
    for i in range(30):
        t = base_time + 52.0 + (i * 0.22)
        honeypot = rf"C:\Users\Public\Honeypots\decoy_{i:02d}.docx"
        send_event(event=build_event(11, "FILE_CREATE", pid + 7,
            Image=worker_image,
            TargetFilename=honeypot,
            entropy=6.1,
            bytes_written=4096,
            timestamp=t,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t)),
            __event_uuid=str(uuid.uuid4()),
        ))
        send_event(event=build_event(22, "DNS_QUERY", pid + 7,
            Image=worker_image,
            QueryName=f"pay-{i}.fastrecover-files.tld",
            timestamp=t + 0.1,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.1)),
            __event_uuid=str(uuid.uuid4()),
            __reasons=["suspicious_powershell_cmdline"],
        ))
        send_event(event=build_event(7, "MODULE_LOAD", pid + 7,
            Image=worker_image,
            ImageLoaded=r"C:\Users\Public\Updates\crypto_helper.dll",
            timestamp=t + 0.2,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t + 0.2)),
            __event_uuid=str(uuid.uuid4()),
        ))

    # ───────────────────────────────────────────────
    # 5. Drop ransom notes across multiple folders
    # ───────────────────────────────────────────────
    print("[5] Dropping ransom notes...")
    note_paths = [
        r"C:\Users\Public\Documents\README_RESTORE_FILES.txt",
        r"C:\Users\Public\Desktop\HOW_TO_DECRYPT.txt",
        r"C:\Users\Public\Downloads\RECOVER_FILES_NOW.txt",
    ]
    for i, note in enumerate(note_paths):
        t = base_time + 52.0 + (i * 1.2)
        send_event(event=build_event(11, "FILE_CREATE", pid,
            Image=image,
            TargetFilename=note,
            entropy=4.1,
            bytes_written=2048,
            timestamp=t,
            UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000", time.localtime(t)),
            __event_uuid=str(uuid.uuid4()),
        ))

    # ───────────────────────────────────────────────
    # 6. One final trigger event
    # ───────────────────────────────────────────────
    print("[6] Final trigger event...")
    time.sleep(1.5)
    send_event(event=build_event(11, "FILE_CREATE", pid,
        Image=image,
        TargetFilename=base_path + "final_large.dat",
        entropy=7.92,
        bytes_written=2 * 1024 * 1024,
        timestamp=time.time(),
        UtcTime=time.strftime("%Y-%m-%d %H:%M:%S.000"),
        __event_uuid=str(uuid.uuid4()),
    ))

    print("\nSimulation finished.")
    print("→ Check your EDR dashboard / logs for Stage 3 score")
    print("→ Look especially at network_burst_60s and family_file_deletes values")


if __name__ == "__main__":
    safe_high_score_simulation()