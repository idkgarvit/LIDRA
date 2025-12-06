#!/usr/bin/env python3
# lidra_agent.py - orchestrates detection, deception, response, reporting
import subprocess, time, os, yaml, signal, sys, psutil

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CFG = os.path.join(BASE, "config", "config.yaml")

def load_config():
    if not os.path.exists(CFG):
        print(f"[ERROR] Config not found: {CFG}")
        sys.exit(1)
    with open(CFG, "r") as f:
        return yaml.safe_load(f)

def run_cmd(script_path):
    """Run a shell script safely."""
    if not os.path.exists(script_path):
        print(f"[WARN] Missing script: {script_path}")
        return
    print(f"[RUN] {os.path.basename(script_path)}")
    subprocess.run([script_path], cwd=BASE, check=False)

def is_process_running(name):
    """Return True if a process containing `name` is already running."""
    for p in psutil.process_iter(attrs=["cmdline"]):
        try:
            cmd = " ".join(p.info["cmdline"])
            if name in cmd and "python" not in cmd:
                return True
        except Exception:
            continue
    return False

def main():
    cfg = load_config()
    sleep_time = 60 if cfg.get("mode") == "development" else 300
    print(f"[INFO] LIDRA Agent started (interval={sleep_time}s)")

    while True:
        # Step 1: Detection
        run_cmd(os.path.join(BASE, "src", "core", "detection.sh"))

        # Step 2: Deception (start once)
        if not is_process_running("deception.sh"):
            print("[INFO] Starting deception module ...")
            subprocess.Popen(
                [os.path.join(BASE, "src", "core", "deception.sh")],
                cwd=BASE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            print("[INFO] Deception already running.")

        # Step 3: Response
        run_cmd(os.path.join(BASE, "src", "core", "response.sh"))

        # Step 4: Reporting
        run_cmd(os.path.join(BASE, "src", "core", "reporting.sh"))

        print(f"[INFO] Cycle complete. Sleeping {sleep_time}s ...")
        try:
            time.sleep(sleep_time)
        except KeyboardInterrupt:
            print("\n[INFO] Agent stopped by user.")
            break

if __name__ == "__main__":
    try:
        import psutil  # ensure dependency
    except ImportError:
        print("[ERROR] psutil not installed. Install with: pip install psutil")
        sys.exit(1)
    main()
