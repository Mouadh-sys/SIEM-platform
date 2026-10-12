#!/usr/bin/env python3
"""
replay_auth_log.py
Generates realistic SSH authentication log lines (syslog format)
to simulate brute-force attacks and benign traffic.
Timestamps are in UTC so @timestamp produced by Fluent Bit matches `date -u`.
"""

import argparse
import datetime
import random
import time

USERS = ["root", "admin", "ubuntu", "test", "postgres", "deploy", "guest", "oracle", "user", "ansible"]
DEFAULT_ATTACKER_IP = "203.0.113.42"
SECONDARY_ATTACKER_IP = "198.51.100.77"
BENIGN_IPS = ["10.0.0.15", "10.0.0.22"]


def generate_timestamp(dt: datetime.datetime) -> str:
    """Syslog format without year, UTC.  Example: Oct 12 03:15:30"""
    return dt.strftime("%b %d %H:%M:%S")


def make_failed_line(dt: datetime.datetime, ip: str, user: str, port: int, pid: int, host: str = "siem-bastion") -> str:
    ts = generate_timestamp(dt)
    msg = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    return f"{ts} {host} sshd[{pid}]: {msg}\n"


def make_accepted_line(dt: datetime.datetime, ip: str, user: str, port: int, pid: int, host: str = "siem-bastion") -> str:
    ts = generate_timestamp(dt)
    msg = f"Accepted password for {user} from {ip} port {port} ssh2"
    return f"{ts} {host} sshd[{pid}]: {msg}\n"


def main():
    parser = argparse.ArgumentParser(description="Replay simulated SSH auth.log entries for SIEM demo.")
    parser.add_argument("--file", "-f", default="data/fluent-bit/auth.log", help="Path to destination auth.log")
    parser.add_argument("--count", "-c", type=int, default=15, help="Number of failed attempts to generate")
    parser.add_argument("--attacker-ip", "-a", default=DEFAULT_ATTACKER_IP, help="Attacker IP address")
    parser.add_argument("--mode", "-m", choices=["brute-force", "benign", "mixed"], default="brute-force", help="Simulation mode")
    parser.add_argument("--delay", "-d", type=float, default=0.1, help="Delay between log lines in seconds")
    args = parser.parse_args()

    print(f"[*] Writing logs to {args.file} (mode: {args.mode}, count: {args.count})")

    pid = 12000

    with open(args.file, "a") as f:
        if args.mode in ["benign", "mixed"]:
            for _ in range(3):
                pid += 1
                # Use UTC time so Fluent Bit's @timestamp matches `date -u`
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                line = make_accepted_line(now_utc, random.choice(BENIGN_IPS), "admin", random.randint(40000, 60000), pid)
                f.write(line)
                f.flush()
                print(f"[BENIGN] {line.strip()}")
                time.sleep(args.delay)

        if args.mode in ["brute-force", "mixed"]:
            for i in range(args.count):
                pid += 1
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                user = USERS[i % len(USERS)]
                port = random.randint(35000, 62000)
                line = make_failed_line(now_utc, args.attacker_ip, user, port, pid)
                f.write(line)
                f.flush()
                print(f"[ATTACK {i+1}/{args.count}] {line.strip()}")
                time.sleep(args.delay)

        if args.mode == "mixed":
            # Secondary attacker IP for multi-source correlation
            for i in range(2):
                pid += 1
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                line = make_failed_line(now_utc, SECONDARY_ATTACKER_IP, "root", random.randint(35000, 62000), pid)
                f.write(line)
                f.flush()
                print(f"[SECONDARY] {line.strip()}")
                time.sleep(args.delay)

    print(f"[✓] Finished generating logs in {args.file}")


if __name__ == "__main__":
    main()
