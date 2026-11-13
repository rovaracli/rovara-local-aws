"""Usage: python -I run_boto3.py --endpoint URL [--validated-endpoint URL] [--validated-control-token T] [--control-token T] [--closed-endpoint URL]
[--only group|case] [--out file.json]"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
os.environ["AWS_CONFIG_FILE"] = "/dev/null"

import harness  # noqa: E402
import cases  # noqa: E402,F401


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--validated-endpoint")
    ap.add_argument("--validated-control-token")
    ap.add_argument("--control-token")
    ap.add_argument("--closed-endpoint")
    ap.add_argument("--only")
    ap.add_argument("--out")
    a = ap.parse_args()
    env = harness.Env(a.endpoint, a.validated_endpoint, a.control_token)
    env.validated_control_token = a.validated_control_token
    env.closed_endpoint = a.closed_endpoint
    return harness.run(env, a.only, a.out)


if __name__ == "__main__":
    sys.exit(main())
