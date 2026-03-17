"""
Test script to verify API rate limiting is working correctly
Run this after starting the API server
"""

import requests
import time
from datetime import datetime

API_URL = "http://localhost:8000"

print("=" * 60)
print("API Rate Limit Test")
print("=" * 60)

# Test 1: Health check rate limit (60/minute)
print("\n📊 Test 1: Health Check Rate Limit (60 requests/minute)")
print("-" * 60)

success_count = 0
rate_limited = False

for i in range(65):  # Try 65 times to exceed limit
    response = requests.get(f"{API_URL}/health")
    print(f"Request {i+1}: Status {response.status_code}", end="")

    if response.status_code == 200:
        success_count += 1
        print(" ✅")
    elif response.status_code == 429:
        rate_limited = True
        print(f" ⚠️  RATE LIMITED")
        print(f"Response: {response.json()}")
        break
    else:
        print(f" ❌ Error: {response.status_code}")

    # Small delay to avoid overwhelming
    time.sleep(0.1)

print(f"\nResult: {success_count} successful requests before rate limit")
print(f"Rate limit triggered: {'✅' if rate_limited else '❌'}")

# Test 2: Upload endpoint rate limit (10/minute)
print("\n" + "=" * 60)
print("📤 Test 2: Upload Endpoint Rate Limit (10 requests/minute)")
print("-" * 60)

# Create a small test CSV
import pandas as pd
import numpy as np

test_data = pd.DataFrame(np.random.randint(0, 1000, size=(10, 81)),
                         columns=['Source Port', 'Destination Port', 'Protocol', 'Flow Duration',
                                  'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
                                  'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
                                  'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
                                  'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
                                  'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
                                  'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
                                  'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
                                  'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                                  'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
                                  'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
                                  'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
                                  'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
                                  'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
                                  'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
                                  'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
                                  'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
                                  'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
                                  'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
                                  'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
                                  'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
                                  'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
                                  'Idle Std', 'Idle Max', 'Idle Min', 'Inbound'])

test_csv_path = "test_rate_limit.csv"
test_data.to_csv(test_csv_path, index=False)

upload_success = 0
upload_rate_limited = False

for i in range(12):  # Try 12 times to exceed limit of 10
    with open(test_csv_path, 'rb') as f:
        response = requests.post(f"{API_URL}/upload-csv", files={'file': f})

    print(f"Upload {i+1}: Status {response.status_code}", end="")

    if response.status_code == 200:
        upload_success += 1
        print(" ✅")
    elif response.status_code == 429:
        upload_rate_limited = True
        print(f" ⚠️  RATE LIMITED")
        print(f"Response: {response.json()}")
        break
    else:
        print(f" ❌ Error: {response.status_code}")

    time.sleep(0.2)

print(f"\nResult: {upload_success} successful uploads before rate limit")
print(f"Rate limit triggered: {'✅' if upload_rate_limited else '❌'}")

# Cleanup
import os
os.remove(test_csv_path)

print("\n" + "=" * 60)
print("Rate Limit Test Complete!")
print("=" * 60)

if rate_limited and upload_rate_limited:
    print("✅ All rate limits are working correctly!")
else:
    print("⚠️  Some rate limits may not be working as expected")
