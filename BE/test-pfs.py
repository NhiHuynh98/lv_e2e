import requests
import json

# Login to get token
login_response = requests.post(
    "http://localhost:8000/token",
    data={"username": "meme", "password": "123456"}
)
print("ddd", login_response)
token = login_response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create a PFS session
session_id = "test_session_1"
pfs_response = requests.post(
    "http://localhost:8000/pfs/create",
    headers=headers,
    json={"session_id": session_id, "algorithm": "ecc"}
)
print("PFS Session Created:", pfs_response.json())

# Wait 6 minutes (longer than rotation interval of 5 min)
# Then check session info - keys should have rotated
import time
time.sleep(360)  # 6 minutes
info_response = requests.get(
    f"http://localhost:8000/pfs/info/meme_{session_id}",
    headers=headers
)
print("PFS Session Info after rotation:", info_response.json())