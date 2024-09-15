# api_testing.py
import requests

def test_api_endpoint(url, headers=None):
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(f"API {url} is accessible")
    else:
        print(f"API {url} returned {response.status_code}")

