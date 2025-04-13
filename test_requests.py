import requests

BASE_URL = "http://127.0.0.1:8000"

# Test user credentials
test_user = {
    "email": "user@example.com",
    "password": "securepassword"
}

def signup():
    url = f"{BASE_URL}/signup"
    response = requests.post(url, json=test_user)
    print("Signup Response:", response.json())

def login():
    url = f"{BASE_URL}/login"
    data = {
        "username": test_user["email"],
        "password": test_user["password"]
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        token = response.json()["access_token"]
        print("Login Successful! Token:", token)
        return token
    else:
        print("Login Failed:", response.json())
        return None

def access_protected(token):
    url = f"{BASE_URL}/protected"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    print("Protected Route Response:", response.json())

if __name__ == "__main__":
    signup()  # Register user
    token = login()  # Login and get token
    if token:
        access_protected(token)  # Access protected route
