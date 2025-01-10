import requests

def get_ip_info(ip_address):
    response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    return response.json() 