import hashlib
import requests
import argparse

parser = argparse.ArgumentParser(
    description='Virus Total Search')

parser.add_argument('-a', '--apikey',
                    required=True,
                    help='Your VirusTotal API key')

parser.add_argument('-p', '--path',
                    type=str,
                    required=True,
                    help='The path of the file you want scanned')
args = parser.parse_args()

# Parse the command line arguments
file_path = args.path
api_key = args.apikey

# Calculate the SHA-1 hash of the file
sha1_hash = hashlib.sha1()
with open(file_path, 'rb') as f:
    sha1_hash.update(f.read())
hash_hex = sha1_hash.hexdigest()

# Make a GET request to the VirusTotal API
api_url = f"https://www.virustotal.com/api/v3/files/{hash_hex}"
headers = {"x-apikey": api_key}
response = requests.get(api_url, headers=headers)

# Parse the response from the API
data = response.json()

mcafee = data["data"]["attributes"]["last_analysis_results"]["McAfee"]["category"],
symantec = data["data"]["attributes"]["last_analysis_results"]["Symantec"]["category"],

print("McAfee :", mcafee[0])
print("Symantec :", symantec[0])


