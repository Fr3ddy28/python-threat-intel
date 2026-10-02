import requests
import json
import sys

def check_ip_reputation(ip_address, api_key=None):
    """
    Queries AbuseIPDB REST API v2 for IP reputation scores during SOC incident triage.
    """
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key or 'YOUR_API_KEY_HERE'
    }
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    print(f"[*] Triaging IP Address: {ip_address}...")
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            print("\n=================== Threat Intelligence Summary ===================")
            print(f"IP Address:            {data.get('ipAddress')}")
            print(f"Abuse Confidence Score:{data.get('abuseConfidenceScore')}%")
            print(f"Country Code:          {data.get('countryCode')}")
            print(f"ISP / Domain:          {data.get('isp')}")
            print(f"Total Threat Reports:  {data.get('totalReports')}")
            print(f"Whitelisted:           {data.get('isWhitelisted')}")
            print("===================================================================\n")
            
            # Recommendation logic
            score = data.get('abuseConfidenceScore', 0)
            if score > 80:
                print("[CRITICAL] IP score exceeds threshold (>80%). Immediate containment recommended.")
            elif score > 50:
                print("[WARNING] Suspicious IP score (50-80%). Monitor traffic and correlate with SIEM logs.")
            else:
                print("[INFO] Low threat score. IP appears clean.")
                
        else:
            print(f"[!] API Request Failed with Status Code: {response.status_code}")
            
    except Exception as e:
        print(f"[!] Execution Error: {e}")

if __name__ == "__main__":
    # Allows command line execution: python threat_intel.py <IP_ADDRESS>
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "185.220.101.5"
    check_ip_reputation(target_ip)
