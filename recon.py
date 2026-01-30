import requests
import json
import sys
from datetime import datetime


def banner():
    print("""
    ╔═══════════════════════════════════════╗
    ║   VirusTotal Domain Recon Tool        ║
    ║   Domain Intelligence Gathering       ║
    ╚═══════════════════════════════════════╝
    """)


def get_domain_report(api_key, domain):
    #Fetch domain report from VirusTotal API
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {
        'apikey': api_key,
        'domain': domain
    }

    try:
        print(f"\n[*] Querying VirusTotal for: {domain}")
        response = requests.get(url, params=params, timeout=30)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 204:
            print("[!] Rate limit exceeded. Please wait before making more requests.")
            return None
        elif response.status_code == 403:
            print("[!] Invalid API key or access denied.")
            return None
        else:
            print(f"[!] Error: HTTP {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None


def display_results(data, domain):
    # Display the reconnaissance results in a readable format
    if not data:
        print("[!] No data returned from API")
        return

    print("\n" + "=" * 60)
    print(f"DOMAIN RECONNAISSANCE REPORT: {domain}")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Response code
    response_code = data.get('response_code', 0)
    if response_code == 1:
        print("\n[+] Domain found in VirusTotal database")
    else:
        print("\n[-] Domain not found in VirusTotal database")
        return

    # Categories
    if 'categories' in data and data['categories']:
        print(f"\n[+] Categories:")
        for category in data['categories']:
            print(f"    - {category}")

    # Subdomains
    if 'subdomains' in data and data['subdomains']:
        print(f"\n[+] Subdomains: {len(data['subdomains'])} found")
        for subdomain in data['subdomains'][:1000]:
            print(f"    - {subdomain}")
        if len(data['subdomains']) > 1000:
            print(f"    ... and {len(data['subdomains']) - 1000} more")

    print("\n" + "=" * 60)


def save_to_file(data, domain):
    # Save the raw JSON data to a file
    filename = f"{domain}_vt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n[+] Full report saved to: {filename}")
    except Exception as e:
        print(f"[!] Failed to save file: {e}")


def main():
    banner()

    # Get API key
    api_key = input("Enter your VirusTotal API key: ").strip()
    if not api_key:
        print("[!] API key cannot be empty")
        sys.exit(1)

    # Get domain
    domain = input("Enter the domain to analyze: ").strip()
    if not domain:
        print("[!] Domain cannot be empty")
        sys.exit(1)

    # Fetch and display report
    data = get_domain_report(api_key, domain)

    if data:
        display_results(data, domain)

        # Ask if user wants to save
        save = input("\nSave full JSON report to file? (y/n): ").strip().lower()
        if save == 'y':
            save_to_file(data, domain)

    print("\n[*] Recon complete!")


if __name__ == "__main__":
    main()