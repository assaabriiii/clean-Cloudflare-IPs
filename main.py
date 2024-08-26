import requests
import dns.resolver


def get_cloudflare_ips():
    ipv4_url = "https://www.cloudflare.com/ips-v4"
    ipv6_url = "https://www.cloudflare.com/ips-v6"
    
    ipv4_ips = requests.get(ipv4_url).text.splitlines()
    ipv6_ips = requests.get(ipv6_url).text.splitlines()
    
    return ipv4_ips + ipv6_ips

# Function to check if an IP is blacklisted
def check_ip_blacklist(ip):
    # List of common DNSBLs (DNS-based Blackhole Lists)
    blacklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]
    
    ip_reversed = ".".join(reversed(ip.split(".")))  # Reverse the IP for DNSBL query
    
    for blacklist in blacklists:
        query = f"{ip_reversed}.{blacklist}"
        try:
            dns.resolver.resolve(query, "A")
            return False  # IP is listed on the blacklist
        except dns.resolver.NXDOMAIN:
            continue  # Not listed on this blacklist
        except dns.resolver.NoAnswer:
            continue  # No answer from DNSBL
        except dns.resolver.Timeout:
            continue  # Query timed out
    
    return True  # IP is clean (not listed on any blacklist)


def find_clean_cloudflare_ips():
    cloudflare_ips = get_cloudflare_ips()
    clean_ips = []
    
    for ip in cloudflare_ips:
        if check_ip_blacklist(ip):
            clean_ips.append(ip)
    
    return clean_ips


if __name__ == "__main__":
    clean_ips = find_clean_cloudflare_ips()
    
    print("Clean Cloudflare IPs:")
    for ip in clean_ips:
        print(ip)
