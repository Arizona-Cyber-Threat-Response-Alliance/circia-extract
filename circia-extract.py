import re
import argparse
from pypdf import PdfReader

ioc_patterns = {
    "host": r"(?i)\b((?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?!apk|apt|arpa|asp|bat|bdoda|bin|bsspx|cer|cfg|cgi|class|close|cpl|cpp|crl|css|dll|doc|docx|dyn|exe|fl|gz|hlp|htm|html|ico|ini|ioc|jar|jpg|js|jxr|lco|lnk|loader|log|lxdns|mdb|mp4|odt|pcap|pdb|pdf|php|plg|plist|png|ppt|pptx|quit|rar|rtf|scr|sleep|ssl|torproject|tmp|txt|vbp|vbs|w32|wav|xls|xlsx|xml|xpi|dat($|\r\n)|gif($|\r\n)|xn$)(?:xn--[a-zA-Z0-9]{2,22}|[a-zA-Z]{2,13}))(?!.*@)",
    "ipv4": r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "email_address": r"(?i)[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])",
    "md5": r"\b([a-fA-F\d]{32})\b",
    "url": r"\b(?:(?:https?|s?ftp|tcp|file)://)(?:(?:\b(?=.{4,253})(?:(?:[a-z0-9_-]{1,63}\.){0,124}(?:(?!-)[-a-z0-9]{1,63}(?<!-)\.){0,125}(?![-0-9])[-a-z0-9]{2,24}(?<![-0-9]))\b|\b(?:(?:(?:[0-9]|[1-8][0-9]|9[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-8][0-9]|9[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b)(?::(?:[1-9]|[1-8][0-9]|9[0-9]|[1-8][0-9]{2}|9[0-8][0-9]|99[0-9]|[1-8][0-9]{3}|9[0-8][0-9]{2}|99[0-8][0-9]|999[0-9]|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?\b)(?:/[-a-zA-Z0-9_.~%!$&'()*+,;=:@]*)*(?:\?[-a-zA-Z0-9_.~%!$&'()*+,;=:@/?]*#?)?(?:\#[-a-zA-Z0-9_.~%!$&'()*+,;=:@/?]+)?",
    "ipv6": r"(?<![a-zA-Z0-9:])(?:(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})|(?:(?=(?:[a-fA-F0-9]{0,4}:){0,7}[a-fA-F0-9]{0,4})(?:(?:[a-fA-F0-9]{1,4}:){1,7}|:)(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)))(?![a-zA-Z0-9:])",
    "sha-1": r"\b([a-fA-F\d]{40})\b",
    "sha-256": r"\b([a-fA-F\d]{64})\b",
    "asn": r"[Aa][Ss][Nn][1-4]?\d{1,8}",
    "reg_key_value": r"(?=.{1,257}$)(?:(?:HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|HKEY_CURRENT_USER|HKEY_CURRENT_USER_LOCAL_SETTINGS|HKEY_LOCAL_MACHINE|HKEY_PERFORMANCE_DATA|HKEY_PERFORMANCE_NLSTEXT|HKEY_PERFORMANCE_TEXT|HKEY_USERS)(?:(?!\\\\.+)(?:\\.+))*)",
    "user_agent": r"[A-Za-z0-9 /().,!""#$%&'*+-\\;:<>=?@[]{}^_`|~]{1,256}",
}

# Whitelist of domains to exclude from indicators
whitelist_domains = {
    'cisa.gov',
    # Add more domains here
}

def extract_pdf_content(file_path):
    reader = PdfReader(file_path)
    content = ""
    for page in reader.pages:
        content += page.extract_text()
    
    start_marker = "Please Enter the Indicator Type"
    end_marker = "Observed Activity"
    
    start_index = content.find(start_marker)
    end_index = content.find(end_marker, start_index)
    
    if start_index != -1 and end_index != -1:
        extracted_content = content[start_index + len(start_marker):end_index].strip()
        return content, extracted_content
    else:
        return content, None

def extract_incident_description(content):
    start_marker = "Please enter a brief description of the incident"
    end_marker = "Impact Details"
    
    start_index = content.find(start_marker)
    end_index = content.find(end_marker, start_index)
    
    if start_index != -1 and end_index != -1:
        incident_description = content[start_index + len(start_marker):end_index].strip()
        return incident_description
    else:
        return None

def is_whitelisted(indicator, ioc_type):
    if ioc_type in ['host', 'url', 'email_address']:
        for domain in whitelist_domains:
            if domain in indicator.lower():
                return True
    return False

def count_indicators(text):
    indicators = {ioc_type: [] for ioc_type in ioc_patterns}
    for ioc_type, pattern in ioc_patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]  # Use the first captured group if it's a tuple
            if not is_whitelisted(match, ioc_type):
                indicators[ioc_type].append(match)
    return indicators

def main(file_path, show_raw):
    full_content, extracted_text = extract_pdf_content(file_path)
    
    if extracted_text is None:
        print("Failed to extract content from the PDF.")
        return
    
    indicators = count_indicators(extracted_text)
    
    total_indicators = sum(len(matches) for matches in indicators.values())
    indicators_with_data = sum(1 for matches in indicators.values() if matches)
    indicators_without_data = total_indicators - indicators_with_data

    # Visualization and Summary
    print("=" * 40)
    print("Summary and Visualization:")
    print(f"Total indicators submitted: {total_indicators}")
    print(f"Indicators with data: {indicators_with_data}")
    print(f"Indicators without data: {indicators_without_data}")
    
    # Simple ASCII bar chart
    max_bar_length = 20
    with_data_bar = "█" * int((indicators_with_data / total_indicators) * max_bar_length) if total_indicators > 0 else ""
    without_data_bar = "░" * int((indicators_without_data / total_indicators) * max_bar_length) if total_indicators > 0 else ""
    print("\nVisualization:")
    print(f"With data    : {with_data_bar} ({indicators_with_data})")
    print(f"Without data : {without_data_bar} ({indicators_without_data})")

    # Indicators lists
    print("\n" + "=" * 40)
    print("Indicators lists:")
    for ioc_type, matches in indicators.items():
        if matches:
            print(f"\n{ioc_type}:")
            for match in matches:
                print(f"  - {match}")
    
    if show_raw:
        print("\n" + "=" * 40)
        print("Raw text extracted:")
        print(extracted_text)

    print("\n" + "=" * 40)
    print("Whitelisted domains:")
    for domain in whitelist_domains:
        print(f"  - {domain}")

    # Incident Description
    incident_description = extract_incident_description(full_content)
    if incident_description:
        print("\n" + "=" * 40)
        print("Incident Description:")
        print(incident_description)
    else:
        print("\nNo incident description found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and analyze indicators from a PDF file.")
    parser.add_argument("-f", "--file", required=True, help="Path to the PDF file")
    parser.add_argument("--raw", action="store_true", help="Display raw extracted content")
    parser.add_argument("--add-whitelist", nargs="+", help="Add domains to the whitelist")
    args = parser.parse_args()
    
    if args.add_whitelist:
        whitelist_domains.update(args.add_whitelist)
    
    main(args.file, args.raw)