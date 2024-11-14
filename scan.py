import virustotal_python
import re

hash = input("Enter the hash (MD5 or SHA256): ")
api = input("Enter the VT API key: ")


if not api:
    print("API key is required. Please enter a valid API key.")
else:
    if not re.match(r"([a-fA-F\d]{32})", hash) and not re.match(r"([a-fA-F\d]{64})", hash):
        print("Invalid hash. Please enter valid hash")
    else:
        try:
            with virustotal_python.Virustotal(api) as vtotal:
                file_report = vtotal.request(f"files/{hash}")
                count = file_report.data['attributes']['last_analysis_stats']['malicious']
                status = file_report.response.status_code
                if status != 200:
                    print("API called failed")
                else:
                    print(f"API Call Status Code: {status}")

                if count > 5:
                    print(f"This file has been detected as malicious by {count} AV engines")
                elif count >0:
                    print(f"This file may be malicious, as it was detected by {count} AV engines")

                else:
                    print("This file is clean")

        except Exception as e:
            print(f"Error: {e}")