import requests

# The URL you want to check
url = "https://www.youtube.com/watch?v=rWcLDax-VmM"

# OpenLinkProfiler API endpoint
endpoint = "https://openlinkprofiler.org/api/getBackLinks"

# Set up parameters
params = {
    'url': url,
    'max': 10,  # Limit to 10 backlinks for this example
}

# Make the request to the OpenLinkProfiler API
response = requests.get(endpoint, params=params)

# Check the response
if response.status_code == 200:
    data = response.json()
    backlinks = data.get('backlinks', [])
    for backlink in backlinks:
        print(backlink)
else:
    print("Error:", response.status_code)
