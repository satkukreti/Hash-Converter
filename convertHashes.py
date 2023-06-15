import requests

headers = {
 "accept": "application/json",
 "x-apikey": "" #Enter your API key from your VirusTotal account
}

filepath = input("Enter file path: ")
with open(filepath, 'r') as f:
	counter = 0
 	for line in f:
		counter = counter+1
		h = line.strip()
		url = "https://www.virustotal.com/api/v3/files/" + h

		try:
			response = requests.get(url, headers=headers)
			d = response.json()

			print(d["data"]["attributes"]["sha256"])

		except Exception as e:
			print("Error occurred while making the request:", counter)
