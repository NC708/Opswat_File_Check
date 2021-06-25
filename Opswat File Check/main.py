import time
import requests
import hashlib

fileName = input("Enter file name: ")
contents = open("sample_files/" + fileName, "rb").read()
hash = hashlib.sha1(contents).hexdigest()
apiKey = open("apiKey.txt").read()

# selectivePrint() prints 6 relevant selections from the given JSON dict
# if an exception is thrown (such as when a non-existent member is referenced),
# the entire dict is printed instead
def selectivePrint(rawData):
    try:
        print(
        "filename: " + rawData['file_info']['display_name'] + "\n" +
        "overall_status: " + rawData['scan_results']['scan_all_result_a'] + "\n"
        )
        for i in rawData['scan_results']['scan_details']:
            print(
            "engine: " + str(i) + "\n" +
            "threat_found: " + str(rawData['scan_results']['scan_details'][i]['threat_found']) + "\n" +
            "scan_result: " + str(rawData['scan_results']['scan_details'][i]['scan_result_i']) + "\n" +
            "def_time: " + str(rawData['scan_results']['scan_details'][i]['def_time']) + "\n" 
            )

    except:
        print("Some elements missing - raw JSON data is displayed below: \n" + str(rawData))

# this communicates with Opswat's API to check if the file in question has been
# scanned before. If not, it is uploaded and scanned by several engines.
# when scan is complete, the dict is sent to selectivePrint()
hashCheck = requests.get("https://api.metadefender.com/v4/hash/" + hash, headers = {"apikey" : apiKey}).json()
try:
    print("Error: " + str(hashCheck['error']))
    if (hashCheck['error']['code'] == 404003):
        print("Analyzing File...")
        postReq = requests.post("https://api.metadefender.com/v4/file", headers = {"apikey" : apiKey, "content-type" : "application/octet-stream"}, data = {contents}).json()
        while True:
            result = requests.get("https://api.metadefender.com/v4/file/" + postReq['data_id'], headers = {"apikey" : apiKey}).json()
            if result['scan_results']['scan_all_result_a'] not in ("In Progress", "In queue"):
                selectivePrint(result)
                print("Analysis completed.")
                break
            time.sleep(1)
    else:
        print("Error unresolvable.")
        
except:
    print("File found in archive.")
    selectivePrint(hashCheck)

print("Press enter to exit.")
input()