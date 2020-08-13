import requests
import logging

class MininetRestClient(object):
    def __init__(self, base_url):
        self.base_url = base_url
    
    def get_link_bandwidths(self):
        try:
            bandwidths = {}
            resp = requests.get(self.base_url + "/links")
            links = resp.json().get("links", [])

            for link in links:
                bandwidths[link["intf1"]] = link["bw1"]
                bandwidths[link["intf2"]] = link["bw2"]

            return bandwidths
        except:
            return {}