# Common Setting for Networt awareness module.

import os

DISCOVERY_PERIOD = 10   			# For discovering topology.

MONITOR_PERIOD = 5					# For monitoring traffic

DELAY_DETECTING_PERIOD = 5			# For detecting link delay.

TOSHOW = True						# For showing information in terminal

MAX_CAPACITY = 281474976710655		# Max capacity of link

MININET_REST_BASE_URL = os.getenv("MININET_SERVER_URL", "http://localhost:8081")

BANDWIDTH_SOURCE = "mininet"
