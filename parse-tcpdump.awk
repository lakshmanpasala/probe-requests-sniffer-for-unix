# extract dBm and distance
# taking default frequency as 2412 MHz
# formula is
# distance = 10 ^ ((27.55 - (20 * log10(frequency)) + |strength|)/20)
# frequency in MHz and strength in dBm

match($0, /-?[0-9]+dBm/, strength) {
	STRENGTH=strength[0]
	BASE=10
	RADICAL=(-40.097 + (-1)*STRENGTH )/40
	DISTANCE=BASE^RADICAL
}

# extract sender MAC address
match($0, /SA(:[a-f0-9]{2}){6}/, mac) {
	gsub(/SA:/, "", mac[0])
	MAC=mac[0]
}

# extract SSID with Probe Request"t (SSID)" regex
match($0, /Probe Request \(.*\)/, ssid) {

	# substitute "t (" and trailing ")" in-place
	gsub(/(Probe Request \(|\))/, "", ssid[0])

	# if there is a non-empty SSID
	if (length(ssid[0]) != 0) {

		# escape commas
		# gsub(/,/, "\\,", ssid[0])
		SSID=ssid[0]

		# extract TIMESTAMP
		gsub(/\.[0-9]+/, "", $1)
		TIMESTAMP=$1

		# print them to stdout
		print TIMESTAMP " " STRENGTH " " DISTANCE"m" " " MAC " \"" SSID "\""
		system("") # flush the buffer
	}
}
