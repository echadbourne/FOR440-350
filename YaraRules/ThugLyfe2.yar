import "hash"

rule is_ThugLyfeServerCall {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks for known thug-lyfe ip addresses"
		date="2025-10-04"
	strings:
		$thuglyfeserver = "165.73.244.11"
		$thuglyfeserver2 = "108.181.155.31"
	condition:
		$thuglyfeserver or $thuglyfeserver2
}

rule is_ThugLyfeEncodedServer{
	meta:
		author = "Elizabeth Chadbourne"
		description = "Checks for known thug-lyfe ip addresses in base64 encoding"
		date = "2025-10-10"
	strings:
		$encodedserver = "165.73.244.11" base64
		$encodedserver2 = "108.181.155.31" base64
	condition:
		$encodedserver or $encodedserver2
}

rule is_ThugLyfeSusImageDownloader {
	meta: 
		author = "Elizabeth Chadbourne"
		description = "Checks for known suspicious document hash"
		date = "2025-10-10"
		
	condition:
		(hash.md5(0,filesize) == "92910b8ec24ace49e3a6eecf3670ff57")
}