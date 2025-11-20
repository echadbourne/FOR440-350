rule is_ThugLyfeInstaller {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks for embedded executables"
		date="2025-09-17"
	strings:
		$executable = "!This program cannot be run in DOS mode."
	condition:
		#executable > 1
}

rule is_ThugLyfedownloader {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks for call to thug-lyfe server"
		date="2025-10-04"
	strings:
		$thuglyfe = "thug.lyfe" nocase
	condition:
		$thuglyfe
}

rule is_ThugLyfeservercall {
	meta:
		author="Elizabeth Chadbourne"
		description="Checks for known thug-lyfe ip address"
		date="2025-10-04"
	strings:
		$thuglyfeserver = "165.73.244.11"
	condition:
		$thuglyfeserver
}