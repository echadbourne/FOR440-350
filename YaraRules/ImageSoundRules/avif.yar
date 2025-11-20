rule avif {
	meta:
		description = "Checks if a file is a avif file"
		author = "Elizabeth Chadbourne"
		date = "2025-10-06"
		
	strings:
		$avif = { 66 74 79 70 61 76 69 66 }
		
	condition:
		$avif at 4
}