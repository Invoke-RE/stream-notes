# Define the list of extensions to exclude
$excludeExtensions = @('386', 'adv', 'ani', 'bat', 'bin', 'cab', 'cmd', 'com', 'cpl', 'cur', 'deskthemepack', 'diagcab', 'diagcfg', 'diagpkg', 'dll', 'drv', 'exe', 'hlp', 'icl', 'icns', 'ico', 'ics', 'idx', 'lnk', 'mod', 'mpa', 'msc', 'msp', 'msstyles', 'msu', 'nls', 'nomedia', 'ocx', 'prf', 'ps1', 'rom', 'rtp', 'scr', 'shs', 'spl', 'sys', 'theme', 'themepack', 'wpx', 'lock', 'key', 'hta', 'msi', 'pdb', 'search-ms')

# Get all files recursively
$allFiles = Get-ChildItem -Path C:\ -Recurse -File

# Filter out files with the specified extensions
$filteredFiles = $allFiles | Where-Object { 
    $extension = $_.Extension.TrimStart('.').ToLower()
    -not ($excludeExtensions -contains $extension)
}

# Sort the remaining files by their size
$sortedFiles = $filteredFiles | Sort-Object Length

# Define the output file path
$outputFilePath = "C:\\sorted_files_table.txt"

# Write the sorted files to the output file in a table format
$sortedFiles | Format-Table Name, Length, Directory | Out-File -FilePath $outputFilePath
