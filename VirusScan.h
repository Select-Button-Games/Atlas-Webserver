#pragma once
#include "globals.h"

const std::string VIRUSTOTAL_API_KEY = "INSERT YOUR API KEY HERE";

// Scan a file with VirusTotal
bool scan_file_with_virustotal(const std::string& filename);


