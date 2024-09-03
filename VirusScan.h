#pragma once
#include "globals.h"

const std::string VIRUSTOTAL_API_KEY = "6dfbbf7f2f70a6097bd4b9c8df55d1a822f40cb2d814506c85deb2593cbb5329";

// Scan a file with VirusTotal
bool scan_file_with_virustotal(const std::string& filename);


