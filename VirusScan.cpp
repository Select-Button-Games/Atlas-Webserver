#include "globals.h"


bool scan_file_with_virustotal(const std::string& filename) {
    httplib::Client cli("https://www.virustotal.com");
    httplib::Headers headers = {
        {"x-apikey", VIRUSTOTAL_API_KEY}
    };

    // Open the file in binary mode
    std::ifstream ifs(filename, std::ios::binary);

    // Read the file into a string
    std::string file_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    // Create a multipart form
    httplib::MultipartFormDataItems items = {
        {"file", file_content, filename, "application/octet-stream"}
    };

    // Send a POST request to the VirusTotal API
    auto res = cli.Post("/api/v3/files", headers, items);

    // Check the response
    if (res && res->status == 200) {
        std::cout << "File scanned successfully" << std::endl;
        return true;
    }
    else {
        // There was an error sending the file
        std::cout << "Error scanning file: " << res.error() << std::endl;
        return false;
    }
}
