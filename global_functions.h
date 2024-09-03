#pragma once
#include "globals.h"

#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

//global functions used in Main.cpp
using namespace httplib;
using json = nlohmann::json;
namespace fs = std::filesystem;

const std::string UPLOAD_DIR = "./uploads/";
const std::string USERNAME = "admin"; // no longer being used but needed still
const std::string PASSWORD = "password"; //no longer being used but needed still 

struct User;




void create_upload_directory() {
#ifdef _WIN32
    int result = _mkdir(UPLOAD_DIR.c_str());
    if (result != 0 && errno != EEXIST) {
        char buffer[100];
        strerror_s(buffer, sizeof(buffer), errno);
        std::cerr << "Error creating directory: " << buffer << std::endl;
        exit(1);
    }
#else
    int result = mkdir(UPLOAD_DIR.c_str(), 0777);
    if (result != 0 && errno != EEXIST) {
        char buffer[100];
        strerror_s(buffer, sizeof(buffer), errno);
        std::cerr << "Error creating directory: " << buffer << std::endl;
        exit(1);
    }
#endif
}

bool authenticate(const Request& req) {
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.find("Basic ") == 0) {
        auto encoded = auth_header.substr(6); // Remove "Basic "
        auto decoded = Base64::decode(encoded);
        auto separator = decoded.find(":");
        if (separator != std::string::npos) {
            auto username = decoded.substr(0, separator);
            auto password = decoded.substr(separator + 1);
            return username == USERNAME && password == PASSWORD;
        }
    }
    return false;
}

void handle_file_upload(const Request& req, Response& res) {
    if (!token_authenticate(req, res)) {
        res.status = 401;
        res.set_content("Unauthorized", "text/plain");
        std::cerr << "Unauthorized access" << std::endl;
        return;
    }
    std::cout << "File upload request received" << std::endl;

    // Debug: List all parameters
    for (const auto& param : req.params) {
        std::cout << "Param: " << param.first << " = " << param.second << std::endl;
    }

    // Debug: List all files
    for (const auto& file : req.files) {
        std::cout << "File: " << file.first << " = " << file.second.filename << " (size: " << file.second.content.size() << " bytes)" << std::endl;
    }

    if (!req.has_file("file")) {
        res.status = 400;
        res.set_content("No file provided", "text/plain");
        std::cerr << "No file provided" << std::endl;
        return;
    }

    auto file = req.get_file_value("file");
    std::string filename = UPLOAD_DIR + file.filename;

    // Save the uploaded file
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs.is_open()) {
        res.status = 500;
        res.set_content("Error saving file", "text/plain");
        std::cerr << "Error opening file for writing" << std::endl;
        return;
    }

    ofs.write(file.content.data(), file.content.size());
    ofs.close();
    std::cout << "File saved successfully" << std::endl;

    // Rename the file to final location
    std::string final_filename = UPLOAD_DIR + file.filename;
    int result = std::rename(filename.c_str(), final_filename.c_str());
    if (result != 0) {
        char buffer[100];
        strerror_s(buffer, sizeof(buffer), errno);
        std::cerr << "Error renaming file: " << buffer << std::endl;
        res.status = 500;
        res.set_content("Error renaming file", "text/plain");
        return;
    }
    std::cout << "File renamed successfully" << std::endl;

    // Scan file with VirusTotal (assuming function is defined)
    if (!scan_file_with_virustotal(final_filename)) {
        res.status = 500;
        res.set_content("Error scanning file", "text/plain");
        return;
    }
    std::cout << "File scanned successfully" << std::endl;

    if (!req.has_param("fileType")) {
        res.status = 400;
        res.set_content("Missing file type", "text/plain");
        std::cerr << "Missing file type" << std::endl;
        return;
    }


    std::string fileType = req.get_param_value("fileType");
    std::cout << "After Getting File type: " << fileType << std::endl;

    // Read the existing JSON file or create a new one
    json storage;
    std::cout << "Before opening storage.json for reading" << std::endl;
    std::ifstream ifs("storage.json");
    if (ifs.is_open()) {
        ifs >> storage;
        ifs.close();
        std::cout << "Read storage.json successfully" << std::endl;
    }
    else {
        std::cerr << "Failed to open storage.json for reading" << std::endl;
    }

    // Add file information
    storage[fileType].push_back(final_filename);


    // Save the JSON file
    std::cout << "Before opening storage.json for writing" << std::endl;
    std::ofstream ofs_json("storage.json");
    if (!ofs_json.is_open()) {
        res.status = 500;
        res.set_content("Error saving JSON file", "text/plain");
        std::cerr << "Error opening JSON file for writing" << std::endl;
        return;
    }
    std::cout << "After opening storage.json for writing" << std::endl;

    ofs_json << storage.dump(4); // Pretty print with 4 spaces
    if (ofs_json.fail()) {
        res.status = 500;
        res.set_content("Error writing to JSON file", "text/plain");
        std::cerr << "Error writing to JSON file" << std::endl;
        return;
    }
    std::cout << "After writing to storage.json" << std::endl;
    ofs_json.close();
    std::cout << "JSON file saved successfully" << std::endl;

    res.status = 200;
    res.set_content("File uploaded successfully", "text/plain");
}








void handle_get_file(const Request& req, Response& res) {
    if (!token_authenticate(req, res)) {
        res.status = 401;
        res.set_content("Unauthorized", "text/plain");
        return;
    }

    std::string filename = req.matches[1];
    std::string filepath = UPLOAD_DIR + filename;

    std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
    if (ifs) {
        auto end = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        auto size = std::size_t(end - ifs.tellg());

        json response;
        response["filename"] = filename;
        response["size"] = size;

        if (size == 0) { // empty file
            res.status = 200;
            response["content"] = "";
        }
        else {
            std::string contents(size, '\0');
            ifs.read(&contents[0], size);
            response["content"] = contents; // or some other property of the file
        }

        res.set_content(response.dump(), "application/json");
    }
    else {
        res.status = 404;
    }
}


void handle_list_files(const Request& req, Response& res) {
    if (!token_authenticate(req, res)) {
        res.status = 401;
        res.set_content("Unauthorized", "text/plain");
        return;
    }

    json file_list = json::array();

    for (const auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
        if (entry.is_regular_file()) {
            file_list.push_back(entry.path().filename().string());
        }
    }

    res.set_content(file_list.dump(), "application/json");
}
