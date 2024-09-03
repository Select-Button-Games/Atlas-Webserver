#pragma once
#ifndef GLOBALS_H
#define GLOBALS_H
//for main.cpp
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "decoder.h"
#include "VirusScan.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "json.hpp"
#include <iostream>
#include <filesystem>

//for endpoints.cpp 
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

//for lua_parsing.cpp
#include "lua_parsing.h"

struct User;

std::string executeLuaScriptAndCaptureOutput(const std::string& script);
bool scan_file_with_virustotal(const std::string& filename);
void handle_register(const httplib::Request& req, httplib::Response& res);
void handle_generate_token(const httplib::Request& req, httplib::Response& res);
bool token_authenticate(const httplib::Request& req, httplib::Response& res);
void handle_protected_endpoint(const httplib::Request& req, httplib::Response& res);
void handle_login(const httplib::Request& req, httplib::Response& res);
User getUserFromDatabase(const std::string& username);

#endif