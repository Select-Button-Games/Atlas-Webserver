#ifndef ENDPOINTS_H
#define ENDPOINTS_H

#include "globals.h"
#include <string>
#include "httplib.h"
#include "json.hpp"

using namespace httplib;
using json = nlohmann::json;

// Utility functions
std::string sha256(const std::string& str);
sql::Connection* connect_to_database();

// User management functions
std::string create_user(const std::string& username, const std::string& password);
std::string generate_api_token(int user_id);
bool validate_api_token(const std::string& token);

// HTTP request handlers
void handle_register(const Request& req, Response& res);
void handle_generate_token(const Request& req, Response& res);
void handle_login(const Request& req, Response& res);
bool token_authenticate(const Request& req, Response& res);
void handle_protected_endpoint(const Request& req, Response& res);
void handle_get_user(const Request& req, Response& res);
void handle_static_files(const Request& req, Response& res);
void handle_execute_lua(const Request& req, Response& res);

// Additional structures or functions if needed
//RESTFUL API FOR GETTING USER
struct User {
    int id;
    std::string username;
    std::string password;

    json toJson() {
        return{ { "id", id}, { "username", username} };
    }
};

User getUserFromDatabase(const std::string& username);

#endif
