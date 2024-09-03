#include "globals.h"
#include "endpoints.h"
// Function to hash a string using SHA256
std::string sha256(const std::string& str) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_DigestInit_ex(context, md, NULL);
    EVP_DigestUpdate(context, str.c_str(), str.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to connect to MySQL database
sql::Connection* connect_to_database() {
    sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
    sql::Connection* conn = driver->connect("tcp://LOCALHOST", "USERNAME", "TESTPASSWORD"); // Replace with your credentials and IP etc
    conn->setSchema("api_auth");
    return conn;
}

// Function to create a new user
std::string create_user(const std::string& username, const std::string& password) {
    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("INSERT INTO users (username, password) VALUES (?, ?)"));
        pstmt->setString(1, username);
        pstmt->setString(2, sha256(password));
        pstmt->execute();
        delete conn;
        return "User registered successfully";
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        return std::string("User registration failed: ") + e.what();
    }
}

// Function to generate a new API token for a user
std::string generate_api_token(int user_id) {
    std::string token = sha256(std::to_string(user_id) + std::to_string(time(nullptr)));
    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("INSERT INTO tokens (user_id, token) VALUES (?, ?)"));
        pstmt->setInt(1, user_id);
        pstmt->setString(2, token);
        pstmt->execute();
        delete conn;
        return token;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        return "";
    }
}

// Function to validate an API token
bool validate_api_token(const std::string& token) {
    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT user_id FROM tokens WHERE token = ?"));
        pstmt->setString(1, token);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        bool is_valid = res->next();
        delete conn;
        return is_valid;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        return false;
    }
}

// Endpoint for user registration
void handle_register(const Request& req, Response& res) {
    auto body = json::parse(req.body);
    std::string username = body["username"];
    std::string password = body["password"];

    std::string result = create_user(username, password);
    json response_body;
    if (result == "User registered successfully") {
        response_body["success"] = true;
        response_body["message"] = result;
    }
    else {
        res.status = 500;
        response_body["success"] = false;
        response_body["message"] = result;
    }
    res.set_content(response_body.dump(), "application/json");
}

void handle_generate_token(const Request& req, Response& res) {
    auto body = json::parse(req.body);
    std::string username = body["username"];
    std::string password = body["password"];

    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT id, password FROM users WHERE username = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> result_set(pstmt->executeQuery());

        if (result_set->next()) {
            int user_id = result_set->getInt("id");
            std::string stored_password = result_set->getString("password");

            if (stored_password == sha256(password)) {
                std::string token = generate_api_token(user_id);
                json response = { {"token", token} };
                res.set_content(response.dump(), "application/json");
            }
            else {
                res.status = 401;
                res.set_content("Invalid credentials", "text/plain");
            }
        }
        else {
            res.status = 404;
            res.set_content("User not found", "text/plain");
        }
        delete conn;
    }
    catch (sql::SQLException& e) {
        res.status = 500;
        res.set_content("Server error", "text/plain");
    }
}



bool token_authenticate(const Request& req, Response& res) {
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.find("Bearer ") == 0) {
        std::string token = auth_header.substr(7); // Remove "Bearer "
        return validate_api_token(token);
    }
    return false;
}

void handle_protected_endpoint(const Request& req, Response& res) {
    if (!token_authenticate(req, res)) {
        res.status = 401;
        res.set_content("Unauthorized", "text/plain");
        return;
    }

    // Handle your protected endpoint logic here
    res.set_content("Access granted", "text/plain");
}


void handle_login(const Request& req, Response& res) {
    std::cout << "Login Endpoint hit" << "/n" << std::endl;
    
    // Set CORS headers
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    // Handle OPTIONS method for preflight request
    if (req.method == "OPTIONS") {
        res.status = 204; // No Content
        return;
    }
    auto body = json::parse(req.body);
    std::string username = body["username"];
    std::string password = body["password"];

    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT id, password FROM users WHERE username = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> result_set(pstmt->executeQuery());

        json response_body;
        if (result_set->next()) {
            int user_id = result_set->getInt("id");
            std::string stored_password = result_set->getString("password");

            if (stored_password == sha256(password)) {
                std::string token = generate_api_token(user_id);
                response_body["success"] = true;
                response_body["token"] = token;
            }
            else {
                res.status = 401;
                response_body["success"] = false;
                response_body["message"] = "Invalid credentials";
            }
        }
        else {
            res.status = 404;
            response_body["success"] = false;
            response_body["message"] = "User not found";
        }
        res.set_content(response_body.dump(), "application/json");
        delete conn;
    }
    catch (sql::SQLException& e) {
        res.status = 500;
        json response_body;
        response_body["success"] = false;
        response_body["message"] = "Server error";
        res.set_content(response_body.dump(), "application/json");
    }
}



User getUserFromDatabase(const std::string& username)
{
    try {
        sql::Connection* conn = connect_to_database();
        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement("SELECT * FROM users WHERE username = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        if (res->next()) {
            User user;
            user.id = res->getInt("id");
            user.username = res->getString("username");
            user.password = res->getString("password");
            return user;
        }
        else {
            return User();
        }
        delete conn;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        return User();
    }
}

void handle_get_user(const Request& req, Response& res) {
    std::string username = req.matches[1];

    try {
        // Retrieve user information from your data storage
        User user = getUserFromDatabase(username);
        std::cout << "User ID: " << user.id << ", Username: " << user.username << std::endl;
        // Convert user information to JSON
        json userJson = user.toJson();
        std::cout << "User JSON: " << userJson.dump() << std::endl;
        // Set the response content type and body
        res.set_content(userJson.dump(), "application/json");
        std::cout << "Response set successfully" << std::endl;
    }
    catch (const std::exception& e) {
        res.status = 500;
        res.set_content(e.what(), "text/plain");
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void handle_static_files(const Request& req, Response& res) {
    // Define the root directory for static files
    const std::string static_files_directory = "www/";

    // Extract the requested path from the request
    std::string requested_path = req.path;

    // Security check: Ensure the requested path does not contain ".." to prevent directory traversal attacks
    if (requested_path.find("..") != std::string::npos) {
        res.status = 403;
        res.set_content("Access denied", "text/plain");
        return;
    }

    // Construct the full path to the requested file
    std::string full_path = static_files_directory + requested_path;

    // Open the requested file
    std::ifstream file(full_path, std::ios::binary);

    if (file) {
        // Determine the content type based on the file extension
        std::string content_type = "text/plain"; // Default content type
        if (requested_path.ends_with(".css")) {
            content_type = "text/css";
        }
        else if (requested_path.ends_with(".png")) {
            content_type = "image/png";
        }
        else if (requested_path.ends_with(".jpg") || requested_path.ends_with(".jpeg")) {
            content_type = "image/jpeg";
        }
        else if (requested_path.ends_with(".html")) {
            content_type = "text/html";
        } // Add more content types as needed

        // Read the file content and set it as the response body
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        res.set_content(content, content_type.c_str());
    }
    else {
        // File not found
        res.status = 404;
        res.set_content("File not found", "text/plain");
    }
}

void handle_execute_lua(const Request& req, Response& res) {
    auto body = json::parse(req.body);
    std::string script = body["script"];
    std::string username = body["username"];
    std::string password = body["password"];

    // Assuming you have a function to set up the Lua environment and execute the script
    // This function should pass `username` and `password` to the Lua script and capture the output
    std::string output = executeLuaScriptAndCaptureOutput("login.lua"); // This function needs to be implemented

    // Prepare the response based on the Lua script output
    json response_body;
    response_body["output"] = output;

    // Set the response content
    res.set_content(response_body.dump(), "application/json");
}
