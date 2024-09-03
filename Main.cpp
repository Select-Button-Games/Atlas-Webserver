#include "globals.h"
#include "global_functions.h"

#include "endpoints.h"
using json = nlohmann::json;

json loadConfig(const std::string& filename) {
    std::ifstream ifs(filename);
    json config;
    if (ifs.is_open()) {
        ifs >> config;
    }
    else {
        std::cerr << "Could not open config file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }
    return config;
}


int main() {
    // Load config files
    json config = loadConfig("config.json");
    // Create the upload directory if it does not exist
    create_upload_directory();

    // Load server settings
    std::string host = config.at("server").at("host");
    int port = config.at("server").at("port");

    // Initialize the SSL server
    std::string sslCertificate = config.at("websites").at(0).at("sslCertificate");
    std::string sslPrivateKey = config.at("websites").at(0).at("sslPrivateKey");
    httplib::SSLServer svr(sslCertificate.c_str(), sslPrivateKey.c_str());

    if (!svr.is_valid()) {
        std::cerr << "Server has an invalid SSL context" << std::endl;
        return 1;
    }

    // Redirect root URL to index.html
    svr.Get("/", [](const Request& req, Response& res) {
        res.set_redirect("/index.html");
        });
    executeLuaScriptAndCaptureOutput("login.lua");
    // Existing routes
    svr.Post("/upload", handle_file_upload); //file upload
    svr.Post("/register", handle_register); // user registration 
    svr.Post("/login", handle_login);
    svr.Post("/token", handle_generate_token); // token generation
    svr.Get("/protected", handle_protected_endpoint); // protected endpoint
    svr.Get("/upload/(.*)", handle_get_file); // Add this line to handle GET request
    svr.Get("/upload/list", handle_list_files);
    svr.Get("/upload/file/(.*)", handle_get_file);
    svr.Get("/users/(.*)", handle_get_user);
    svr.Get(R"(/(.+\.(html|css|js|png|jpg)))", handle_static_files);
    svr.Get("/execute_lua", handle_execute_lua);

   

    // Start the server
    std::cout << "Server is running on " << host << ":" << port << std::endl;
    svr.listen(host.c_str(), port);
    
    return 0;
}
