#include "globals.h"

using json = nlohmann::json;
// Initialize Lua and execute a script
void executeLuaScript(const std::string& script) {
    lua_State* L = luaL_newstate(); // Create a new Lua state
    luaL_openlibs(L); // Open the standard Lua libraries

    // Execute the Lua script
    if (luaL_dofile(L, script.c_str()) != LUA_OK) {
        std::cerr << "Error executing Lua script: " << lua_tostring(L, -1) << std::endl;
    }

    lua_close(L); // Close the Lua state
}

std::string executeLuaScriptAndCaptureOutput(const std::string& script) {
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    // Redirect the print function to capture output
    std::ostringstream output;
    lua_pushlightuserdata(L, &output);
    lua_pushcclosure(L, [](lua_State* L) -> int {
        std::ostringstream* output = static_cast<std::ostringstream*>(lua_touserdata(L, lua_upvalueindex(1)));
        int nargs = lua_gettop(L);
        for (int i = 1; i <= nargs; i++) {
            if (lua_isstring(L, i)) {
                *output << lua_tostring(L, i);
                if (i != nargs) *output << "\t";
            }
        }
        *output << "\n";
        return 0;
        }, 1);
    lua_setglobal(L, "print");

    // Execute the Lua script
    if (luaL_dostring(L, script.c_str()) != LUA_OK) {
        std::cerr << "Error executing Lua script: " << lua_tostring(L, -1) << std::endl;
    }

    lua_close(L);
    return output.str();
}

int lua_login(lua_State* L) {
    // Get username and password from Lua arguments
    const char* username = luaL_checkstring(L, 1);
    const char* password = luaL_checkstring(L, 2);

    // Create a Request object and populate its body with username and password in JSON format
    httplib::Request req;
    json body;
    body["username"] = username;
    body["password"] = password;
    req.body = body.dump();

    // Create a Response object to capture the response from handle_login
    httplib::Response res;

    // Use your existing C++ code to validate the user
    handle_login(req, res);

    // Extract the token or error message from the response
    auto res_body = json::parse(res.body);
    std::string token_or_error = res_body.contains("token") ? res_body["token"] : res_body["message"];

    // Push the result (token or error message) back to Lua
    lua_pushstring(L, token_or_error.c_str());

    return 1; // Number of return values
}

// This function should be called after initializing your Lua state
void registerLuaFunctions(lua_State* L) {
    lua_register(L, "login", lua_login);
}