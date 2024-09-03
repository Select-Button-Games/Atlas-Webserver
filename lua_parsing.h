#include <iostream>
#include <sstream>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

void executeLuaScript(const std::string& script);
std::string executeLuaScriptAndCaptureOutput(const std::string& script);
