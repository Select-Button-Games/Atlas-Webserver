# Atlas-WebServer

Atlas-WebServer is a C++ based web server implementation designed for handling file uploads with integrated virus scanning functionality. It also serves as a micro web server for a small website it can handle HTML, CSS, IMAGES, LUA, and a few other things a website will need. 

## Features
- **File Upload Handling**: Supports handling multiple file uploads.
- **Virus Scanning**: Integrated with a virus scanning module to ensure uploaded files are safe.
- **Configuration**: Easily configurable via `config.json`.

## Installation
1. **Clone the repository**:
   ```sh
   git clone https://github.com/Tivoilos/Atlas-WebServer.git
   cd Atlas-WebServer
2. **Dependencies: Ensure you have the required dependencies installed.**;


cpp-httplib: Found in cpp-httplib-0.15.3/
Lua: Included DLLs (lua.dll, libcrypto-3-x64.dll, libssl-3-x64.dll)

3. **Build the project**;
Open Dev_Upload_Server.sln in Visual Studio.
Build the solution.

## Usage
1. **Configure the server**;

Edit config.json to set your desired configurations.


2. **Run the server**;
   ```sh
   ./Dev_Upload_Server

## Project Structure
  Main.cpp: Entry point of the server.
  VirusScan.cpp / VirusScan.h: Modules for virus scanning.
  endpoints.cpp / endpoints.h: Define the server endpoints.
  decoder.cpp / decoder.h: Handles file decoding.
  login.lua: Lua script for handling login operations.
  cpp-httplib-0.15.3/: HTTP library used by the server.
  config.json: Configuration file for the server.

## License
**This project is licensed under the MIT License - see the LICENSE.txt file for details.**;

## Contributing
Feel free to submit issues or pull requests. For major changes, please open an issue first to discuss what you would like to change.




