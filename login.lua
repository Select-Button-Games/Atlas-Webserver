-- Assume username and password are provided to the script
local username = "user_example"
local password = "password_example"

-- Call the login function exposed from C++
local token_or_error = login(username, password)

-- Decide what to do based on the result
if token_or_error and #token_or_error > 0 then
    print("Login successful. Token: " .. token_or_error)
else
    print("Login failed.")
end
