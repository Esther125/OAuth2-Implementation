# Spring Authorization Server with Wekan Integration　　
## Overview
This project is developed during my internship at Academia Sinica. It features a custom Spring Authorization Server designed to integrate with Wekan, the open-source kanban software, using OpenID Connect (OIDC) for authentication. One of the key enhancements of this server is the ability to log in using QR codes, streamlining the authentication process and saving time for users.

## Features
- OIDC Login: Implements OpenID Connect protocol to facilitate secure authentication and authorization processes.
- Wekan Integration: Seamlessly integrates with Wekan, allowing users to manage kanban boards with improved authentication methods.
- QR Code Login: Users can log in quickly by scanning a QR code with their mobile device, enhancing the user experience and access efficiency.

## How to use?
### Run Wekan
To ensure proper connectivity with the authorization server, especially when running on WSL2, update the OAUTH2_SERVER_URL in the Docker Compose configuration:
```bash
# .devcontainer/docker-compose.yml
- OAUTH2_SERVER_URL=http://{WSL IP address}:8080
```
To determine the WSL IP address, use the following command in your WSL terminal:
```bash
ip addr # Look for the IP address listed under eth0
```
Start the Wekan application using:
```
cd wekan-7.01
docker-compose -f .devcontainer/docker-compose.yml up
```
The app will run on http://localhost:3000 after you build it successfully.

### Run Spring Authorization Server 
Execute `SpringAuthorizationServerExampleApplication.java` to start the server.
The server will be accessible at http://localhost:8080.

### Testing with Postman
You can use Postman to test the QR code scanning part. First, you should scan the QR code with your cellphone, and you will get a token. Next, to simulate the login process through your application backend, follow these steps in Postman:
- Create a new request.
- Select 'POST' as the request method.
- Set the request URL to `http://localhost:8080/login/clt`.
- Configure the request body
```
{
    "token": "{The token you get when scanning Qrcode}", 
    "client_id": "wekan",
    "state": "eyJsb2dpblN0eWxlIjoicG9wdXAiLCJjcmVkZW50aWFsVG9rZW4iOiJIbEYxS1pBbVhpWTkzUUEzWmlvWkw4dWtHX0xtLUF4RlMyVzNBWFVidEg4IiwiaXNDb3Jkb3ZhIjpmYWxzZX0=",
    "userName": "admin",
    "password": "password"
}
```
This setup allows you to thoroughly test and ensure the authentication process aligns with your operational requirements.

