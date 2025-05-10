# Spring OAuth2 Demo

This project demonstrates a working OAuth2 Authorization Server and Resource Server in Spring Boot 3.4.5, with JWT token support and client_credentials flow.

## Projects

- `auth-server/`: Issues JWTs using Spring Authorization Server
- `resource-server/`: Validates JWTs and secures a `/api/sample` endpoint
- `postman/`: Postman collection to test the full flow

## How to Run

```bash
cd auth-server
./mvnw spring-boot:run

# In a new terminal:
cd ../resource-server
./mvnw spring-boot:run

