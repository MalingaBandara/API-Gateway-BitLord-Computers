<div align="center">
  <h1>🚪 Bitlord's Computer Parts - API Gateway</h1>
  <p>The single entry point, intelligent router, and security perimeter for all microservices.</p>
</div>

## 📖 Overview
The **API Gateway** intercepts all incoming traffic from the frontend application. It leverages the Eureka Server to dynamically route requests to the correct backend service instances. Additionally, it implements a security filter chain to validate JWTs on protected routes before allowing requests into the internal network.

[⬅️ Back to Main Repository](https://github.com/yourusername/bitlord-computer-parts)

## 🛠️ Tech Stack
- **Language**: Java 17
- **Framework**: Spring Boot 3.2
- **Gateway**: Spring Cloud Gateway
- **Security**: JWT Validation Filters
- **Service Discovery**: Netflix Eureka Client
- **Observability**: Prometheus, Micrometer, Zipkin

## 🛣️ Routing Configuration
The Gateway resolves routes dynamically using service names registered in Eureka:
- `/api/auth/**` ➡️ `auth-service`
- `/api/orders/**` ➡️ `order-service` (Secured: requires valid JWT)
- `/api/inventory/**` ➡️ `inventory-service` (Write operations secured)

## 🛡️ Security & Cross-Cutting Concerns
- **JWT Validation**: Decodes and verifies tokens issued by the Auth Service without hitting the database, rejecting unauthorized requests instantly.
- **CORS Handling**: Configured to safely accept Cross-Origin requests from the Frontend Application.
- **Distributed Tracing**: Automatically injects and propagates Zipkin trace IDs into HTTP headers for full request observability.

## 🚀 How to Run Locally

### Prerequisites
- JDK 17
- Maven
- Eureka Server must be running first.

### Steps
1. Navigate to the `api-gateway` directory.
2. Build the project:
   ```bash
   mvn clean install -DskipTests
   ```
3. Run the application:
   ```bash
   mvn spring-boot:run
   ```
4. The Gateway will start on port `8080`. All frontend API traffic should be directed here.
