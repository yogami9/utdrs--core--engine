# Core Engine for Unified Threat Detection and Response System (UTDRS)

This is the Core Engine component of the UTDRS, providing threat detection capabilities using signature-based, anomaly-based, and machine learning approaches.

## Features

- Multi-layered threat detection
- Rule-based detection engine
- Machine learning model integration
- MITRE ATT&CK framework mapping
- MongoDB integration for data storage
- Dockerized for easy deployment on Render
- REST API for integration with other components

## Getting Started

### Prerequisites

- Docker and Docker Compose (for local development)
- MongoDB database (can use MongoDB Atlas)

### Local Development

1. **Clone the repository**

```bash
git clone <repository-url>
cd core-engine
```

2. **Configure environment variables**

Copy the example environment file and update it with your settings:

```bash
cp .env.example .env
# Edit .env with your MongoDB connection details and other settings
```

3. **Run using Docker Compose**

```bash
docker-compose up
```

The API will start running at `http://localhost:8001`, and you can access the API documentation at `http://localhost:8001/docs`.

## Deployment on Render

### Using the Render Dashboard

1. Create a new Web Service on Render
2. Select "Build and deploy from a Git repository"
3. Connect your GitHub/GitLab repository
4. Select "Docker" as the runtime
5. Configure environment variables:
   - `MONGODB_URI`: Your MongoDB connection string
   - `DB_NAME`: Database name (default is "utdrs")
   - `API_GATEWAY_URL`: URL of the deployed API Gateway
   - `JWT_SECRET`: A secret key for JWT token generation
   - `DEBUG`: Set to "false" for production

## API Endpoints

- **/health** - Health check endpoints
- **/detections/process** - Process an event and generate alerts
- **/detections/alerts** - Get and manage alerts
- **/rules** - Manage detection rules

## Project Structure

- **api/** - API routes and controllers
- **core/** - Core detection engine logic
  - **detection/** - Detection modules (signature, anomaly, ML)
  - **models/** - Data models and ML models
  - **rules/** - Rule management
  - **services/** - Business logic services
  - **database/** - Database connection and repositories
- **utils/** - Utility functions
- **ml_models/** - Pre-trained ML models
- **tests/** - Test files

## Integration with Other Components

The Core Engine integrates with:

- **API Gateway** - For centralized communication
- **MongoDB** - For data storage
- **Response Service** - For automated threat response
