# 🔍 Port Scanner API

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688)](https://fastapi.tiangolo.com/)

An asynchronous port scanning API built with FastAPI. Features real-time WebSocket updates, persistent SQLite storage, configurable security controls, and comprehensive service detection capabilities.

## ✨ Features

- **🚀 High-Performance Async Scanning**: Built on `asyncio` with configurable concurrency limits and rate limiting
- **📡 Real-Time Updates**: WebSocket endpoints for live scan progress monitoring
- **🗄️ Persistent Storage**: SQLite database with SQLAlchemy ORM for scan history and results
- **🔒 Security Controls**: CIDR-based network restrictions to prevent unauthorized scanning
- **🎯 Multiple Scan Presets**: Quick, Common, Extended, Full, Web, Database, and Mail port presets
- **📊 Service Detection**: Automatic service identification and banner grabbing for common ports
- **⚙️ Flexible Configuration**: Environment-based configuration via `pydantic-settings`
- **📱 RESTful API**: Complete CRUD operations for scan management with OpenAPI documentation

## 📁 Project Structure

```
.
├── api
│   └── main.py              # FastAPI application & REST endpoints
├── config.py                # Application configuration & settings
├── core
│   ├── database.py          # SQLAlchemy models & database operations
│   └── scanner.py           # Async port scanning engine
├── requirements.txt         # Python dependencies
└── start_server.py          # Server startup script with CLI args
```

## 🛠️ Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/port-scanner-api.git
   cd port-scanner-api
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv

   # On Windows
   venv\Scripts\activate

   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| FastAPI | 0.109.0 | Web framework |
| Uvicorn | 0.27.0 | ASGI server |
| SQLAlchemy | 2.0.25 | ORM & database |
| aiosqlite | 0.19.0 | Async SQLite driver |
| Pydantic | 2.5.3 | Data validation |
| pydantic-settings | 2.1.0 | Configuration management |
| websockets | 12.0 | WebSocket support |

## ⚙️ Configuration

Configuration is managed via `config.py` using `pydantic-settings`. Create a `.env` file in the project root:

```bash
APP_NAME=Port Scanner API
APP_VERSION=1.0.0
DEBUG=false
HOST=0.0.0.0
PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./portscanner.db
ALLOWED_NETWORKS=["192.168.1.0/24","10.0.0.0/8","127.0.0.1/32"]
DEFAULT_TIMEOUT=2.0
DEFAULT_MAX_CONCURRENT=100
# DEFAULT_RATE_LIMIT=100
CORS_ORIGINS=["http://localhost:5173","http://localhost:3000"]
LOG_LEVEL=INFO

```

### Key Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8000` | Server port |
| `DATABASE_URL` | `sqlite+aiosqlite:///./portscanner.db` | Database connection string |
| `ALLOWED_NETWORKS` | `[]` | Comma-separated CIDR ranges (empty = no restrictions) |
| `DEFAULT_TIMEOUT` | `2.0` | Connection timeout in seconds |
| `DEFAULT_MAX_CONCURRENT` | `100` | Max concurrent connections per scan |
| `CORS_ORIGINS` | `["*"]` | Allowed CORS origins |

## 🚀 Usage

### Starting the Server

**Basic startup:**
```bash
python start_server.py
```

**Development mode with auto-reload:**
```bash
python start_server.py --reload --verbose
```

**Production deployment:**
```bash
python start_server.py --host 0.0.0.0 --port 8000
```

**Initialize database only:**
```bash
python start_server.py --init-db
```
**Server Options:**
```bash
python start_server.py --help

# Options:
#   --host TEXT       Host to bind to (default: 0.0.0.0)
#   --port INTEGER    Port to bind to (default: 8000)
#   --reload          Enable auto-reload for development
#   --verbose, -v     Enable verbose logging
#   --init-db         Initialize database and exit
```
### API Endpoints

Once running, access the interactive API documentation at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

#### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API information |
| GET | `/api/presets` | List available port presets |
| POST | `/api/validate` | Validate target hosts without scanning |
| GET | `/api/scans` | List all scan jobs |
| POST | `/api/scans` | Create and start a new scan |
| GET | `/api/scans/{scan_id}` | Get scan job details |
| DELETE | `/api/scans/{scan_id}` | Delete a scan job |
| GET | `/api/scans/{scan_id}/results` | Get scan results |
| POST | `/api/scans/{scan_id}/cancel` | Cancel running scan |
| WS | `/ws/{scan_id}` | WebSocket for real-time updates |

### Example API Usage

**Create a new scan:**
```bash
curl -X POST "http://localhost:8000/api/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1", "scanme.nmap.org"],
    "port_preset": "common",
    "name": "Network Audit Q1",
    "description": "Quarterly security scan",
    "timeout": 2.0,
    "max_concurrent": 50
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Network Audit Q1",
  "status": "pending",
  "targets": ["192.168.1.1", "scanme.nmap.org"],
  "port_preset": "common",
  "total_hosts": 2,
  "total_ports": 32,
  "open_ports_found": 0,
  "created_at": "2024-01-15T10:30:00"
}
```

**Get scan results:**
```bash
curl "http://localhost:8000/api/scans/550e8400-e29b-41d4-a716-446655440000/results?only_open=true"
```

**WebSocket connection for real-time updates:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/550e8400-e29b-41d4-a716-446655440000');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Scan update:', data);
};
```

### Available Port Presets

| Preset | Ports | Use Case |
|--------|-------|----------|
| `quick` | 1-1024 | Fast initial reconnaissance |
| `common` | 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443 | Most common services |
| `extended` | 1-1024 + database/mail ports | Thorough service discovery |
| `full` | 1-65535 | Complete port coverage |
| `web` | 80, 443, 8080, 8443, 3000, 4200, 5000, 8000, 9000 | Web services only |
| `database` | 1433, 1521, 3306, 5432, 27017, 6379, 9200, 9300 | Database services |
| `mail` | 25, 110, 143, 465, 587, 993, 995 | Mail services |

## 🔒 Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

- Always configure `ALLOWED_NETWORKS` in production to restrict scanning scope
- The API includes hostname resolution and CIDR validation
- Rate limiting is available to prevent network flooding
- All scan jobs are logged to the database for audit trails



**Disclaimer**: This tool is intended for authorized security testing and network administration only. Users are responsible for complying with all applicable laws and regulations. Always obtain proper authorization before scanning networks you do not own.
