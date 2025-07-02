# Running CyberSentinel AI - ATITA

## Quick Start

### 1. Setup Environment

```bash
# Clone the repository
git clone <repository-url>
cd CyberSentinel-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp env.example .env
# Edit .env with your configuration
```

### 2. Run the System

```bash
# Start the application
python main.py
```

The system will start on `http://localhost:8000`

### 3. Test the API

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Submit a Threat
```bash
curl -X POST "http://localhost:8000/api/v1/threats" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious Ransomware Email",
    "description": "User received email with ransomware attachment",
    "source": "email",
    "source_details": {
      "sender": "attacker@malicious.com",
      "subject": "URGENT: Account suspended",
      "attachments": ["invoice.exe"]
    }
  }'
```

#### Get Threat Status
```bash
# Replace {threat_id} with the ID from the previous response
curl http://localhost:8000/api/v1/threats/{threat_id}
```

#### Check Agent Status
```bash
curl http://localhost:8000/api/v1/agents/status
```

#### Get Analytics
```bash
curl http://localhost:8000/api/v1/analytics
```

### 4. Run with Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f cybersentinel
```

## API Documentation

Once the system is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Complete Workflow Example

The system processes threats through this pipeline:

1. **Intake Agent**: Receives threat data from multiple sources
2. **Triage Agent**: Classifies and prioritizes threats using AI/ML
3. **Enrichment Agent**: Gathers external threat intelligence
4. **Policy Agent**: Applies organizational policies and decisions
5. **Escalation Agent**: Decides if human intervention is needed
6. **Memory Agent**: Stores case history and incorporates feedback

### Example Threat Processing

When you submit a threat with "ransomware" in the title/description:

1. **Intake**: Threat is received and standardized
2. **Triage**: Classified as "ransomware" with "critical" severity
3. **Enrichment**: IOCs are extracted and enriched with external data
4. **Policy**: Auto-block actions are applied (high confidence)
5. **Escalation**: Likely escalated due to critical severity
6. **Memory**: Case is stored for learning

## Testing

### Run Tests
```bash
pytest tests/
```

### Run Specific Test
```bash
pytest tests/test_end_to_end.py -v
```

### Run Demo Script
```bash
python scripts/demo.py
```

## Configuration

Key configuration options in `.env`:

- `DEBUG`: Enable debug mode
- `DATABASE_URL`: PostgreSQL connection string
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for enrichment
- `ALIENVAULT_API_KEY`: AlienVault OTX API key
- `THREAT_CLASSIFICATION_THRESHOLD`: ML confidence threshold
- `AUTO_ESCALATION_THRESHOLD`: Escalation confidence threshold

## Monitoring

- Health check: `GET /health`
- Agent status: `GET /api/v1/agents/status`
- System analytics: `GET /api/v1/analytics`

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Check `DATABASE_URL` in `.env`
   - Ensure PostgreSQL is running
   - System will fallback to SQLite for development

2. **Agent Initialization Error**
   - Check logs for specific error messages
   - Verify all required environment variables

3. **API Timeout**
   - Increase timeout values in `.env`
   - Check agent processing times

### Logs

The system uses structured logging. Check logs for:
- Agent initialization and status
- Threat processing workflow
- Error messages and stack traces
- Performance metrics

## Production Deployment

For production deployment:

1. Use Docker Compose with proper volumes
2. Set up PostgreSQL and Redis
3. Configure external threat intelligence APIs
4. Set up monitoring and alerting
5. Configure backup and disaster recovery
6. Implement proper security measures (RBAC, mTLS, etc.)

## Extending the System

The system is designed to be extensible:

- Add new threat intelligence sources in `EnrichmentAgent`
- Implement new policies in `PolicyAgent`
- Add new intake sources in `IntakeAgent`
- Extend ML models in `TriageAgent`
- Add new escalation workflows in `EscalationAgent` 