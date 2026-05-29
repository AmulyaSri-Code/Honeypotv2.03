# HoneyPot v3 Mind Map

```mermaid
mindmap
  root((HoneyPot v3))
    Mission
      Deception-first defense lab
      Capture suspicious activity safely
      Turn events into analyst-ready intelligence
      Keep deployment simple and local by default
    Core Runtime
      Flask application
        API routes
        Dashboard serving
        Health and metadata endpoints
      Honeypot engine
        Request capture
        Attack pattern logging
        Threat event generation
      Environment loader
        Safe configuration defaults
        Optional .env support
        Secret values kept out of status responses
    Dashboard
      HoneyPot v3 Defense Console
      Browser-based UI
      Login modal
      Alert channel status
        Slack
        Telegram
        Discord
        n8n
      Threat and health visibility
      JavaScript syntax verified
    Security Posture
      Loopback-first local bindings
      Token-based API auth
      No exposed webhook/token values
      Runtime artifacts excluded from commits
      Docker n8n bound to 127.0.0.1
      Deployment checklist in README
    Alerting and Automation
      Provider status booleans
      Slack alerts
      Telegram alerts
      Discord alerts
      n8n webhook provider
        N8N_WEBHOOK_URL
        Structured JSON payload
        Source and summary fields
        Original event included
      Optional automation workflows
        Critical alert router
        IP enrichment candidate
        Ticket creation candidate
        Daily report candidate
    n8n Integration
      Optional, not core dependency
      Docker Compose automation profile
        n8nio/n8n image
        Persistent n8n_data volume
        Local UI on port 5678
      Sample workflow
        n8n-workflows/honeypot-v3-critical-alert.json
        Webhook path honeypot-v3-alert
        Critical severity filter
        Normalization step
        Placeholder analyst notification
      Real testing requires user's webhook URL in .env
    Machine Learning
      Attack classifier module
      model.pkl
      vectorizer.pkl
      Threat summary support
      Tests for classifier behavior
    Configuration
      .env.example
        API credentials placeholders
        Alert provider placeholders
        N8N_WEBHOOK_URL
        N8N_ENCRYPTION_KEY placeholder
      setup.py
        Interactive setup
        Non-interactive CLI flags
        n8n webhook option
      docker-compose.yml
        Honeypot service
        Optional env_file
        Automation profile
    Testing and Verification
      Pytest suite
        API tests
        Alert tests
        Dashboard UI tests
        Honeypot safety tests
        ML classifier tests
        Setup config tests
        Threat summary tests
      Compile checks
      JSON validation
      Dashboard JS check
      Docker Compose config check
      API smoke check
      Browser smoke check
    Repository Hygiene
      Source and docs committed
      Runtime files kept local
        honeypot.db
        honeypot.log
        reports/
        __pycache__/
        .pytest_cache/
      Latest pushed branch
        main to origin/main
      Key commits
        HoneyPot v3 baseline
        n8n provider and dashboard support
        n8n docs and workflow setup
    Website Backend Integration
      Private sidecar beside real website backend
      Reverse proxy suspicious trap paths only
      Nginx and Caddy examples
      Node.js Express proxy example
      Python backend proxy pattern
      Docker Compose sidecar pattern
      Keep dashboard private or behind VPN/SSO
      Pass X-Real-IP and X-Forwarded-For headers
    Operator Workflow
      Quick start from README
      Configure .env locally
      Run honeypot
      Monitor dashboard
      Enable alert providers as needed
      Optionally start n8n automation
      Import sample workflow
      Activate workflow
      Test high-severity alert delivery
    Future Enhancements
      More n8n workflow templates
      GeoIP or ASN enrichment
      AbuseIPDB or threat intel lookup
      Case management integration
      Scheduled daily/weekly reports
      More dashboard analytics
      Hardened production deployment guide
```

## Quick mental model

HoneyPot v3 is organized around one main loop:

1. Attract and capture suspicious traffic.
2. Normalize it into structured threat events.
3. Display operational status in the dashboard.
4. Send high-value alerts through optional providers.
5. Use n8n only when automation is desired, keeping the core honeypot lightweight.

## Best next branches from this map

- Automation branch: add more n8n workflows for enrichment, ticketing, and daily reporting.
- Security branch: harden production deployment docs and secret handling checks.
- Intelligence branch: improve ML classification and attacker behavior summaries.
- UX branch: add richer dashboard charts and incident drill-downs.
