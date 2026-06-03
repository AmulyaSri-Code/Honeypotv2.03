# HoneyPot v3 Backup, Restore, Upgrade, and Rollback

Back up before upgrades and before changing deployment mode.

## What to back up

- `.env` secrets and deployment settings;
- `honeypot.db` or Docker `honeypot_data` volume;
- logs/reports needed for investigation;
- ML artifacts if generated locally and not rebuilt during deployment.

Do not commit backups to git.

## Docker backup

Create a local backup directory:

```bash
mkdir -p backups
```

Back up data and logs volumes:

```bash
docker run --rm -v honeypotv203_honeypot_data:/data -v "$PWD/backups:/backup" alpine   tar czf /backup/honeypot_data_$(date +%F).tgz -C /data .

docker run --rm -v honeypotv203_honeypot_logs:/logs -v "$PWD/backups:/backup" alpine   tar czf /backup/honeypot_logs_$(date +%F).tgz -C /logs .
```

Back up `.env` separately and store it securely.

## Docker restore

```bash
docker compose down
# Restore archives into the named volumes using a temporary container.
docker compose up -d honeypot
curl -i http://127.0.0.1:5050/api/health
```

## Local backup

If the app is stopped, copy files:

```bash
mkdir -p backups
cp .env backups/env_$(date +%F)
cp honeypot.db backups/honeypot_$(date +%F).db
cp honeypot.log backups/honeypot_$(date +%F).log
```

If SQLite is running, prefer a SQLite backup:

```bash
sqlite3 honeypot.db ".backup 'backups/honeypot_$(date +%F).db'"
```

## Upgrade

```bash
git pull --ff-only
docker compose config >/tmp/honeypot-compose.yml
docker compose up -d --build honeypot
curl -i http://127.0.0.1:5050/api/health
```

Then verify dashboard login, sensor traffic, alerts, and logs.

## Rollback

1. Stop the new version.
2. Restore the previous database/log backup if needed.
3. Check out the previous known-good commit or image.
4. Start HoneyPot again.
5. Verify `/api/health`, dashboard login, sensors, and alerts.
