# Example Target-Host Profile

This is a versioned example profile. Copy relevant values into a non-versioned
`.env` on the target host and replace placeholders.

## Compose Production Defaults

```env
HMI_PUBLISHED_PORT=8080
MODBUS_PUBLISHED_PORT=1502
OPS_PUBLISHED_PORT=9090
OPS_ENABLED=1
ENABLE_SERVICE_LOGIN=1
```

Docker Compose forces the correct container-internal binds. Do not add
container-internal ports to `.env`.

## Optional Port 80 HMI

```env
HMI_PUBLISHED_PORT=80
```

The container still listens internally on `8080`.

## Exporters

Enable exporters only when real approved targets exist:

```env
WEBHOOK_EXPORTER_ENABLED=1
WEBHOOK_EXPORTER_URL=https://collector.example.net/honeypot-ingest
APPROVED_EGRESS_TARGETS=webhook:collector.example.net:443
APPROVED_EGRESS_CIDRS=<narrow-public-collector-cidr>
PROHIBITED_OT_CIDRS=<all-routed-real-ot-cidrs>
APPROVED_EGRESS_RECIPIENTS=webhook:observer-collector-live
```

Do not keep documentation hostnames in a live deployment.

Open-Meteo requires both fixed targets; automatic GeoIP requires its DB-IP
target. Merge only the paths actually enabled on the host with any exporter
specs already present in `APPROVED_EGRESS_TARGETS`:

```env
APPROVED_EGRESS_TARGETS=weather-open-meteo:api.open-meteo.com:443,weather-open-meteo-archive:archive-api.open-meteo.com:443,geoip-dbip:download.db-ip.com:443
APPROVED_EGRESS_CIDRS=<narrow-public-provider-cidrs>
```

## Operator Roles

Set these in the real deployment when running exposed research:

```env
WATCH_OFFICER_NAME=blue-watch
DUTY_ENGINEER_NAME=ops-duty
```

## Validation

```bash
docker compose pull
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
docker compose up -d
```
