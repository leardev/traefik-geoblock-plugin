# traefik-geoblock-plugin

A [Traefik](https://traefik.io/) middleware plugin that blocks or allows requests based on geographic location, using the [IPInfo Lite](https://ipinfo.io/products/free-ip-database) database with automatic updates.

## Features

- **Allowlist or blocklist** mode via country codes (ISO 3166-1 alpha-2)
- **Automatic database updates** on a configurable interval
- **Private/reserved IP handling** — optionally pass through RFC1918 and loopback addresses
- **Configurable fallback** when an IP is not found in the database
- **Custom HTTP status code** for blocked requests (default: `403`)
- **Optional request logging**

## Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    geoblock:
      moduleName: github.com/leardev/traefik-geoblock-plugin
      version: v0.1.0
```

For local development, use `localPlugins` instead (see [test/docker-compose.yml](test/docker-compose.yml)).

## Configuration

### Database backends

The plugin supports two database backends. Set **either** `databasePath` (CSV, default) **or** `databaseMMDBPath` (MMDB) — not both.

| Backend | Config key | Default path | Memory usage |
|---------|-----------|--------------|-------------|
| CSV `.csv.gz` | `databasePath` | `/tmp/ipinfo_lite.csv.gz` | ~150 MB heap per replica |
| MMDB `.mmdb` | `databaseMMDBPath` | *(none)* | ~50 MB heap per replica |

The MMDB backend is recommended for production and multi-replica deployments.

### All options

| Option               | Type       | Default                     | Description                                                       |
|----------------------|------------|-----------------------------|-------------------------------------------------------------------|
| `allowedCountries`   | `[]string` | —                           | Allowlist of country codes. Mutually exclusive with `blockedCountries`. |
| `blockedCountries`   | `[]string` | —                           | Blocklist of country codes. Mutually exclusive with `allowedCountries`. |
| `token`              | `string`   | **required**                | IPInfo API token for downloading the database.                    |
| `databasePath`       | `string`   | `/tmp/ipinfo_lite.csv.gz`   | Path to cache the gzipped CSV database. Mutually exclusive with `databaseMMDBPath`. |
| `databaseURL`        | `string`   | *(IPInfo CSV URL)*          | Override the CSV download URL (testing only).                     |
| `databaseMMDBPath`   | `string`   | —                           | Path to cache the MMDB database. When set, the MMDB backend is used. Mutually exclusive with `databasePath`. |
| `databaseMMDBURL`    | `string`   | *(IPInfo MMDB URL)*         | Override the MMDB download URL (testing only).                    |
| `updateInterval`     | `int`      | `24`                        | Hours between automatic database refreshes.                       |
| `allowPrivate`       | `bool`     | `true`                      | Pass through requests from private/reserved IP ranges.            |
| `defaultAllow`       | `bool`     | `true`                      | Allow requests when the IP is not found or the DB is not loaded.  |
| `httpStatusCode`     | `int`      | `403`                       | HTTP status code returned for blocked requests.                   |
| `logEnabled`         | `bool`     | `false`                     | Log each allowed/blocked decision.                                |

Exactly one of `allowedCountries` or `blockedCountries` must be set.

## Example dynamic configuration

### MMDB backend (recommended)

```yaml
http:
  middlewares:
    my-geoblock:
      plugin:
        geoblock:
          allowedCountries:
            - DE
            - AT
            - CH
          token: "your-ipinfo-token"
          databaseMMDBPath: "/data/ipinfo_lite.mmdb"
          updateInterval: 24
          allowPrivate: true
          defaultAllow: false
          logEnabled: true
```

### CSV backend (higher RAM usage)

```yaml
http:
  middlewares:
    my-geoblock:
      plugin:
        geoblock:
          allowedCountries:
            - DE
            - AT
            - CH
          token: "your-ipinfo-token"
          databasePath: "/data/ipinfo_lite.csv.gz"
          updateInterval: 24
          allowPrivate: true
          defaultAllow: false
          logEnabled: true
```

## Local testing

> **Note:** The Docker Compose setup in `test/` is for integration testing only, not for production use.

```bash
IPINFO_TOKEN=your-token docker compose -f test/docker-compose.yml up
```

Traefik will be available at `http://localhost:80` and the dashboard at `http://localhost:8080`.

## License

MIT
