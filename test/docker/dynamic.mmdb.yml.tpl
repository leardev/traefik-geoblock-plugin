http:
  middlewares:
    my-geoblock:
      plugin:
        geoblock:
          allowedCountries:
            - DE
            - AT
            - CH
          token: "${IPINFO_TOKEN}"
          databaseMMDBPath: "/data/ipinfo_lite.mmdb"
          updateInterval: 24
          allowPrivate: true
          defaultAllow: true
          logEnabled: true

  routers:
    whoami:
      rule: "PathPrefix(`/`)"
      entryPoints:
        - web
      middlewares:
        - my-geoblock
      service: whoami

  services:
    whoami:
      loadBalancer:
        servers:
          - url: "http://whoami:80"
