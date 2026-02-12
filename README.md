# Traefik Modsec Plugin

This is a fork of a fork of a fork of the original
[`traefik-modsecurity-plugin`][traefik-modsecurity-plugin].

[traefik-modsecurity-plugin]: https://github.com/madebymode/traefik-modsecurity-plugin

Traefik plugin to proxy requests to a Modsecurity service, usually a container
running [`docker.io/owasp/modsecurity-crs:nginx`][container-repo].

[container-repo]: https://github.com/coreruleset/modsecurity-crs-docker/

## Demo

Demo with WAF intercepting relative access in query param.

![Demo](./img/waf.gif)

## Usage (compose.yaml)

See [compose.yaml](compose.yaml)

```sh
# start containers
$ podman compose up -d

# test known good url (status code should be 200)
$ curl -v http://127.0.0.1:8080/website

# test known bad url (status code should be 403)
$ curl -v http://127.0.0.1:8080/website?test=../etc

# test bypass url (status code should be 200)
$ curl -v http://127.0.0.1:8080/bypass?test=../etc

# develop/test locally
$ podman compose -f compose.local.yaml -d
```

## Configuration

| Key                     | Required? | Default              | What it does                                                                                                                                          |
| ----------------------- | --------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `serviceUrl`            | no        | `http://modsec:8080` | Service URL of the service container (e.g. `http://modsecurity-crs.modsecurity-crs.svc:8080`).                                                        |
| `timeout`               | no        | `2s`                 | _Whole_ request budget (dial + request + response).                                                                                                   |
| `dialTimeout`           | no        | `30s`                | Time limit for establishing a connection to the `serviceUrl`. If the socket isn’t connected within this window, the plugin aborts with `Bad Gateway`. |
| `idleTimeout`           | no        | `90s`                | How long an idle keep-alive socket can stay open before it is closed. Lowering this prevents a slow leak of goroutines under spiky traffic.           |
| `maxConns`              | no        | `4`                  | Max number of idle connections to `serviceUrl`. Set higher for very high-RPS environments, lower to conserve file descriptors / conn-track slots.     |
| `jail.enabled`          | no        | `false`              | Enables "jail" for repeat offenders.                                                                                                                  |
| `jail.badRequestLimit`  | no        | `25`                 | Number of `403` replies that trips the jail.                                                                                                          |
| `jail.badRequestPeriod` | no        | `600s`               | Sliding-window length for the above threshold.                                                                                                        |
| `jail.duration`         | no        | `1h`                 | How long a remote ip stays in jail.                                                                                                                   |
| `backoff`               | no        | `0s`                 | The backoff period when new connections to `serviceUrl` fail.                                                                                         |
