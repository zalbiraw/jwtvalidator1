# JWT Validator Plugin for Traefik

A Traefik plugin that validates JWTs and forwards claims to HTTP headers and query parameters. Supports mapping, renaming, and forwarding both single and array claim values. Designed for robust integration with downstream services.

## Installation & Enabling

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    jwtvalidator:
      moduleName: github.com/zalbiraw/jwtvalidator
      version: v0.0.2
```

## Dynamic Configuration Example

```yaml
http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - jwtvalidator

  middlewares:
    jwtvalidator:
      plugin:
        signingSecret: mysecret
        forwardHeaders:
          Group: group
          Expires-At: expires_at
        forwardQueryParams:
          group: group
          expires_at: expires_at
        authHeader: Authorization
```

## How It Works

- The plugin extracts the JWT from the configured header (default: `Authorization`).
- It validates the token signature and expiration using the provided secret.
- Claims can be mapped to HTTP headers and/or query parameters by specifying the mapping in `forwardHeaders` and `forwardQueryParams`.
- Supports forwarding array claims as multiple header/query parameter values.
- If a claim is missing, the header or query parameter will not be set.

### Example

Given this configuration:

```yaml
forwardHeaders:
  Group: group
  Expires-At: expires_at
forwardQueryParams:
  group: group
  expires_at: expires_at
```

And a JWT with these claims:

```json
{
  "group": ["engineering", "qa"],
  "expires_at": 1744916399
}
```

The resulting request will have:

- Headers:
  - `Group: engineering`
  - `Group: qa`
  - `Expires-At: 1744916399`
- Query string:
  - `?group=engineering&group=qa&expires_at=1744916399`

## Development & Testing

Run tests with:

```sh
go test -v
```

---

## Traefik Local Plugin Support

You can use this project as a [Traefik Local Plugin](https://doc.traefik.io/traefik/plugins/local-plugins/). This allows you to develop and test the plugin locally, without needing to publish it to an external registry. Reference the plugin's local path in your Traefik configuration for rapid iteration and debugging.


## Terraform-Enabled Module

This repository includes a Terraform module (`main.tf`) that provisions all necessary plugin configuration and source code into a Kubernetes `ConfigMap`. This enables you to manage and deploy the plugin as infrastructure-as-code, integrating seamlessly with your Terraform workflows.

> **Security Tip:** Always use environment variables or secret managers to handle sensitive information. Avoid hardcoding secrets in `.tf` files.

---

For more details, see the source code and test cases.
