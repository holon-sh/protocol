# spec

The documents in this directory describe Holon's contracts for readers that are not Go. Everything here is generated
from the Go module and committed. Do not edit these files by hand: change the Go source, then run

```sh
go generate ./...
```

and commit the result.

## control

The control contract between a client and the platform's control plane, the MCP tools at `/mcp` on the dev and admin
planes. It is written from the rules in `internal/model`, which the `protocol` package also reads its patterns, bounds
and reserved values from.

- `control/schema.json` holds the definitions: the app as a client declares it (`App`) and as the server stores and
  returns it (`ObservedApp`), each tool's request and result, the installation's `Info`, and the error envelope
  (`ErrorResponse`).
- `control/operations.json` lists each tool with its Go constant, the planes that serve it, its scope class, and the
  definitions of its request and result. On the dev plane the read and write scopes are `system:dev:read` and
  `system:dev:write`, and on the admin plane `system:prod:read` and `system:prod:write`.
- `control/inputs/<tool>.json` is each tool's input schema as a self-contained document, with the request's members at
  its root.

Requests are closed: a member the schema does not list is rejected. A result lists what this version writes, and a
reader tolerates a member or value it does not know.

## artifact

- `artifact/schema.json` is the build record stored beside an app's built image. Its `$defs` also hold the release an
  image's lifecycle hooks make up: each hook is a file `hooks/[<version>/]<event>[.js|.ts|.py]` under the image's
  working directory.

## runtime

The runtime contract between the platform and an app's process.

- `runtime/schema.json` is a JSON Schema 2020-12 document for the payload of the compact JWS in `X-Holon-Context`.
  Its `$defs` also hold the forms of the `X-Holon-Context` and `X-Holon-Caller` header values. It is written from the
  rules in `runtimecontract/internal/model`.
- `runtime/names.json` lists each header, variable, path, media type, and fixed value of the runtime contract, with
  the Go constant that holds it.

`runtimecontract.Admit` is how an app's SDK decides a request from these: the route, whether to reject it with 400,
the principal and caller it carries, and the headers that app code must not see.

## Schema profile

The schemas use only local `$defs`, and only regular expression features that RE2 and ECMA-262 read alike. A length
bound counts bytes in the contract and characters in JSON Schema, so a schema admits some longer non-ASCII text that the
parse rejects. The rule model has no boolean kind, so a boolean member is a `Boolean`, which the schema admits as any
value and the parse checks. A schema states the rules of one value and of one object's members. A rule that it cannot
state, or that spans an app's members or a session's apps, is the parse's.
