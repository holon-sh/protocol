# spec

The documents in this directory describe Holon's contracts for readers that are not Go. Everything here is generated
from the Go module and committed. Do not edit these files by hand: change the Go source, then run

```sh
go generate ./...
```

and commit the result.

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

The schemas use only local `$defs`, and only regular expression features that RE2 and ECMA-262 read alike.
