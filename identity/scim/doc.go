// Package scim is the part of SCIM 2.0 Holon needs from an identity backend: users, the groups that stand
// for permission sets, and what the backend can do. Resources follow the core schema of [RFC 7643] and
// operations follow [RFC 7644]. Bulk ([RFC 7644 §3.7]), sorting ([RFC 7644 §3.4.2.3]), the /Schemas and
// /ResourceTypes endpoints ([RFC 7644 §4]) and the Enterprise User extension ([RFC 7643 §4.3]) are not
// needed, and Handler answers 501 for the endpoints.
//
// [RFC 7643]: https://www.rfc-editor.org/rfc/rfc7643.html
// [RFC 7644]: https://www.rfc-editor.org/rfc/rfc7644.html
// [RFC 7644 §3.7]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.7
// [RFC 7644 §3.4.2.3]: https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.3
// [RFC 7644 §4]: https://www.rfc-editor.org/rfc/rfc7644.html#section-4
// [RFC 7643 §4.3]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.3
package scim
