// Package profile states what Holon requires of an identity backend, so a backend is built against the
// standards and not against one provider. It has no code. Package conformance tests a live issuer and adapter
// against these rules.
//
//   - Clients. The browser client is confidential and uses the authorization code grant with PKCE S256,
//     [RFC 6749 §4.1] and [RFC 7636 §4.2]. The cli client is public and uses the device authorization grant,
//     [RFC 8628 §3], with offline_access. A service account uses client credentials, [RFC 6749 §4.4]; the
//     conformance suite is given one.
//   - Resource. Every authorization, device and token request carries exactly one resource parameter,
//     [RFC 8707 §2]. The access token's aud is that resource and nothing else, [RFC 8707 §2.2]. A refresh naming
//     a different resource is refused with invalid_target, [RFC 8707 §2].
//   - Scope. The issued scope is the requested scopes limited to those the resource registered and the subject
//     holds through a permission set. When it differs from the request, the token response carries the scope
//     parameter, [RFC 6749 §5.1]. Protocol scopes (openid, profile, email, offline_access) pass through
//     unchanged.
//   - Registration. A token minted before its resource was registered, or after it was deleted and registered
//     again, is inactive.
//   - Passwords. A password written through SCIM, [RFC 7643 §4.1.1], is temporary: the issuer requires a new one
//     at the first sign-in, refuses the same value, and collects the person's name there too if the account has
//     none.
//   - Invitations. An invitation link is valid for its Lifetime and no longer, and is refused once the person
//     has finished setting up.
//   - Introspection. The adapter answers [RFC 7662 §2.2] with active, iss, sub, client_id, exp, aud and scope,
//     and authenticates the caller by the shared bearer, which [RFC 7662 §2.1] allows.
//   - Revocation. The issuer advertises revocation_endpoint, [RFC 8414 §2], and accepts [RFC 7009 §2.1] from the
//     cli client with its client_id and no credential. A revoked refresh token is refused with invalid_grant on
//     its next use, [RFC 6749 §5.2].
//   - Discovery. {issuer}/.well-known/openid-configuration serves [OpenID Connect Discovery 1.0 §4]. Holon reads
//     the authorization, device, token, revocation and end-session endpoints from it and nowhere else.
//
// [RFC 6749 §4.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
// [RFC 6749 §4.4]: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4
// [RFC 6749 §5.1]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
// [RFC 6749 §5.2]: https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2
// [RFC 7009 §2.1]: https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1
// [RFC 7636 §4.2]: https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
// [RFC 7643 §4.1.1]: https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1.1
// [RFC 7662 §2.1]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1
// [RFC 7662 §2.2]: https://www.rfc-editor.org/rfc/rfc7662.html#section-2.2
// [RFC 8414 §2]: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
// [RFC 8628 §3]: https://www.rfc-editor.org/rfc/rfc8628.html#section-3
// [RFC 8707 §2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2
// [RFC 8707 §2.2]: https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
// [OpenID Connect Discovery 1.0 §4]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
package profile
