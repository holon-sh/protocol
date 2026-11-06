// Package profile states what Holon requires of an identity backend, so a backend is built against the
// standards and not against one provider. It has no code. Package conformance tests a live issuer and adapter
// against these rules.
//
//   - Clients. The browser client is confidential and uses the authorization code grant with PKCE S256,
//     [RFC 6749 §4.1] and [RFC 7636 §4.2]. The cli client is public and uses the device authorization grant,
//     [RFC 8628 §3], with offline_access. One person has one sub at both, the public subject type of
//     [OpenID Connect Core 1.0 §8]. A service account uses client credentials, [RFC 6749 §4.4]; the conformance suite
//     is given one. The issuer refuses the password grant to every client, [RFC 9700 §2.4].
//   - Resource. Every authorization, device and token request carries exactly one resource parameter,
//     [RFC 8707 §2]. The access token's aud is that resource and nothing else, [RFC 8707 §2.2]. A token requested
//     for no resource or an unregistered one is inactive or refused with invalid_target, and a refresh naming a
//     different resource is refused with invalid_target, [RFC 8707 §2].
//   - Scope. A request names no resource scope. The resource decides, the default [RFC 6749 §3.3] allows: the issued
//     scope is what the resource registered and the subject holds through a permission set when the token is issued,
//     refreshes included. The token response carries it in the scope parameter, [RFC 6749 §5.1]. At introspection the
//     scope is what the subject holds at that moment, more or less than was issued, and the token stays active.
//     Protocol scopes (openid, profile, email, offline_access) pass through unchanged.
//   - Registration. A token minted before its resource was registered, or after it was deleted and registered
//     again, is inactive.
//   - Passwords. A password written through SCIM, [RFC 7643 §4.1.1], is temporary: the issuer requires a new one
//     at the first sign-in, refuses the same value, and collects the person's name there too if the account has
//     none.
//   - Invitations. An invitation link is valid for its Lifetime and no longer, and is refused once the person
//     has finished setting up.
//   - Introspection. The adapter answers [RFC 7662 §2.2] with active, token_type Bearer, iss, sub, client_id, exp,
//     aud as one string, and scope in the format of [RFC 6749 §3.3] unless it is empty, and authenticates the caller by
//     the shared bearer, which [RFC 7662 §2.1] allows. A token of any other type is not active.
//   - Personal tokens. POST /v1/token-clients creates a client for one token. A person who signs in through it with
//     the authorization code grant, PKCE S256 and one resource receives an access token whose sub is the same as at
//     the browser client, whose client_id is the created client and whose exp is 30 days away. It survives that
//     person's browser sign-out.
//   - Revocation. The issuer advertises revocation_endpoint, [RFC 8414 §2], and accepts [RFC 7009 §2.1] from the
//     cli client with its client_id and no credential. A revoked refresh token is refused with invalid_grant on
//     its next use, [RFC 6749 §5.2].
//   - Sign-out. A request to end_session_endpoint with id_token_hint, including an expired one, ends the provider
//     session without asking the user, [OpenID Connect RP-Initiated Logout 1.0 §2]: the session's access token
//     goes inactive and its refresh token is refused with invalid_grant, except that a personal token minted in the
//     session stays active. With no hint the provider asks the user
//     to confirm before it ends a browser's session. The browser client has {origin}/?signedOut=1 registered as a
//     post-logout redirect URI for the base, admin and dev origins, and the provider redirects there after
//     logout, [OpenID Connect RP-Initiated Logout 1.0 §3].
//   - Discovery. {issuer}/.well-known/openid-configuration serves [OpenID Connect Discovery 1.0 §4]. Holon reads
//     the authorization, device, token, revocation and end-session endpoints from it and nowhere else.
//
// [RFC 6749 §3.3]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
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
// [RFC 9700 §2.4]: https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4
// [OpenID Connect Core 1.0 §8]: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
// [OpenID Connect Discovery 1.0 §4]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
// [OpenID Connect RP-Initiated Logout 1.0 §2]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// [OpenID Connect RP-Initiated Logout 1.0 §3]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
package profile
