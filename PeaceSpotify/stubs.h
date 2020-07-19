#pragma once
#include "pch.h"
#include <stdint.h>

#define CEF_CALLBACK __stdcall

typedef wchar_t char16;

typedef struct _cef_string_utf16_t {
    char16* str;
    size_t length;
    void (*dtor)(char16* str);
} cef_string_utf16_t;

typedef cef_string_utf16_t cef_string_t;

typedef cef_string_utf16_t* cef_string_userfree_utf16_t;

typedef cef_string_userfree_utf16_t cef_string_userfree_t;

typedef enum {
    ///
    /// Clear the referrer header if the header value is HTTPS but the request
    /// destination is HTTP. This is the default behavior.
    ///
    REFERRER_POLICY_CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
    REFERRER_POLICY_DEFAULT =
    REFERRER_POLICY_CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE,

    ///
    /// A slight variant on CLEAR_REFERRER_ON_TRANSITION_FROM_SECURE_TO_INSECURE:
    /// If the request destination is HTTP, an HTTPS referrer will be cleared. If
    /// the request's destination is cross-origin with the referrer (but does not
    /// downgrade), the referrer's granularity will be stripped down to an origin
    /// rather than a full URL. Same-origin requests will send the full referrer.
    ///
    REFERRER_POLICY_REDUCE_REFERRER_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,

    ///
    /// Strip the referrer down to an origin when the origin of the referrer is
    /// different from the destination's origin.
    ///
    REFERRER_POLICY_ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN,

    ///
    /// Never change the referrer.
    ///
    REFERRER_POLICY_NEVER_CLEAR_REFERRER,

    ///
    /// Strip the referrer down to the origin regardless of the redirect location.
    ///
    REFERRER_POLICY_ORIGIN,

    ///
    /// Clear the referrer when the request's referrer is cross-origin with the
    /// request's destination.
    ///
    REFERRER_POLICY_CLEAR_REFERRER_ON_TRANSITION_CROSS_ORIGIN,

    ///
    /// Strip the referrer down to the origin, but clear it entirely if the
    /// referrer value is HTTPS and the destination is HTTP.
    ///
    REFERRER_POLICY_ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,

    ///
    /// Always clear the referrer regardless of the request destination.
    ///
    REFERRER_POLICY_NO_REFERRER,

    /// Always the last value in this enumeration.
    REFERRER_POLICY_LAST_VALUE = REFERRER_POLICY_NO_REFERRER,
} cef_referrer_policy_t;

typedef struct _cef_string_multimap_t* cef_string_multimap_t;

typedef enum {
    ///
    /// Top level page.
    ///
    RT_MAIN_FRAME = 0,

    ///
    /// Frame or iframe.
    ///
    RT_SUB_FRAME,

    ///
    /// CSS stylesheet.
    ///
    RT_STYLESHEET,

    ///
    /// External script.
    ///
    RT_SCRIPT,

    ///
    /// Image (jpg/gif/png/etc).
    ///
    RT_IMAGE,

    ///
    /// Font.
    ///
    RT_FONT_RESOURCE,

    ///
    /// Some other subresource. This is the default type if the actual type is
    /// unknown.
    ///
    RT_SUB_RESOURCE,

    ///
    /// Object (or embed) tag for a plugin, or a resource that a plugin requested.
    ///
    RT_OBJECT,

    ///
    /// Media resource.
    ///
    RT_MEDIA,

    ///
    /// Main resource of a dedicated worker.
    ///
    RT_WORKER,

    ///
    /// Main resource of a shared worker.
    ///
    RT_SHARED_WORKER,

    ///
    /// Explicitly requested prefetch.
    ///
    RT_PREFETCH,

    ///
    /// Favicon.
    ///
    RT_FAVICON,

    ///
    /// XMLHttpRequest.
    ///
    RT_XHR,

    ///
    /// A request for a "<ping>".
    ///
    RT_PING,

    ///
    /// Main resource of a service worker.
    ///
    RT_SERVICE_WORKER,

    ///
    /// A report of Content Security Policy violations.
    ///
    RT_CSP_REPORT,

    ///
    /// A resource that a plugin requested.
    ///
    RT_PLUGIN_RESOURCE,

    ///
    /// A main-frame service worker navigation preload request.
    ///
    RT_NAVIGATION_PRELOAD_MAIN_FRAME = 19,

    ///
    /// A sub-frame service worker navigation preload request.
    ///
    RT_NAVIGATION_PRELOAD_SUB_FRAME,
} cef_resource_type_t;

typedef enum {
    ///
    /// Source is a link click or the JavaScript window.open function. This is
    /// also the default value for requests like sub-resource loads that are not
    /// navigations.
    ///
    TT_LINK = 0,

    ///
    /// Source is some other "explicit" navigation. This is the default value for
    /// navigations where the actual type is unknown. See also
    /// TT_DIRECT_LOAD_FLAG.
    ///
    TT_EXPLICIT = 1,

    ///
    /// User got to this page through a suggestion in the UI (for example, via the
    /// destinations page). Chrome runtime only.
    ///
    TT_AUTO_BOOKMARK = 2,

    ///
    /// Source is a subframe navigation. This is any content that is automatically
    /// loaded in a non-toplevel frame. For example, if a page consists of several
    /// frames containing ads, those ad URLs will have this transition type.
    /// The user may not even realize the content in these pages is a separate
    /// frame, so may not care about the URL.
    ///
    TT_AUTO_SUBFRAME = 3,

    ///
    /// Source is a subframe navigation explicitly requested by the user that will
    /// generate new navigation entries in the back/forward list. These are
    /// probably more important than frames that were automatically loaded in
    /// the background because the user probably cares about the fact that this
    /// link was loaded.
    ///
    TT_MANUAL_SUBFRAME = 4,

    ///
    /// User got to this page by typing in the URL bar and selecting an entry
    /// that did not look like a URL.  For example, a match might have the URL
    /// of a Google search result page, but appear like "Search Google for ...".
    /// These are not quite the same as EXPLICIT navigations because the user
    /// didn't type or see the destination URL. Chrome runtime only.
    /// See also TT_KEYWORD.
    ///
    TT_GENERATED = 5,

    ///
    /// This is a toplevel navigation. This is any content that is automatically
    /// loaded in a toplevel frame.  For example, opening a tab to show the ASH
    /// screen saver, opening the devtools window, opening the NTP after the safe
    /// browsing warning, opening web-based dialog boxes are examples of
    /// AUTO_TOPLEVEL navigations. Chrome runtime only.
    ///
    TT_AUTO_TOPLEVEL = 6,

    ///
    /// Source is a form submission by the user. NOTE: In some situations
    /// submitting a form does not result in this transition type. This can happen
    /// if the form uses a script to submit the contents.
    ///
    TT_FORM_SUBMIT = 7,

    ///
    /// Source is a "reload" of the page via the Reload function or by re-visiting
    /// the same URL. NOTE: This is distinct from the concept of whether a
    /// particular load uses "reload semantics" (i.e. bypasses cached data).
    ///
    TT_RELOAD = 8,

    ///
    /// The url was generated from a replaceable keyword other than the default
    /// search provider. If the user types a keyword (which also applies to
    /// tab-to-search) in the omnibox this qualifier is applied to the transition
    /// type of the generated url. TemplateURLModel then may generate an
    /// additional visit with a transition type of TT_KEYWORD_GENERATED against
    /// the url 'http://' + keyword. For example, if you do a tab-to-search
    /// against wikipedia the generated url has a transition qualifer of
    /// TT_KEYWORD, and TemplateURLModel generates a visit for 'wikipedia.org'
    /// with a transition type of TT_KEYWORD_GENERATED. Chrome runtime only.
    ///
    TT_KEYWORD = 9,

    ///
    /// Corresponds to a visit generated for a keyword. See description of
    /// TT_KEYWORD for more details. Chrome runtime only.
    ///
    TT_KEYWORD_GENERATED = 10,

    ///
    /// General mask defining the bits used for the source values.
    ///
    TT_SOURCE_MASK = 0xFF,

    /// Qualifiers.
    /// Any of the core values above can be augmented by one or more qualifiers.
    /// These qualifiers further define the transition.

    ///
    /// Attempted to visit a URL but was blocked.
    ///
    TT_BLOCKED_FLAG = 0x00800000,

    ///
    /// Used the Forward or Back function to navigate among browsing history.
    /// Will be ORed to the transition type for the original load.
    ///
    TT_FORWARD_BACK_FLAG = 0x01000000,

    ///
    /// Loaded a URL directly via CreateBrowser, LoadURL or LoadRequest.
    ///
    TT_DIRECT_LOAD_FLAG = 0x02000000,

    ///
    /// User is navigating to the home page. Chrome runtime only.
    ///
    TT_HOME_PAGE_FLAG = 0x04000000,

    ///
    /// The transition originated from an external application; the exact
    /// definition of this is embedder dependent. Chrome runtime and
    /// extension system only.
    ///
    TT_FROM_API_FLAG = 0x08000000,

    ///
    /// The beginning of a navigation chain.
    ///
    TT_CHAIN_START_FLAG = 0x10000000,

    ///
    /// The last transition in a redirect chain.
    ///
    TT_CHAIN_END_FLAG = 0x20000000,

    ///
    /// Redirects caused by JavaScript or a meta refresh tag on the page.
    ///
    TT_CLIENT_REDIRECT_FLAG = 0x40000000,

    ///
    /// Redirects sent from the server by HTTP headers.
    ///
    TT_SERVER_REDIRECT_FLAG = 0x80000000,

    ///
    /// Used to test whether a transition involves a redirect.
    ///
    TT_IS_REDIRECT_MASK = 0xC0000000,

    ///
    /// General mask defining the bits used for the qualifiers.
    ///
    TT_QUALIFIER_MASK = 0xFFFFFF00,
} cef_transition_type_t;

///
/// Flags that represent CefURLRequest status.
///
typedef enum {
    ///
    /// Unknown status.
    ///
    UR_UNKNOWN = 0,

    ///
    /// Request succeeded.
    ///
    UR_SUCCESS,

    ///
    /// An IO request is pending, and the caller will be informed when it is
    /// completed.
    ///
    UR_IO_PENDING,

    ///
    /// Request was canceled programatically.
    ///
    UR_CANCELED,

    ///
    /// Request failed for some reason.
    ///
    UR_FAILED,
} cef_urlrequest_status_t;

typedef enum {
    // No error.
    ERR_NONE = 0,
#define NET_ERROR(label, value) ERR_##label = value,
    // Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate enum values. The following line silences a
// presubmit and Tricium warning that would otherwise be triggered by this:
// no-include-guard-because-multiply-included
// NOLINT(build/header_guard)

// This file contains the list of network errors.

//
// Ranges:
//     0- 99 System related errors
//   100-199 Connection related errors
//   200-299 Certificate errors
//   300-399 HTTP errors
//   400-499 Cache errors
//   500-599 ?
//   600-699 FTP errors
//   700-799 Certificate manager errors
//   800-899 DNS resolver errors

// An asynchronous IO operation is not yet complete.  This usually does not
// indicate a fatal error.  Typically this error will be generated as a
// notification to wait for some external notification that the IO operation
// finally completed.
NET_ERROR(IO_PENDING, -1)

// A generic failure occurred.
NET_ERROR(FAILED, -2)

// An operation was aborted (due to user action).
NET_ERROR(ABORTED, -3)

// An argument to the function is incorrect.
NET_ERROR(INVALID_ARGUMENT, -4)

// The handle or file descriptor is invalid.
NET_ERROR(INVALID_HANDLE, -5)

// The file or directory cannot be found.
NET_ERROR(FILE_NOT_FOUND, -6)

// An operation timed out.
NET_ERROR(TIMED_OUT, -7)

// The file is too large.
NET_ERROR(FILE_TOO_BIG, -8)

// An unexpected error.  This may be caused by a programming mistake or an
// invalid assumption.
NET_ERROR(UNEXPECTED, -9)

// Permission to access a resource, other than the network, was denied.
NET_ERROR(ACCESS_DENIED, -10)

// The operation failed because of unimplemented functionality.
NET_ERROR(NOT_IMPLEMENTED, -11)

// There were not enough resources to complete the operation.
NET_ERROR(INSUFFICIENT_RESOURCES, -12)

// Memory allocation failed.
NET_ERROR(OUT_OF_MEMORY, -13)

// The file upload failed because the file's modification time was different
// from the expectation.
NET_ERROR(UPLOAD_FILE_CHANGED, -14)

// The socket is not connected.
NET_ERROR(SOCKET_NOT_CONNECTED, -15)

// The file already exists.
NET_ERROR(FILE_EXISTS, -16)

// The path or file name is too long.
NET_ERROR(FILE_PATH_TOO_LONG, -17)

// Not enough room left on the disk.
NET_ERROR(FILE_NO_SPACE, -18)

// The file has a virus.
NET_ERROR(FILE_VIRUS_INFECTED, -19)

// The client chose to block the request.
NET_ERROR(BLOCKED_BY_CLIENT, -20)

// The network changed.
NET_ERROR(NETWORK_CHANGED, -21)

// The request was blocked by the URL block list configured by the domain
// administrator.
NET_ERROR(BLOCKED_BY_ADMINISTRATOR, -22)

// The socket is already connected.
NET_ERROR(SOCKET_IS_CONNECTED, -23)

// Error -24 was removed (BLOCKED_ENROLLMENT_CHECK_PENDING)

// The upload failed because the upload stream needed to be re-read, due to a
// retry or a redirect, but the upload stream doesn't support that operation.
NET_ERROR(UPLOAD_STREAM_REWIND_NOT_SUPPORTED, -25)

// The request failed because the URLRequestContext is shutting down, or has
// been shut down.
NET_ERROR(CONTEXT_SHUT_DOWN, -26)

// The request failed because the response was delivered along with requirements
// which are not met ('X-Frame-Options' and 'Content-Security-Policy' ancestor
// checks and 'Cross-Origin-Resource-Policy' for instance).
NET_ERROR(BLOCKED_BY_RESPONSE, -27)

// Error -28 was removed (BLOCKED_BY_XSS_AUDITOR).

// The request was blocked by system policy disallowing some or all cleartext
// requests. Used for NetworkSecurityPolicy on Android.
NET_ERROR(CLEARTEXT_NOT_PERMITTED, -29)

// The request was blocked by a Content Security Policy
NET_ERROR(BLOCKED_BY_CSP, -30)

// The request was blocked because of no H/2 or QUIC session.
NET_ERROR(H2_OR_QUIC_REQUIRED, -31)

// The request was blocked by CORB or ORB.
NET_ERROR(BLOCKED_BY_ORB, -32)

// A connection was closed (corresponding to a TCP FIN).
NET_ERROR(CONNECTION_CLOSED, -100)

// A connection was reset (corresponding to a TCP RST).
NET_ERROR(CONNECTION_RESET, -101)

// A connection attempt was refused.
NET_ERROR(CONNECTION_REFUSED, -102)

// A connection timed out as a result of not receiving an ACK for data sent.
// This can include a FIN packet that did not get ACK'd.
NET_ERROR(CONNECTION_ABORTED, -103)

// A connection attempt failed.
NET_ERROR(CONNECTION_FAILED, -104)

// The host name could not be resolved.
NET_ERROR(NAME_NOT_RESOLVED, -105)

// The Internet connection has been lost.
NET_ERROR(INTERNET_DISCONNECTED, -106)

// An SSL protocol error occurred.
NET_ERROR(SSL_PROTOCOL_ERROR, -107)

// The IP address or port number is invalid (e.g., cannot connect to the IP
// address 0 or the port 0).
NET_ERROR(ADDRESS_INVALID, -108)

// The IP address is unreachable.  This usually means that there is no route to
// the specified host or network.
NET_ERROR(ADDRESS_UNREACHABLE, -109)

// The server requested a client certificate for SSL client authentication.
NET_ERROR(SSL_CLIENT_AUTH_CERT_NEEDED, -110)

// A tunnel connection through the proxy could not be established.
NET_ERROR(TUNNEL_CONNECTION_FAILED, -111)

// No SSL protocol versions are enabled.
NET_ERROR(NO_SSL_VERSIONS_ENABLED, -112)

// The client and server don't support a common SSL protocol version or
// cipher suite.
NET_ERROR(SSL_VERSION_OR_CIPHER_MISMATCH, -113)

// The server requested a renegotiation (rehandshake).
NET_ERROR(SSL_RENEGOTIATION_REQUESTED, -114)

// The proxy requested authentication (for tunnel establishment) with an
// unsupported method.
NET_ERROR(PROXY_AUTH_UNSUPPORTED, -115)

// Error -116 was removed (CERT_ERROR_IN_SSL_RENEGOTIATION)

// The SSL handshake failed because of a bad or missing client certificate.
NET_ERROR(BAD_SSL_CLIENT_AUTH_CERT, -117)

// A connection attempt timed out.
NET_ERROR(CONNECTION_TIMED_OUT, -118)

// There are too many pending DNS resolves, so a request in the queue was
// aborted.
NET_ERROR(HOST_RESOLVER_QUEUE_TOO_LARGE, -119)

// Failed establishing a connection to the SOCKS proxy server for a target host.
NET_ERROR(SOCKS_CONNECTION_FAILED, -120)

// The SOCKS proxy server failed establishing connection to the target host
// because that host is unreachable.
NET_ERROR(SOCKS_CONNECTION_HOST_UNREACHABLE, -121)

// The request to negotiate an alternate protocol failed.
NET_ERROR(ALPN_NEGOTIATION_FAILED, -122)

// The peer sent an SSL no_renegotiation alert message.
NET_ERROR(SSL_NO_RENEGOTIATION, -123)

// Winsock sometimes reports more data written than passed.  This is probably
// due to a broken LSP.
NET_ERROR(WINSOCK_UNEXPECTED_WRITTEN_BYTES, -124)

// An SSL peer sent us a fatal decompression_failure alert. This typically
// occurs when a peer selects DEFLATE compression in the mistaken belief that
// it supports it.
NET_ERROR(SSL_DECOMPRESSION_FAILURE_ALERT, -125)

// An SSL peer sent us a fatal bad_record_mac alert. This has been observed
// from servers with buggy DEFLATE support.
NET_ERROR(SSL_BAD_RECORD_MAC_ALERT, -126)

// The proxy requested authentication (for tunnel establishment).
NET_ERROR(PROXY_AUTH_REQUESTED, -127)

// Error -129 was removed (SSL_WEAK_SERVER_EPHEMERAL_DH_KEY).

// Could not create a connection to the proxy server. An error occurred
// either in resolving its name, or in connecting a socket to it.
// Note that this does NOT include failures during the actual "CONNECT" method
// of an HTTP proxy.
NET_ERROR(PROXY_CONNECTION_FAILED, -130)

// A mandatory proxy configuration could not be used. Currently this means
// that a mandatory PAC script could not be fetched, parsed or executed.
NET_ERROR(MANDATORY_PROXY_CONFIGURATION_FAILED, -131)

// -132 was formerly ERR_ESET_ANTI_VIRUS_SSL_INTERCEPTION

// We've hit the max socket limit for the socket pool while preconnecting.  We
// don't bother trying to preconnect more sockets.
NET_ERROR(PRECONNECT_MAX_SOCKET_LIMIT, -133)

// The permission to use the SSL client certificate's private key was denied.
NET_ERROR(SSL_CLIENT_AUTH_PRIVATE_KEY_ACCESS_DENIED, -134)

// The SSL client certificate has no private key.
NET_ERROR(SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY, -135)

// The certificate presented by the HTTPS Proxy was invalid.
NET_ERROR(PROXY_CERTIFICATE_INVALID, -136)

// An error occurred when trying to do a name resolution (DNS).
NET_ERROR(NAME_RESOLUTION_FAILED, -137)

// Permission to access the network was denied. This is used to distinguish
// errors that were most likely caused by a firewall from other access denied
// errors. See also ERR_ACCESS_DENIED.
NET_ERROR(NETWORK_ACCESS_DENIED, -138)

// The request throttler module cancelled this request to avoid DDOS.
NET_ERROR(TEMPORARILY_THROTTLED, -139)

// A request to create an SSL tunnel connection through the HTTPS proxy
// received a 302 (temporary redirect) response.  The response body might
// include a description of why the request failed.
//
// TODO(https://crbug.com/928551): This is deprecated and should not be used by
// new code.
NET_ERROR(HTTPS_PROXY_TUNNEL_RESPONSE_REDIRECT, -140)

// We were unable to sign the CertificateVerify data of an SSL client auth
// handshake with the client certificate's private key.
//
// Possible causes for this include the user implicitly or explicitly
// denying access to the private key, the private key may not be valid for
// signing, the key may be relying on a cached handle which is no longer
// valid, or the CSP won't allow arbitrary data to be signed.
NET_ERROR(SSL_CLIENT_AUTH_SIGNATURE_FAILED, -141)

// The message was too large for the transport.  (for example a UDP message
// which exceeds size threshold).
NET_ERROR(MSG_TOO_BIG, -142)

// Error -143 was removed (SPDY_SESSION_ALREADY_EXISTS)

// Error -144 was removed (LIMIT_VIOLATION).

// Websocket protocol error. Indicates that we are terminating the connection
// due to a malformed frame or other protocol violation.
NET_ERROR(WS_PROTOCOL_ERROR, -145)

// Error -146 was removed (PROTOCOL_SWITCHED)

// Returned when attempting to bind an address that is already in use.
NET_ERROR(ADDRESS_IN_USE, -147)

// An operation failed because the SSL handshake has not completed.
NET_ERROR(SSL_HANDSHAKE_NOT_COMPLETED, -148)

// SSL peer's public key is invalid.
NET_ERROR(SSL_BAD_PEER_PUBLIC_KEY, -149)

// The certificate didn't match the built-in public key pins for the host name.
// The pins are set in net/http/transport_security_state.cc and require that
// one of a set of public keys exist on the path from the leaf to the root.
NET_ERROR(SSL_PINNED_KEY_NOT_IN_CERT_CHAIN, -150)

// Server request for client certificate did not contain any types we support.
NET_ERROR(CLIENT_AUTH_CERT_TYPE_UNSUPPORTED, -151)

// Error -152 was removed (ORIGIN_BOUND_CERT_GENERATION_TYPE_MISMATCH)

// An SSL peer sent us a fatal decrypt_error alert. This typically occurs when
// a peer could not correctly verify a signature (in CertificateVerify or
// ServerKeyExchange) or validate a Finished message.
NET_ERROR(SSL_DECRYPT_ERROR_ALERT, -153)

// There are too many pending WebSocketJob instances, so the new job was not
// pushed to the queue.
NET_ERROR(WS_THROTTLE_QUEUE_TOO_LARGE, -154)

// Error -155 was removed (TOO_MANY_SOCKET_STREAMS)

// The SSL server certificate changed in a renegotiation.
NET_ERROR(SSL_SERVER_CERT_CHANGED, -156)

// Error -157 was removed (SSL_INAPPROPRIATE_FALLBACK).

// Error -158 was removed (CT_NO_SCTS_VERIFIED_OK).

// The SSL server sent us a fatal unrecognized_name alert.
NET_ERROR(SSL_UNRECOGNIZED_NAME_ALERT, -159)

// Failed to set the socket's receive buffer size as requested.
NET_ERROR(SOCKET_SET_RECEIVE_BUFFER_SIZE_ERROR, -160)

// Failed to set the socket's send buffer size as requested.
NET_ERROR(SOCKET_SET_SEND_BUFFER_SIZE_ERROR, -161)

// Failed to set the socket's receive buffer size as requested, despite success
// return code from setsockopt.
NET_ERROR(SOCKET_RECEIVE_BUFFER_SIZE_UNCHANGEABLE, -162)

// Failed to set the socket's send buffer size as requested, despite success
// return code from setsockopt.
NET_ERROR(SOCKET_SEND_BUFFER_SIZE_UNCHANGEABLE, -163)

// Failed to import a client certificate from the platform store into the SSL
// library.
NET_ERROR(SSL_CLIENT_AUTH_CERT_BAD_FORMAT, -164)

// Error -165 was removed (SSL_FALLBACK_BEYOND_MINIMUM_VERSION).

// Resolving a hostname to an IP address list included the IPv4 address
// "127.0.53.53". This is a special IP address which ICANN has recommended to
// indicate there was a name collision, and alert admins to a potential
// problem.
NET_ERROR(ICANN_NAME_COLLISION, -166)

// The SSL server presented a certificate which could not be decoded. This is
// not a certificate error code as no X509Certificate object is available. This
// error is fatal.
NET_ERROR(SSL_SERVER_CERT_BAD_FORMAT, -167)

// Certificate Transparency: Received a signed tree head that failed to parse.
NET_ERROR(CT_STH_PARSING_FAILED, -168)

// Certificate Transparency: Received a signed tree head whose JSON parsing was
// OK but was missing some of the fields.
NET_ERROR(CT_STH_INCOMPLETE, -169)

// The attempt to reuse a connection to send proxy auth credentials failed
// before the AuthController was used to generate credentials. The caller should
// reuse the controller with a new connection. This error is only used
// internally by the network stack.
NET_ERROR(UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH, -170)

// Certificate Transparency: Failed to parse the received consistency proof.
NET_ERROR(CT_CONSISTENCY_PROOF_PARSING_FAILED, -171)

// The SSL server required an unsupported cipher suite that has since been
// removed. This error will temporarily be signaled on a fallback for one or two
// releases immediately following a cipher suite's removal, after which the
// fallback will be removed.
NET_ERROR(SSL_OBSOLETE_CIPHER, -172)

// When a WebSocket handshake is done successfully and the connection has been
// upgraded, the URLRequest is cancelled with this error code.
NET_ERROR(WS_UPGRADE, -173)

// Socket ReadIfReady support is not implemented. This error should not be user
// visible, because the normal Read() method is used as a fallback.
NET_ERROR(READ_IF_READY_NOT_IMPLEMENTED, -174)

// Error -175 was removed (SSL_VERSION_INTERFERENCE).

// No socket buffer space is available.
NET_ERROR(NO_BUFFER_SPACE, -176)

// There were no common signature algorithms between our client certificate
// private key and the server's preferences.
NET_ERROR(SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS, -177)

// TLS 1.3 early data was rejected by the server. This will be received before
// any data is returned from the socket. The request should be retried with
// early data disabled.
NET_ERROR(EARLY_DATA_REJECTED, -178)

// TLS 1.3 early data was offered, but the server responded with TLS 1.2 or
// earlier. This is an internal error code to account for a
// backwards-compatibility issue with early data and TLS 1.2. It will be
// received before any data is returned from the socket. The request should be
// retried with early data disabled.
//
// See https://tools.ietf.org/html/rfc8446#appendix-D.3 for details.
NET_ERROR(WRONG_VERSION_ON_EARLY_DATA, -179)

// TLS 1.3 was enabled, but a lower version was negotiated and the server
// returned a value indicating it supported TLS 1.3. This is part of a security
// check in TLS 1.3, but it may also indicate the user is behind a buggy
// TLS-terminating proxy which implemented TLS 1.2 incorrectly. (See
// https://crbug.com/boringssl/226.)
NET_ERROR(TLS13_DOWNGRADE_DETECTED, -180)

// The server's certificate has a keyUsage extension incompatible with the
// negotiated TLS key exchange method.
NET_ERROR(SSL_KEY_USAGE_INCOMPATIBLE, -181)

// The ECHConfigList fetched over DNS cannot be parsed.
NET_ERROR(INVALID_ECH_CONFIG_LIST, -182)

// ECH was enabled, but the server was unable to decrypt the encrypted
// ClientHello.
NET_ERROR(ECH_NOT_NEGOTIATED, -183)

// ECH was enabled, the server was unable to decrypt the encrypted ClientHello,
// and additionally did not present a certificate valid for the public name.
NET_ERROR(ECH_FALLBACK_CERTIFICATE_INVALID, -184)

// Certificate error codes
//
// The values of certificate error codes must be consecutive.

// The server responded with a certificate whose common name did not match
// the host name.  This could mean:
//
// 1. An attacker has redirected our traffic to their server and is
//    presenting a certificate for which they know the private key.
//
// 2. The server is misconfigured and responding with the wrong cert.
//
// 3. The user is on a wireless network and is being redirected to the
//    network's login page.
//
// 4. The OS has used a DNS search suffix and the server doesn't have
//    a certificate for the abbreviated name in the address bar.
//
NET_ERROR(CERT_COMMON_NAME_INVALID, -200)

// The server responded with a certificate that, by our clock, appears to
// either not yet be valid or to have expired.  This could mean:
//
// 1. An attacker is presenting an old certificate for which they have
//    managed to obtain the private key.
//
// 2. The server is misconfigured and is not presenting a valid cert.
//
// 3. Our clock is wrong.
//
NET_ERROR(CERT_DATE_INVALID, -201)

// The server responded with a certificate that is signed by an authority
// we don't trust.  The could mean:
//
// 1. An attacker has substituted the real certificate for a cert that
//    contains their public key and is signed by their cousin.
//
// 2. The server operator has a legitimate certificate from a CA we don't
//    know about, but should trust.
//
// 3. The server is presenting a self-signed certificate, providing no
//    defense against active attackers (but foiling passive attackers).
//
NET_ERROR(CERT_AUTHORITY_INVALID, -202)

// The server responded with a certificate that contains errors.
// This error is not recoverable.
//
// MSDN describes this error as follows:
//   "The SSL certificate contains errors."
// NOTE: It's unclear how this differs from ERR_CERT_INVALID. For consistency,
// use that code instead of this one from now on.
//
NET_ERROR(CERT_CONTAINS_ERRORS, -203)

// The certificate has no mechanism for determining if it is revoked.  In
// effect, this certificate cannot be revoked.
NET_ERROR(CERT_NO_REVOCATION_MECHANISM, -204)

// Revocation information for the security certificate for this site is not
// available.  This could mean:
//
// 1. An attacker has compromised the private key in the certificate and is
//    blocking our attempt to find out that the cert was revoked.
//
// 2. The certificate is unrevoked, but the revocation server is busy or
//    unavailable.
//
NET_ERROR(CERT_UNABLE_TO_CHECK_REVOCATION, -205)

// The server responded with a certificate has been revoked.
// We have the capability to ignore this error, but it is probably not the
// thing to do.
NET_ERROR(CERT_REVOKED, -206)

// The server responded with a certificate that is invalid.
// This error is not recoverable.
//
// MSDN describes this error as follows:
//   "The SSL certificate is invalid."
//
NET_ERROR(CERT_INVALID, -207)

// The server responded with a certificate that is signed using a weak
// signature algorithm.
NET_ERROR(CERT_WEAK_SIGNATURE_ALGORITHM, -208)

// -209 is available: was CERT_NOT_IN_DNS.

// The host name specified in the certificate is not unique.
NET_ERROR(CERT_NON_UNIQUE_NAME, -210)

// The server responded with a certificate that contains a weak key (e.g.
// a too-small RSA key).
NET_ERROR(CERT_WEAK_KEY, -211)

// The certificate claimed DNS names that are in violation of name constraints.
NET_ERROR(CERT_NAME_CONSTRAINT_VIOLATION, -212)

// The certificate's validity period is too long.
NET_ERROR(CERT_VALIDITY_TOO_LONG, -213)

// Certificate Transparency was required for this connection, but the server
// did not provide CT information that complied with the policy.
NET_ERROR(CERTIFICATE_TRANSPARENCY_REQUIRED, -214)

// The certificate chained to a legacy Symantec root that is no longer trusted.
// https://g.co/chrome/symantecpkicerts
NET_ERROR(CERT_SYMANTEC_LEGACY, -215)

// -216 was QUIC_CERT_ROOT_NOT_KNOWN which has been renumbered to not be in the
// certificate error range.

// The certificate is known to be used for interception by an entity other
// the device owner.
NET_ERROR(CERT_KNOWN_INTERCEPTION_BLOCKED, -217)

// -218 was SSL_OBSOLETE_VERSION which is not longer used. TLS 1.0/1.1 instead
// cause SSL_VERSION_OR_CIPHER_MISMATCH now.

// Add new certificate error codes here.
//
// Update the value of CERT_END whenever you add a new certificate error
// code.

// The value immediately past the last certificate error code.
NET_ERROR(CERT_END, -219)

// The URL is invalid.
NET_ERROR(INVALID_URL, -300)

// The scheme of the URL is disallowed.
NET_ERROR(DISALLOWED_URL_SCHEME, -301)

// The scheme of the URL is unknown.
NET_ERROR(UNKNOWN_URL_SCHEME, -302)

// Attempting to load an URL resulted in a redirect to an invalid URL.
NET_ERROR(INVALID_REDIRECT, -303)

// Attempting to load an URL resulted in too many redirects.
NET_ERROR(TOO_MANY_REDIRECTS, -310)

// Attempting to load an URL resulted in an unsafe redirect (e.g., a redirect
// to file:// is considered unsafe).
NET_ERROR(UNSAFE_REDIRECT, -311)

// Attempting to load an URL with an unsafe port number.  These are port
// numbers that correspond to services, which are not robust to spurious input
// that may be constructed as a result of an allowed web construct (e.g., HTTP
// looks a lot like SMTP, so form submission to port 25 is denied).
NET_ERROR(UNSAFE_PORT, -312)

// The server's response was invalid.
NET_ERROR(INVALID_RESPONSE, -320)

// Error in chunked transfer encoding.
NET_ERROR(INVALID_CHUNKED_ENCODING, -321)

// The server did not support the request method.
NET_ERROR(METHOD_NOT_SUPPORTED, -322)

// The response was 407 (Proxy Authentication Required), yet we did not send
// the request to a proxy.
NET_ERROR(UNEXPECTED_PROXY_AUTH, -323)

// The server closed the connection without sending any data.
NET_ERROR(EMPTY_RESPONSE, -324)

// The headers section of the response is too large.
NET_ERROR(RESPONSE_HEADERS_TOO_BIG, -325)

// Error -326 was removed (PAC_STATUS_NOT_OK)

// The evaluation of the PAC script failed.
NET_ERROR(PAC_SCRIPT_FAILED, -327)

// The response was 416 (Requested range not satisfiable) and the server cannot
// satisfy the range requested.
NET_ERROR(REQUEST_RANGE_NOT_SATISFIABLE, -328)

// The identity used for authentication is invalid.
NET_ERROR(MALFORMED_IDENTITY, -329)

// Content decoding of the response body failed.
NET_ERROR(CONTENT_DECODING_FAILED, -330)

// An operation could not be completed because all network IO
// is suspended.
NET_ERROR(NETWORK_IO_SUSPENDED, -331)

// FLIP data received without receiving a SYN_REPLY on the stream.
NET_ERROR(SYN_REPLY_NOT_RECEIVED, -332)

// Converting the response to target encoding failed.
NET_ERROR(ENCODING_CONVERSION_FAILED, -333)

// The server sent an FTP directory listing in a format we do not understand.
NET_ERROR(UNRECOGNIZED_FTP_DIRECTORY_LISTING_FORMAT, -334)

// Obsolete.  Was only logged in NetLog when an HTTP/2 pushed stream expired.
// NET_ERROR(INVALID_SPDY_STREAM, -335)

// There are no supported proxies in the provided list.
NET_ERROR(NO_SUPPORTED_PROXIES, -336)

// There is an HTTP/2 protocol error.
NET_ERROR(HTTP2_PROTOCOL_ERROR, -337)

// Credentials could not be established during HTTP Authentication.
NET_ERROR(INVALID_AUTH_CREDENTIALS, -338)

// An HTTP Authentication scheme was tried which is not supported on this
// machine.
NET_ERROR(UNSUPPORTED_AUTH_SCHEME, -339)

// Detecting the encoding of the response failed.
NET_ERROR(ENCODING_DETECTION_FAILED, -340)

// (GSSAPI) No Kerberos credentials were available during HTTP Authentication.
NET_ERROR(MISSING_AUTH_CREDENTIALS, -341)

// An unexpected, but documented, SSPI or GSSAPI status code was returned.
NET_ERROR(UNEXPECTED_SECURITY_LIBRARY_STATUS, -342)

// The environment was not set up correctly for authentication (for
// example, no KDC could be found or the principal is unknown.
NET_ERROR(MISCONFIGURED_AUTH_ENVIRONMENT, -343)

// An undocumented SSPI or GSSAPI status code was returned.
NET_ERROR(UNDOCUMENTED_SECURITY_LIBRARY_STATUS, -344)

// The HTTP response was too big to drain.
NET_ERROR(RESPONSE_BODY_TOO_BIG_TO_DRAIN, -345)

// The HTTP response contained multiple distinct Content-Length headers.
NET_ERROR(RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH, -346)

// HTTP/2 headers have been received, but not all of them - status or version
// headers are missing, so we're expecting additional frames to complete them.
NET_ERROR(INCOMPLETE_HTTP2_HEADERS, -347)

// No PAC URL configuration could be retrieved from DHCP. This can indicate
// either a failure to retrieve the DHCP configuration, or that there was no
// PAC URL configured in DHCP.
NET_ERROR(PAC_NOT_IN_DHCP, -348)

// The HTTP response contained multiple Content-Disposition headers.
NET_ERROR(RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION, -349)

// The HTTP response contained multiple Location headers.
NET_ERROR(RESPONSE_HEADERS_MULTIPLE_LOCATION, -350)

// HTTP/2 server refused the request without processing, and sent either a
// GOAWAY frame with error code NO_ERROR and Last-Stream-ID lower than the
// stream id corresponding to the request indicating that this request has not
// been processed yet, or a RST_STREAM frame with error code REFUSED_STREAM.
// Client MAY retry (on a different connection).  See RFC7540 Section 8.1.4.
NET_ERROR(HTTP2_SERVER_REFUSED_STREAM, -351)

// HTTP/2 server didn't respond to the PING message.
NET_ERROR(HTTP2_PING_FAILED, -352)

// Obsolete.  Kept here to avoid reuse, as the old error can still appear on
// histograms.
// NET_ERROR(PIPELINE_EVICTION, -353)

// The HTTP response body transferred fewer bytes than were advertised by the
// Content-Length header when the connection is closed.
NET_ERROR(CONTENT_LENGTH_MISMATCH, -354)

// The HTTP response body is transferred with Chunked-Encoding, but the
// terminating zero-length chunk was never sent when the connection is closed.
NET_ERROR(INCOMPLETE_CHUNKED_ENCODING, -355)

// There is a QUIC protocol error.
NET_ERROR(QUIC_PROTOCOL_ERROR, -356)

// The HTTP headers were truncated by an EOF.
NET_ERROR(RESPONSE_HEADERS_TRUNCATED, -357)

// The QUIC crypto handshake failed.  This means that the server was unable
// to read any requests sent, so they may be resent.
NET_ERROR(QUIC_HANDSHAKE_FAILED, -358)

// Obsolete.  Kept here to avoid reuse, as the old error can still appear on
// histograms.
// NET_ERROR(REQUEST_FOR_SECURE_RESOURCE_OVER_INSECURE_QUIC, -359)

// Transport security is inadequate for the HTTP/2 version.
NET_ERROR(HTTP2_INADEQUATE_TRANSPORT_SECURITY, -360)

// The peer violated HTTP/2 flow control.
NET_ERROR(HTTP2_FLOW_CONTROL_ERROR, -361)

// The peer sent an improperly sized HTTP/2 frame.
NET_ERROR(HTTP2_FRAME_SIZE_ERROR, -362)

// Decoding or encoding of compressed HTTP/2 headers failed.
NET_ERROR(HTTP2_COMPRESSION_ERROR, -363)

// Proxy Auth Requested without a valid Client Socket Handle.
NET_ERROR(PROXY_AUTH_REQUESTED_WITH_NO_CONNECTION, -364)

// HTTP_1_1_REQUIRED error code received on HTTP/2 session.
NET_ERROR(HTTP_1_1_REQUIRED, -365)

// HTTP_1_1_REQUIRED error code received on HTTP/2 session to proxy.
NET_ERROR(PROXY_HTTP_1_1_REQUIRED, -366)

// The PAC script terminated fatally and must be reloaded.
NET_ERROR(PAC_SCRIPT_TERMINATED, -367)

// Obsolete. Kept here to avoid reuse.
// Request is throttled because of a Backoff header.
// See: crbug.com/486891.
// NET_ERROR(TEMPORARY_BACKOFF, -369)

// The server was expected to return an HTTP/1.x response, but did not. Rather
// than treat it as HTTP/0.9, this error is returned.
NET_ERROR(INVALID_HTTP_RESPONSE, -370)

// Initializing content decoding failed.
NET_ERROR(CONTENT_DECODING_INIT_FAILED, -371)

// Received HTTP/2 RST_STREAM frame with NO_ERROR error code.  This error should
// be handled internally by HTTP/2 code, and should not make it above the
// SpdyStream layer.
NET_ERROR(HTTP2_RST_STREAM_NO_ERROR_RECEIVED, -372)

// Obsolete. HTTP/2 push is removed.
// NET_ERROR(HTTP2_PUSHED_STREAM_NOT_AVAILABLE, -373)

// Obsolete. HTTP/2 push is removed.
// NET_ERROR(HTTP2_CLAIMED_PUSHED_STREAM_RESET_BY_SERVER, -374)

// An HTTP transaction was retried too many times due for authentication or
// invalid certificates. This may be due to a bug in the net stack that would
// otherwise infinite loop, or if the server or proxy continually requests fresh
// credentials or presents a fresh invalid certificate.
NET_ERROR(TOO_MANY_RETRIES, -375)

// Received an HTTP/2 frame on a closed stream.
NET_ERROR(HTTP2_STREAM_CLOSED, -376)

// Obsolete. HTTP/2 push is removed.
// NET_ERROR(HTTP2_CLIENT_REFUSED_STREAM, -377)

// Obsolete. HTTP/2 push is removed.
// NET_ERROR(HTTP2_PUSHED_RESPONSE_DOES_NOT_MATCH, -378)

// The server returned a non-2xx HTTP response code.
//
// Not that this error is only used by certain APIs that interpret the HTTP
// response itself. URLRequest for instance just passes most non-2xx
// response back as success.
NET_ERROR(HTTP_RESPONSE_CODE_FAILURE, -379)

// The certificate presented on a QUIC connection does not chain to a known root
// and the origin connected to is not on a list of domains where unknown roots
// are allowed.
NET_ERROR(QUIC_CERT_ROOT_NOT_KNOWN, -380)

// A GOAWAY frame has been received indicating that the request has not been
// processed and is therefore safe to retry on a different connection.
NET_ERROR(QUIC_GOAWAY_REQUEST_CAN_BE_RETRIED, -381)

// The ACCEPT_CH restart has been triggered too many times
NET_ERROR(TOO_MANY_ACCEPT_CH_RESTARTS, -382)

// The IP address space of the remote endpoint differed from the previous
// observed value during the same request. Any cache entry for the affected
// request should be invalidated.
NET_ERROR(INCONSISTENT_IP_ADDRESS_SPACE, -383)

// The IP address space of the cached remote endpoint is blocked by private
// network access check.
NET_ERROR(CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY,
    -384)

    // The cache does not have the requested entry.
    NET_ERROR(CACHE_MISS, -400)

    // Unable to read from the disk cache.
    NET_ERROR(CACHE_READ_FAILURE, -401)

    // Unable to write to the disk cache.
    NET_ERROR(CACHE_WRITE_FAILURE, -402)

    // The operation is not supported for this entry.
    NET_ERROR(CACHE_OPERATION_NOT_SUPPORTED, -403)

    // The disk cache is unable to open this entry.
    NET_ERROR(CACHE_OPEN_FAILURE, -404)

    // The disk cache is unable to create this entry.
    NET_ERROR(CACHE_CREATE_FAILURE, -405)

    // Multiple transactions are racing to create disk cache entries. This is an
    // internal error returned from the HttpCache to the HttpCacheTransaction that
    // tells the transaction to restart the entry-creation logic because the state
    // of the cache has changed.
    NET_ERROR(CACHE_RACE, -406)

    // The cache was unable to read a checksum record on an entry. This can be
    // returned from attempts to read from the cache. It is an internal error,
    // returned by the SimpleCache backend, but not by any URLRequest methods
    // or members.
    NET_ERROR(CACHE_CHECKSUM_READ_FAILURE, -407)

    // The cache found an entry with an invalid checksum. This can be returned from
    // attempts to read from the cache. It is an internal error, returned by the
    // SimpleCache backend, but not by any URLRequest methods or members.
    NET_ERROR(CACHE_CHECKSUM_MISMATCH, -408)

    // Internal error code for the HTTP cache. The cache lock timeout has fired.
    NET_ERROR(CACHE_LOCK_TIMEOUT, -409)

    // Received a challenge after the transaction has read some data, and the
    // credentials aren't available.  There isn't a way to get them at that point.
    NET_ERROR(CACHE_AUTH_FAILURE_AFTER_READ, -410)

    // Internal not-quite error code for the HTTP cache. In-memory hints suggest
    // that the cache entry would not have been usable with the transaction's
    // current configuration (e.g. load flags, mode, etc.)
    NET_ERROR(CACHE_ENTRY_NOT_SUITABLE, -411)

    // The disk cache is unable to doom this entry.
    NET_ERROR(CACHE_DOOM_FAILURE, -412)

    // The disk cache is unable to open or create this entry.
    NET_ERROR(CACHE_OPEN_OR_CREATE_FAILURE, -413)

    // The server's response was insecure (e.g. there was a cert error).
    NET_ERROR(INSECURE_RESPONSE, -501)

    // An attempt to import a client certificate failed, as the user's key
    // database lacked a corresponding private key.
    NET_ERROR(NO_PRIVATE_KEY_FOR_CERT, -502)

    // An error adding a certificate to the OS certificate database.
    NET_ERROR(ADD_USER_CERT_FAILED, -503)

    // An error occurred while handling a signed exchange.
    NET_ERROR(INVALID_SIGNED_EXCHANGE, -504)

    // An error occurred while handling a Web Bundle source.
    NET_ERROR(INVALID_WEB_BUNDLE, -505)

    // A Trust Tokens protocol operation-executing request failed for one of a
    // number of reasons (precondition failure, internal error, bad response).
    NET_ERROR(TRUST_TOKEN_OPERATION_FAILED, -506)

    // When handling a Trust Tokens protocol operation-executing request, the system
    // was able to execute the request's Trust Tokens operation without sending the
    // request to its destination: for instance, the results could have been present
    // in a local cache (for redemption) or the operation could have been diverted
    // to a local provider (for "platform-provided" issuance).
    NET_ERROR(TRUST_TOKEN_OPERATION_SUCCESS_WITHOUT_SENDING_REQUEST, -507)

    // *** Code -600 is reserved (was FTP_PASV_COMMAND_FAILED). ***

    // A generic error for failed FTP control connection command.
    // If possible, please use or add a more specific error code.
    NET_ERROR(FTP_FAILED, -601)

    // The server cannot fulfill the request at this point. This is a temporary
    // error.
    // FTP response code 421.
    NET_ERROR(FTP_SERVICE_UNAVAILABLE, -602)

    // The server has aborted the transfer.
    // FTP response code 426.
    NET_ERROR(FTP_TRANSFER_ABORTED, -603)

    // The file is busy, or some other temporary error condition on opening
    // the file.
    // FTP response code 450.
    NET_ERROR(FTP_FILE_BUSY, -604)

    // Server rejected our command because of syntax errors.
    // FTP response codes 500, 501.
    NET_ERROR(FTP_SYNTAX_ERROR, -605)

    // Server does not support the command we issued.
    // FTP response codes 502, 504.
    NET_ERROR(FTP_COMMAND_NOT_SUPPORTED, -606)

    // Server rejected our command because we didn't issue the commands in right
    // order.
    // FTP response code 503.
    NET_ERROR(FTP_BAD_COMMAND_SEQUENCE, -607)

    // PKCS #12 import failed due to incorrect password.
    NET_ERROR(PKCS12_IMPORT_BAD_PASSWORD, -701)

    // PKCS #12 import failed due to other error.
    NET_ERROR(PKCS12_IMPORT_FAILED, -702)

    // CA import failed - not a CA cert.
    NET_ERROR(IMPORT_CA_CERT_NOT_CA, -703)

    // Import failed - certificate already exists in database.
    // Note it's a little weird this is an error but reimporting a PKCS12 is ok
    // (no-op).  That's how Mozilla does it, though.
    NET_ERROR(IMPORT_CERT_ALREADY_EXISTS, -704)

    // CA import failed due to some other error.
    NET_ERROR(IMPORT_CA_CERT_FAILED, -705)

    // Server certificate import failed due to some internal error.
    NET_ERROR(IMPORT_SERVER_CERT_FAILED, -706)

    // PKCS #12 import failed due to invalid MAC.
    NET_ERROR(PKCS12_IMPORT_INVALID_MAC, -707)

    // PKCS #12 import failed due to invalid/corrupt file.
    NET_ERROR(PKCS12_IMPORT_INVALID_FILE, -708)

    // PKCS #12 import failed due to unsupported features.
    NET_ERROR(PKCS12_IMPORT_UNSUPPORTED, -709)

    // Key generation failed.
    NET_ERROR(KEY_GENERATION_FAILED, -710)

    // Error -711 was removed (ORIGIN_BOUND_CERT_GENERATION_FAILED)

    // Failure to export private key.
    NET_ERROR(PRIVATE_KEY_EXPORT_FAILED, -712)

    // Self-signed certificate generation failed.
    NET_ERROR(SELF_SIGNED_CERT_GENERATION_FAILED, -713)

    // The certificate database changed in some way.
    NET_ERROR(CERT_DATABASE_CHANGED, -714)

    // Error -715 was removed (CHANNEL_ID_IMPORT_FAILED)

    // The certificate verifier configuration changed in some way.
    NET_ERROR(CERT_VERIFIER_CHANGED, -716)

    // DNS error codes.

    // DNS resolver received a malformed response.
    NET_ERROR(DNS_MALFORMED_RESPONSE, -800)

    // DNS server requires TCP
    NET_ERROR(DNS_SERVER_REQUIRES_TCP, -801)

    // DNS server failed.  This error is returned for all of the following
    // error conditions:
    // 1 - Format error - The name server was unable to interpret the query.
    // 2 - Server failure - The name server was unable to process this query
    //     due to a problem with the name server.
    // 4 - Not Implemented - The name server does not support the requested
    //     kind of query.
    // 5 - Refused - The name server refuses to perform the specified
    //     operation for policy reasons.
    NET_ERROR(DNS_SERVER_FAILED, -802)

    // DNS transaction timed out.
    NET_ERROR(DNS_TIMED_OUT, -803)

    // The entry was not found in cache or other local sources, for lookups where
    // only local sources were queried.
    // TODO(ericorth): Consider renaming to DNS_LOCAL_MISS or something like that as
    // the cache is not necessarily queried either.
    NET_ERROR(DNS_CACHE_MISS, -804)

    // Suffix search list rules prevent resolution of the given host name.
    NET_ERROR(DNS_SEARCH_EMPTY, -805)

    // Failed to sort addresses according to RFC3484.
    NET_ERROR(DNS_SORT_ERROR, -806)

    // Error -807 was removed (DNS_HTTP_FAILED)

    // Failed to resolve the hostname of a DNS-over-HTTPS server.
    NET_ERROR(DNS_SECURE_RESOLVER_HOSTNAME_RESOLUTION_FAILED, -808)

    // DNS identified the request as disallowed for insecure connection (http/ws).
    // Error should be handled as if an HTTP redirect was received to redirect to
    // https or wss.
    NET_ERROR(DNS_NAME_HTTPS_ONLY, -809)

    // All DNS requests associated with this job have been cancelled.
    NET_ERROR(DNS_REQUEST_CANCELLED, -810)

    // The hostname resolution of HTTPS record was expected to be resolved with
    // alpn values of supported protocols, but did not.
    NET_ERROR(DNS_NO_MATCHING_SUPPORTED_ALPN, -811)

    // The compression dictionary cannot be loaded.
    NET_ERROR(DICTIONARY_LOAD_FAILED, -812)

    // Error -813 was removed (DICTIONARY_ORIGIN_CHECK_FAILED)
#undef NET_ERROR
        } cef_errorcode_t;


typedef struct _cef_base_ref_counted_t {
    ///
    // Size of the data structure.
    ///
    size_t size;

    ///
    // Called to increment the reference count for the object. Should be called
    // for every new copy of a pointer to a given object.
    ///
    void(CEF_CALLBACK* add_ref)(struct _cef_base_ref_counted_t* self);

    ///
    // Called to decrement the reference count for the object. If the reference
    // count falls to 0 the object should self-delete. Returns true (1) if the
    // resulting reference count is 0.
    ///
    int(CEF_CALLBACK* release)(struct _cef_base_ref_counted_t* self);

    ///
    // Returns true (1) if the current reference count is 1.
    ///
    int(CEF_CALLBACK* has_one_ref)(struct _cef_base_ref_counted_t* self);

    ///
    // Returns true (1) if the current reference count is at least 1.
    ///
    int(CEF_CALLBACK* has_at_least_one_ref)(struct _cef_base_ref_counted_t* self);
} cef_base_ref_counted_t;



typedef struct _cef_request_t {
    ///
    /// Base structure.
    ///
    cef_base_ref_counted_t base;

    ///
    /// Returns true (1) if this object is read-only.
    ///
    int(CEF_CALLBACK* is_read_only)(struct _cef_request_t* self);

    ///
    /// Get the fully qualified URL.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_url)(struct _cef_request_t* self);

    ///
    /// Set the fully qualified URL.
    ///
    void(CEF_CALLBACK* set_url)(struct _cef_request_t* self,
        const cef_string_t* url);

    ///
    /// Get the request function type. The value will default to POST if post data
    /// is provided and GET otherwise.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_method)(struct _cef_request_t* self);

    ///
    /// Set the request function type.
    ///
    void(CEF_CALLBACK* set_method)(struct _cef_request_t* self,
        const cef_string_t* method);

    ///
    /// Set the referrer URL and policy. If non-NULL the referrer URL must be
    /// fully qualified with an HTTP or HTTPS scheme component. Any username,
    /// password or ref component will be removed.
    ///
    void(CEF_CALLBACK* set_referrer)(struct _cef_request_t* self,
        const cef_string_t* referrer_url,
        cef_referrer_policy_t policy);

    ///
    /// Get the referrer URL.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_referrer_url)(
        struct _cef_request_t* self);

    ///
    /// Get the referrer policy.
    ///
    cef_referrer_policy_t(CEF_CALLBACK* get_referrer_policy)(
        struct _cef_request_t* self);

    ///
    /// Get the post data.
    ///
    struct _cef_post_data_t* (CEF_CALLBACK* get_post_data)(
        struct _cef_request_t* self);

    ///
    /// Set the post data.
    ///
    void(CEF_CALLBACK* set_post_data)(struct _cef_request_t* self,
        struct _cef_post_data_t* postData);

    ///
    /// Get the header values. Will not include the Referer value if any.
    ///
    void(CEF_CALLBACK* get_header_map)(struct _cef_request_t* self,
        cef_string_multimap_t headerMap);

    ///
    /// Set the header values. If a Referer value exists in the header map it will
    /// be removed and ignored.
    ///
    void(CEF_CALLBACK* set_header_map)(struct _cef_request_t* self,
        cef_string_multimap_t headerMap);

    ///
    /// Returns the first header value for |name| or an NULL string if not found.
    /// Will not return the Referer value if any. Use GetHeaderMap instead if
    /// |name| might have multiple values.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_header_by_name)(
        struct _cef_request_t* self,
        const cef_string_t* name);

    ///
    /// Set the header |name| to |value|. If |overwrite| is true (1) any existing
    /// values will be replaced with the new value. If |overwrite| is false (0)
    /// any existing values will not be overwritten. The Referer value cannot be
    /// set using this function.
    ///
    void(CEF_CALLBACK* set_header_by_name)(struct _cef_request_t* self,
        const cef_string_t* name,
        const cef_string_t* value,
        int overwrite);

    ///
    /// Set all values at one time.
    ///
    void(CEF_CALLBACK* set)(struct _cef_request_t* self,
        const cef_string_t* url,
        const cef_string_t* method,
        struct _cef_post_data_t* postData,
        cef_string_multimap_t headerMap);

    ///
    /// Get the flags used in combination with cef_urlrequest_t. See
    /// cef_urlrequest_flags_t for supported values.
    ///
    int(CEF_CALLBACK* get_flags)(struct _cef_request_t* self);

    ///
    /// Set the flags used in combination with cef_urlrequest_t.  See
    /// cef_urlrequest_flags_t for supported values.
    ///
    void(CEF_CALLBACK* set_flags)(struct _cef_request_t* self, int flags);

    ///
    /// Get the URL to the first party for cookies used in combination with
    /// cef_urlrequest_t.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_first_party_for_cookies)(
        struct _cef_request_t* self);

    ///
    /// Set the URL to the first party for cookies used in combination with
    /// cef_urlrequest_t.
    ///
    void(CEF_CALLBACK* set_first_party_for_cookies)(struct _cef_request_t* self,
        const cef_string_t* url);

    ///
    /// Get the resource type for this request. Only available in the browser
    /// process.
    ///
    cef_resource_type_t(CEF_CALLBACK* get_resource_type)(
        struct _cef_request_t* self);

    ///
    /// Get the transition type for this request. Only available in the browser
    /// process and only applies to requests that represent a main frame or sub-
    /// frame navigation.
    ///
    cef_transition_type_t(CEF_CALLBACK* get_transition_type)(
        struct _cef_request_t* self);

    ///
    /// Returns the globally unique identifier for this request or 0 if not
    /// specified. Can be used by cef_resource_request_handler_t implementations
    /// in the browser process to track a single request across multiple
    /// callbacks.
    ///
    uint64_t(CEF_CALLBACK* get_identifier)(struct _cef_request_t* self);
} cef_request_t;

typedef struct _cef_urlrequest_t {
    ///
    /// Base structure.
    ///
    cef_base_ref_counted_t base;

    ///
    /// Returns the request object used to create this URL request. The returned
    /// object is read-only and should not be modified.
    ///
    struct _cef_request_t* (CEF_CALLBACK* get_request)(
        struct _cef_urlrequest_t* self);

    ///
    /// Returns the client.
    ///
    struct _cef_urlrequest_client_t* (CEF_CALLBACK* get_client)(
        struct _cef_urlrequest_t* self);

    ///
    /// Returns the request status.
    ///
    cef_urlrequest_status_t(CEF_CALLBACK* get_request_status)(
        struct _cef_urlrequest_t* self);

    ///
    /// Returns the request error if status is UR_CANCELED or UR_FAILED, or 0
    /// otherwise.
    ///
    cef_errorcode_t(CEF_CALLBACK* get_request_error)(
        struct _cef_urlrequest_t* self);

    ///
    /// Returns the response, or NULL if no response information is available.
    /// Response information will only be available after the upload has
    /// completed. The returned object is read-only and should not be modified.
    ///
    struct _cef_response_t* (CEF_CALLBACK* get_response)(
        struct _cef_urlrequest_t* self);

    ///
    /// Returns true (1) if the response body was served from the cache. This
    /// includes responses for which revalidation was required.
    ///
    int(CEF_CALLBACK* response_was_cached)(struct _cef_urlrequest_t* self);

    ///
    /// Cancel the request.
    ///
    void(CEF_CALLBACK* cancel)(struct _cef_urlrequest_t* self);
} cef_urlrequest_t;

typedef struct _cef_urlrequest_client_t {
    ///
    /// Base structure.
    ///
    cef_base_ref_counted_t base;

    ///
    /// Notifies the client that the request has completed. Use the
    /// cef_urlrequest_t::GetRequestStatus function to determine if the request
    /// was successful or not.
    ///
    void(CEF_CALLBACK* on_request_complete)(struct _cef_urlrequest_client_t* self,
        struct _cef_urlrequest_t* request);

    ///
    /// Notifies the client of upload progress. |current| denotes the number of
    /// bytes sent so far and |total| is the total size of uploading data (or -1
    /// if chunked upload is enabled). This function will only be called if the
    /// UR_FLAG_REPORT_UPLOAD_PROGRESS flag is set on the request.
    ///
    void(CEF_CALLBACK* on_upload_progress)(struct _cef_urlrequest_client_t* self,
        struct _cef_urlrequest_t* request,
        int64_t current,
        int64_t total);

    ///
    /// Notifies the client of download progress. |current| denotes the number of
    /// bytes received up to the call and |total| is the expected total size of
    /// the response (or -1 if not determined).
    ///
    void(CEF_CALLBACK* on_download_progress)(
        struct _cef_urlrequest_client_t* self,
        struct _cef_urlrequest_t* request,
        int64_t current,
        int64_t total);

    ///
    /// Called when some part of the response is read. |data| contains the current
    /// bytes received since the last call. This function will not be called if
    /// the UR_FLAG_NO_DOWNLOAD_DATA flag is set on the request.
    ///
    void(CEF_CALLBACK* on_download_data)(struct _cef_urlrequest_client_t* self,
        struct _cef_urlrequest_t* request,
        const void* data,
        size_t data_length);

    ///
    /// Called on the IO thread when the browser needs credentials from the user.
    /// |isProxy| indicates whether the host is a proxy server. |host| contains
    /// the hostname and |port| contains the port number. Return true (1) to
    /// continue the request and call cef_auth_callback_t::cont() when the
    /// authentication information is available. If the request has an associated
    /// browser/frame then returning false (0) will result in a call to
    /// GetAuthCredentials on the cef_request_handler_t associated with that
    /// browser, if any. Otherwise, returning false (0) will cancel the request
    /// immediately. This function will only be called for requests initiated from
    /// the browser process.
    ///
    int(CEF_CALLBACK* get_auth_credentials)(
        struct _cef_urlrequest_client_t* self,
        int isProxy,
        const cef_string_t* host,
        int port,
        const cef_string_t* realm,
        const cef_string_t* scheme,
        struct _cef_auth_callback_t* callback);
} cef_urlrequest_client_t;

typedef enum {
    CEF_CONTENT_SETTING_TYPE_COOKIES = 0,
    CEF_CONTENT_SETTING_TYPE_IMAGES,
    CEF_CONTENT_SETTING_TYPE_JAVASCRIPT,

    /// This setting governs both popups and unwanted redirects like tab-unders
    /// and framebusting.
    CEF_CONTENT_SETTING_TYPE_POPUPS,

    CEF_CONTENT_SETTING_TYPE_GEOLOCATION,
    CEF_CONTENT_SETTING_TYPE_NOTIFICATIONS,
    CEF_CONTENT_SETTING_TYPE_AUTO_SELECT_CERTIFICATE,
    CEF_CONTENT_SETTING_TYPE_MIXEDSCRIPT,
    CEF_CONTENT_SETTING_TYPE_MEDIASTREAM_MIC,
    CEF_CONTENT_SETTING_TYPE_MEDIASTREAM_CAMERA,
    CEF_CONTENT_SETTING_TYPE_PROTOCOL_HANDLERS,
    CEF_CONTENT_SETTING_TYPE_DEPRECATED_PPAPI_BROKER,
    CEF_CONTENT_SETTING_TYPE_AUTOMATIC_DOWNLOADS,
    CEF_CONTENT_SETTING_TYPE_MIDI_SYSEX,
    CEF_CONTENT_SETTING_TYPE_SSL_CERT_DECISIONS,
    CEF_CONTENT_SETTING_TYPE_PROTECTED_MEDIA_IDENTIFIER,
    CEF_CONTENT_SETTING_TYPE_APP_BANNER,
    CEF_CONTENT_SETTING_TYPE_SITE_ENGAGEMENT,
    CEF_CONTENT_SETTING_TYPE_DURABLE_STORAGE,
    CEF_CONTENT_SETTING_TYPE_USB_CHOOSER_DATA,
    CEF_CONTENT_SETTING_TYPE_BLUETOOTH_GUARD,
    CEF_CONTENT_SETTING_TYPE_BACKGROUND_SYNC,
    CEF_CONTENT_SETTING_TYPE_AUTOPLAY,
    CEF_CONTENT_SETTING_TYPE_IMPORTANT_SITE_INFO,
    CEF_CONTENT_SETTING_TYPE_PERMISSION_AUTOBLOCKER_DATA,
    CEF_CONTENT_SETTING_TYPE_ADS,

    /// Website setting which stores metadata for the subresource filter to aid in
    /// decisions for whether or not to show the UI.
    CEF_CONTENT_SETTING_TYPE_ADS_DATA,

    /// This is special-cased in the permissions layer to always allow, and as
    /// such doesn't have associated prefs data.
    CEF_CONTENT_SETTING_TYPE_MIDI,

    /// This content setting type is for caching password protection service's
    /// verdicts of each origin.
    CEF_CONTENT_SETTING_TYPE_PASSWORD_PROTECTION,

    /// Website setting which stores engagement data for media related to a
    /// specific origin.
    CEF_CONTENT_SETTING_TYPE_MEDIA_ENGAGEMENT,

    /// Content setting which stores whether or not the site can play audible
    /// sound. This will not block playback but instead the user will not hear it.
    CEF_CONTENT_SETTING_TYPE_SOUND,

    /// Website setting which stores the list of client hints that the origin
    /// requested the browser to remember. The browser is expected to send all
    /// client hints in the HTTP request headers for every resource requested
    /// from that origin.
    CEF_CONTENT_SETTING_TYPE_CLIENT_HINTS,

    /// Generic Sensor API covering ambient-light-sensor, accelerometer, gyroscope
    /// and magnetometer are all mapped to a single content_settings_type.
    /// Setting for the Generic Sensor API covering ambient-light-sensor,
    /// accelerometer, gyroscope and magnetometer. These are all mapped to a
    /// single ContentSettingsType.
    CEF_CONTENT_SETTING_TYPE_SENSORS,

    /// Content setting which stores whether or not the user has granted the site
    /// permission to respond to accessibility events, which can be used to
    /// provide a custom accessibility experience. Requires explicit user consent
    /// because some users may not want sites to know they're using assistive
    /// technology.
    CEF_CONTENT_SETTING_TYPE_ACCESSIBILITY_EVENTS,

    /// Used to store whether to allow a website to install a payment handler.
    CEF_CONTENT_SETTING_TYPE_PAYMENT_HANDLER,

    /// Content setting which stores whether to allow sites to ask for permission
    /// to access USB devices. If this is allowed specific device permissions are
    /// stored under USB_CHOOSER_DATA.
    CEF_CONTENT_SETTING_TYPE_USB_GUARD,

    /// Nothing is stored in this setting at present. Please refer to
    /// BackgroundFetchPermissionContext for details on how this permission
    /// is ascertained.
    CEF_CONTENT_SETTING_TYPE_BACKGROUND_FETCH,

    /// Website setting which stores the amount of times the user has dismissed
    /// intent picker UI without explicitly choosing an option.
    CEF_CONTENT_SETTING_TYPE_INTENT_PICKER_DISPLAY,

    /// Used to store whether to allow a website to detect user active/idle state.
    CEF_CONTENT_SETTING_TYPE_IDLE_DETECTION,

    /// Setting for enabling auto-select of all screens for getDisplayMediaSet.
    CEF_CONTENT_SETTING_TYPE_GET_DISPLAY_MEDIA_SET_SELECT_ALL_SCREENS,

    /// Content settings for access to serial ports. The "guard" content setting
    /// stores whether to allow sites to ask for permission to access a port. The
    /// permissions granted to access particular ports are stored in the "chooser
    /// data" website setting.
    CEF_CONTENT_SETTING_TYPE_SERIAL_GUARD,
    CEF_CONTENT_SETTING_TYPE_SERIAL_CHOOSER_DATA,

    /// Nothing is stored in this setting at present. Please refer to
    /// PeriodicBackgroundSyncPermissionContext for details on how this permission
    /// is ascertained.
    /// This content setting is not registered because it does not require access
    /// to any existing providers.
    CEF_CONTENT_SETTING_TYPE_PERIODIC_BACKGROUND_SYNC,

    /// Content setting which stores whether to allow sites to ask for permission
    /// to do Bluetooth scanning.
    CEF_CONTENT_SETTING_TYPE_BLUETOOTH_SCANNING,

    /// Content settings for access to HID devices. The "guard" content setting
    /// stores whether to allow sites to ask for permission to access a device.
    /// The permissions granted to access particular devices are stored in the
    /// "chooser data" website setting.
    CEF_CONTENT_SETTING_TYPE_HID_GUARD,
    CEF_CONTENT_SETTING_TYPE_HID_CHOOSER_DATA,

    /// Wake Lock API, which has two lock types: screen and system locks.
    /// Currently, screen locks do not need any additional permission, and system
    /// locks are always denied while the right UI is worked out.
    CEF_CONTENT_SETTING_TYPE_WAKE_LOCK_SCREEN,
    CEF_CONTENT_SETTING_TYPE_WAKE_LOCK_SYSTEM,

    /// Legacy SameSite cookie behavior. This disables SameSite=Lax-by-default,
    /// SameSite=None requires Secure, and Schemeful Same-Site, forcing the
    /// legacy behavior wherein 1) cookies that don't specify SameSite are treated
    /// as SameSite=None, 2) SameSite=None cookies are not required to be Secure,
    /// and 3) schemeful same-site is not active.
    ///
    /// This will also be used to revert to legacy behavior when future changes
    /// in cookie handling are introduced.
    CEF_CONTENT_SETTING_TYPE_LEGACY_COOKIE_ACCESS,

    /// Content settings which stores whether to allow sites to ask for permission
    /// to save changes to an original file selected by the user through the
    /// File System Access API.
    CEF_CONTENT_SETTING_TYPE_FILE_SYSTEM_WRITE_GUARD,

    /// Used to store whether to allow a website to exchange data with NFC
    /// devices.
    CEF_CONTENT_SETTING_TYPE_NFC,

    /// Website setting to store permissions granted to access particular
    /// Bluetooth devices.
    CEF_CONTENT_SETTING_TYPE_BLUETOOTH_CHOOSER_DATA,

    /// Full access to the system clipboard (sanitized read without user gesture,
    /// and unsanitized read and write with user gesture).
    CEF_CONTENT_SETTING_TYPE_CLIPBOARD_READ_WRITE,

    /// This is special-cased in the permissions layer to always allow, and as
    /// such doesn't have associated prefs data.
    CEF_CONTENT_SETTING_TYPE_CLIPBOARD_SANITIZED_WRITE,

    /// This content setting type is for caching safe browsing real time url
    /// check's verdicts of each origin.
    CEF_CONTENT_SETTING_TYPE_SAFE_BROWSING_URL_CHECK_DATA,

    /// Used to store whether a site is allowed to request AR or VR sessions with
    /// the WebXr Device API.
    CEF_CONTENT_SETTING_TYPE_VR,
    CEF_CONTENT_SETTING_TYPE_AR,

    /// Content setting which stores whether to allow site to open and read files
    /// and directories selected through the File System Access API.
    CEF_CONTENT_SETTING_TYPE_FILE_SYSTEM_READ_GUARD,

    /// Access to first party storage in a third-party context. Exceptions are
    /// scoped to the combination of requesting/top-level origin, and are managed
    /// through the Storage Access API. For the time being, this content setting
    /// exists in parallel to third-party cookie rules stored in COOKIES.
    CEF_CONTENT_SETTING_TYPE_STORAGE_ACCESS,

    /// Content setting which stores whether to allow a site to control camera
    /// movements. It does not give access to camera.
    CEF_CONTENT_SETTING_TYPE_CAMERA_PAN_TILT_ZOOM,

    /// Content setting for Screen Enumeration and Screen Detail functionality.
    /// Permits access to detailed multi-screen information, like size and
    /// position. Permits placing fullscreen and windowed content on specific
    /// screens. See also: https://w3c.github.io/window-placement
    CEF_CONTENT_SETTING_TYPE_WINDOW_MANAGEMENT,

    /// Stores whether to allow insecure websites to make local network requests.
    /// See also: https://wicg.github.io/local-network-access
    /// Set through enterprise policies only.
    CEF_CONTENT_SETTING_TYPE_INSECURE_LOCAL_NETWORK,

    /// Content setting which stores whether or not a site can access low-level
    /// locally installed font data using the Local Fonts Access API.
    CEF_CONTENT_SETTING_TYPE_LOCAL_FONTS,

    /// Stores per-origin state for permission auto-revocation (for all permission
    /// types).
    CEF_CONTENT_SETTING_TYPE_PERMISSION_AUTOREVOCATION_DATA,

    /// Stores per-origin state of the most recently selected directory for the
    /// use by the File System Access API.
    CEF_CONTENT_SETTING_TYPE_FILE_SYSTEM_LAST_PICKED_DIRECTORY,

    /// Controls access to the getDisplayMedia API when {preferCurrentTab: true}
    /// is specified.
    CEF_CONTENT_SETTING_TYPE_DISPLAY_CAPTURE,

    /// Website setting to store permissions metadata granted to paths on the
    /// local file system via the File System Access API.
    /// |FILE_SYSTEM_WRITE_GUARD| is the corresponding "guard" setting.
    CEF_CONTENT_SETTING_TYPE_FILE_SYSTEM_ACCESS_CHOOSER_DATA,

    /// Stores a grant that allows a relying party to send a request for identity
    /// information to specified identity providers, potentially through any
    /// anti-tracking measures that would otherwise prevent it. This setting is
    /// associated with the relying party's origin.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_SHARING,

    /// Whether to use the v8 optimized JIT for running JavaScript on the page.
    CEF_CONTENT_SETTING_TYPE_JAVASCRIPT_JIT,

    /// Content setting which stores user decisions to allow loading a site over
    /// HTTP. Entries are added by hostname when a user bypasses the HTTPS-First
    /// Mode interstitial warning when a site does not support HTTPS. Allowed
    /// hosts are exact hostname matches -- subdomains of a host on the allowlist
    /// must be separately allowlisted.
    CEF_CONTENT_SETTING_TYPE_HTTP_ALLOWED,

    /// Stores metadata related to form fill, such as e.g. whether user data was
    /// autofilled on a specific website.
    CEF_CONTENT_SETTING_TYPE_FORMFILL_METADATA,

    /// Setting to indicate that there is an active federated sign-in session
    /// between a specified relying party and a specified identity provider for
    /// a specified account. When this is present it allows access to session
    /// management capabilities between the sites. This setting is associated
    /// with the relying party's origin.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_ACTIVE_SESSION,

    /// Setting to indicate whether Chrome should automatically apply darkening to
    /// web content.
    CEF_CONTENT_SETTING_TYPE_AUTO_DARK_WEB_CONTENT,

    /// Setting to indicate whether Chrome should request the desktop view of a
    /// site instead of the mobile one.
    CEF_CONTENT_SETTING_TYPE_REQUEST_DESKTOP_SITE,

    /// Setting to indicate whether browser should allow signing into a website
    /// via the browser FedCM API.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_API,

    /// Stores notification interactions per origin for the past 90 days.
    /// Interactions per origin are pre-aggregated over seven-day windows: A
    /// notification interaction or display is assigned to the last Monday
    /// midnight in local time.
    CEF_CONTENT_SETTING_TYPE_NOTIFICATION_INTERACTIONS,

    /// Website setting which stores the last reduced accept language negotiated
    /// for a given origin, to be used on future visits to the origin.
    CEF_CONTENT_SETTING_TYPE_REDUCED_ACCEPT_LANGUAGE,

    /// Website setting which is used for NotificationPermissionReviewService to
    /// store origin blocklist from review notification permissions feature.
    CEF_CONTENT_SETTING_TYPE_NOTIFICATION_PERMISSION_REVIEW,

    /// Website setting to store permissions granted to access particular devices
    /// in private network.
    CEF_CONTENT_SETTING_TYPE_PRIVATE_NETWORK_GUARD,
    CEF_CONTENT_SETTING_TYPE_PRIVATE_NETWORK_CHOOSER_DATA,

    /// Website setting which stores whether the browser has observed the user
    /// signing into an identity-provider based on observing the IdP-SignIn-Status
    /// HTTP header.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_IDENTITY_PROVIDER_SIGNIN_STATUS,

    /// Website setting which is used for UnusedSitePermissionsService to
    /// store revoked permissions of unused sites from unused site permissions
    /// feature.
    CEF_CONTENT_SETTING_TYPE_REVOKED_UNUSED_SITE_PERMISSIONS,

    /// Similar to STORAGE_ACCESS, but applicable at the page-level rather than
    /// being specific to a frame.
    CEF_CONTENT_SETTING_TYPE_TOP_LEVEL_STORAGE_ACCESS,

    /// Setting to indicate whether user has opted in to allowing auto re-authn
    /// via the FedCM API.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_AUTO_REAUTHN_PERMISSION,

    /// Website setting which stores whether the user has explicitly registered
    /// a website as an identity-provider.
    CEF_CONTENT_SETTING_TYPE_FEDERATED_IDENTITY_IDENTITY_PROVIDER_REGISTRATION,

    /// Content setting which is used to indicate whether anti-abuse functionality
    /// should be enabled.
    CEF_CONTENT_SETTING_TYPE_ANTI_ABUSE,

    /// Content setting used to indicate whether third-party storage partitioning
    /// should be enabled.
    CEF_CONTENT_SETTING_TYPE_THIRD_PARTY_STORAGE_PARTITIONING,

    /// Used to indicate whether HTTPS-First Mode is enabled on the hostname.
    CEF_CONTENT_SETTING_TYPE_HTTPS_ENFORCED,

    CEF_CONTENT_SETTING_TYPE_NUM_TYPES,
} cef_content_setting_types_t;


typedef struct _cef_preference_manager_t {
    ///
    /// Base structure.
    ///
    cef_base_ref_counted_t base;

    ///
    /// Returns true (1) if a preference with the specified |name| exists. This
    /// function must be called on the browser process UI thread.
    ///
    int(CEF_CALLBACK* has_preference)(struct _cef_preference_manager_t* self,
        const cef_string_t* name);

    ///
    /// Returns the value for the preference with the specified |name|. Returns
    /// NULL if the preference does not exist. The returned object contains a copy
    /// of the underlying preference value and modifications to the returned
    /// object will not modify the underlying preference value. This function must
    /// be called on the browser process UI thread.
    ///
    struct _cef_value_t* (CEF_CALLBACK* get_preference)(
        struct _cef_preference_manager_t* self,
        const cef_string_t* name);

    ///
    /// Returns all preferences as a dictionary. If |include_defaults| is true (1)
    /// then preferences currently at their default value will be included. The
    /// returned object contains a copy of the underlying preference values and
    /// modifications to the returned object will not modify the underlying
    /// preference values. This function must be called on the browser process UI
    /// thread.
    ///
    struct _cef_dictionary_value_t* (CEF_CALLBACK* get_all_preferences)(
        struct _cef_preference_manager_t* self,
        int include_defaults);

    ///
    /// Returns true (1) if the preference with the specified |name| can be
    /// modified using SetPreference. As one example preferences set via the
    /// command-line usually cannot be modified. This function must be called on
    /// the browser process UI thread.
    ///
    int(CEF_CALLBACK* can_set_preference)(struct _cef_preference_manager_t* self,
        const cef_string_t* name);

    ///
    /// Set the |value| associated with preference |name|. Returns true (1) if the
    /// value is set successfully and false (0) otherwise. If |value| is NULL the
    /// preference will be restored to its default value. If setting the
    /// preference fails then |error| will be populated with a detailed
    /// description of the problem. This function must be called on the browser
    /// process UI thread.
    ///
    int(CEF_CALLBACK* set_preference)(struct _cef_preference_manager_t* self,
        const cef_string_t* name,
        struct _cef_value_t* value,
        cef_string_t* error);
} cef_preference_manager_t;

typedef struct _cef_string_list_t* cef_string_list_t;

typedef enum {
    CEF_CONTENT_SETTING_VALUE_DEFAULT = 0,
    CEF_CONTENT_SETTING_VALUE_ALLOW,
    CEF_CONTENT_SETTING_VALUE_BLOCK,
    CEF_CONTENT_SETTING_VALUE_ASK,
    CEF_CONTENT_SETTING_VALUE_SESSION_ONLY,
    CEF_CONTENT_SETTING_VALUE_DETECT_IMPORTANT_CONTENT,

    CEF_CONTENT_SETTING_VALUE_NUM_VALUES
} cef_content_setting_values_t;

typedef struct _cef_request_context_t {
    ///
    /// Base structure.
    ///
    cef_preference_manager_t base;

    ///
    /// Returns true (1) if this object is pointing to the same context as |that|
    /// object.
    ///
    int(CEF_CALLBACK* is_same)(struct _cef_request_context_t* self,
        struct _cef_request_context_t* other);

    ///
    /// Returns true (1) if this object is sharing the same storage as |that|
    /// object.
    ///
    int(CEF_CALLBACK* is_sharing_with)(struct _cef_request_context_t* self,
        struct _cef_request_context_t* other);

    ///
    /// Returns true (1) if this object is the global context. The global context
    /// is used by default when creating a browser or URL request with a NULL
    /// context argument.
    ///
    int(CEF_CALLBACK* is_global)(struct _cef_request_context_t* self);

    ///
    /// Returns the handler for this context if any.
    ///
    struct _cef_request_context_handler_t* (CEF_CALLBACK* get_handler)(
        struct _cef_request_context_t* self);

    ///
    /// Returns the cache path for this object. If NULL an "incognito mode" in-
    /// memory cache is being used.
    ///
    // The resulting string must be freed by calling cef_string_userfree_free().
    cef_string_userfree_t(CEF_CALLBACK* get_cache_path)(
        struct _cef_request_context_t* self);

    ///
    /// Returns the cookie manager for this object. If |callback| is non-NULL it
    /// will be executed asnychronously on the UI thread after the manager's
    /// storage has been initialized.
    ///
    struct _cef_cookie_manager_t* (CEF_CALLBACK* get_cookie_manager)(
        struct _cef_request_context_t* self,
        struct _cef_completion_callback_t* callback);

    ///
    /// Register a scheme handler factory for the specified |scheme_name| and
    /// optional |domain_name|. An NULL |domain_name| value for a standard scheme
    /// will cause the factory to match all domain names. The |domain_name| value
    /// will be ignored for non-standard schemes. If |scheme_name| is a built-in
    /// scheme and no handler is returned by |factory| then the built-in scheme
    /// handler factory will be called. If |scheme_name| is a custom scheme then
    /// you must also implement the cef_app_t::on_register_custom_schemes()
    /// function in all processes. This function may be called multiple times to
    /// change or remove the factory that matches the specified |scheme_name| and
    /// optional |domain_name|. Returns false (0) if an error occurs. This
    /// function may be called on any thread in the browser process.
    ///
    int(CEF_CALLBACK* register_scheme_handler_factory)(
        struct _cef_request_context_t* self,
        const cef_string_t* scheme_name,
        const cef_string_t* domain_name,
        struct _cef_scheme_handler_factory_t* factory);

    ///
    /// Clear all registered scheme handler factories. Returns false (0) on error.
    /// This function may be called on any thread in the browser process.
    ///
    int(CEF_CALLBACK* clear_scheme_handler_factories)(
        struct _cef_request_context_t* self);

    ///
    /// Clears all certificate exceptions that were added as part of handling
    /// cef_request_handler_t::on_certificate_error(). If you call this it is
    /// recommended that you also call close_all_connections() or you risk not
    /// being prompted again for server certificates if you reconnect quickly. If
    /// |callback| is non-NULL it will be executed on the UI thread after
    /// completion.
    ///
    void(CEF_CALLBACK* clear_certificate_exceptions)(
        struct _cef_request_context_t* self,
        struct _cef_completion_callback_t* callback);

    ///
    /// Clears all HTTP authentication credentials that were added as part of
    /// handling GetAuthCredentials. If |callback| is non-NULL it will be executed
    /// on the UI thread after completion.
    ///
    void(CEF_CALLBACK* clear_http_auth_credentials)(
        struct _cef_request_context_t* self,
        struct _cef_completion_callback_t* callback);

    ///
    /// Clears all active and idle connections that Chromium currently has. This
    /// is only recommended if you have released all other CEF objects but don't
    /// yet want to call cef_shutdown(). If |callback| is non-NULL it will be
    /// executed on the UI thread after completion.
    ///
    void(CEF_CALLBACK* close_all_connections)(
        struct _cef_request_context_t* self,
        struct _cef_completion_callback_t* callback);

    ///
    /// Attempts to resolve |origin| to a list of associated IP addresses.
    /// |callback| will be executed on the UI thread after completion.
    ///
    void(CEF_CALLBACK* resolve_host)(struct _cef_request_context_t* self,
        const cef_string_t* origin,
        struct _cef_resolve_callback_t* callback);

    ///
    /// Load an extension.
    ///
    /// If extension resources will be read from disk using the default load
    /// implementation then |root_directory| should be the absolute path to the
    /// extension resources directory and |manifest| should be NULL. If extension
    /// resources will be provided by the client (e.g. via cef_request_handler_t
    /// and/or cef_extension_handler_t) then |root_directory| should be a path
    /// component unique to the extension (if not absolute this will be internally
    /// prefixed with the PK_DIR_RESOURCES path) and |manifest| should contain the
    /// contents that would otherwise be read from the "manifest.json" file on
    /// disk.
    ///
    /// The loaded extension will be accessible in all contexts sharing the same
    /// storage (HasExtension returns true (1)). However, only the context on
    /// which this function was called is considered the loader (DidLoadExtension
    /// returns true (1)) and only the loader will receive
    /// cef_request_context_handler_t callbacks for the extension.
    ///
    /// cef_extension_handler_t::OnExtensionLoaded will be called on load success
    /// or cef_extension_handler_t::OnExtensionLoadFailed will be called on load
    /// failure.
    ///
    /// If the extension specifies a background script via the "background"
    /// manifest key then cef_extension_handler_t::OnBeforeBackgroundBrowser will
    /// be called to create the background browser. See that function for
    /// additional information about background scripts.
    ///
    /// For visible extension views the client application should evaluate the
    /// manifest to determine the correct extension URL to load and then pass that
    /// URL to the cef_browser_host_t::CreateBrowser* function after the extension
    /// has loaded. For example, the client can look for the "browser_action"
    /// manifest key as documented at
    /// https://developer.chrome.com/extensions/browserAction. Extension URLs take
    /// the form "chrome-extension://<extension_id>/<path>".
    ///
    /// Browsers that host extensions differ from normal browsers as follows:
    ///  - Can access chrome.* JavaScript APIs if allowed by the manifest. Visit
    ///    chrome://extensions-support for the list of extension APIs currently
    ///    supported by CEF.
    ///  - Main frame navigation to non-extension content is blocked.
    ///  - Pinch-zooming is disabled.
    ///  - CefBrowserHost::GetExtension returns the hosted extension.
    ///  - CefBrowserHost::IsBackgroundHost returns true for background hosts.
    ///
    /// See https://developer.chrome.com/extensions for extension implementation
    /// and usage documentation.
    ///
    void(CEF_CALLBACK* load_extension)(struct _cef_request_context_t* self,
        const cef_string_t* root_directory,
        struct _cef_dictionary_value_t* manifest,
        struct _cef_extension_handler_t* handler);

    ///
    /// Returns true (1) if this context was used to load the extension identified
    /// by |extension_id|. Other contexts sharing the same storage will also have
    /// access to the extension (see HasExtension). This function must be called
    /// on the browser process UI thread.
    ///
    int(CEF_CALLBACK* did_load_extension)(struct _cef_request_context_t* self,
        const cef_string_t* extension_id);

    ///
    /// Returns true (1) if this context has access to the extension identified by
    /// |extension_id|. This may not be the context that was used to load the
    /// extension (see DidLoadExtension). This function must be called on the
    /// browser process UI thread.
    ///
    int(CEF_CALLBACK* has_extension)(struct _cef_request_context_t* self,
        const cef_string_t* extension_id);

    ///
    /// Retrieve the list of all extensions that this context has access to (see
    /// HasExtension). |extension_ids| will be populated with the list of
    /// extension ID values. Returns true (1) on success. This function must be
    /// called on the browser process UI thread.
    ///
    int(CEF_CALLBACK* get_extensions)(struct _cef_request_context_t* self,
        cef_string_list_t extension_ids);

    ///
    /// Returns the extension matching |extension_id| or NULL if no matching
    /// extension is accessible in this context (see HasExtension). This function
    /// must be called on the browser process UI thread.
    ///
    struct _cef_extension_t* (CEF_CALLBACK* get_extension)(
        struct _cef_request_context_t* self,
        const cef_string_t* extension_id);

    ///
    /// Returns the MediaRouter object associated with this context.  If
    /// |callback| is non-NULL it will be executed asnychronously on the UI thread
    /// after the manager's context has been initialized.
    ///
    struct _cef_media_router_t* (CEF_CALLBACK* get_media_router)(
        struct _cef_request_context_t* self,
        struct _cef_completion_callback_t* callback);

    ///
    /// Returns the current value for |content_type| that applies for the
    /// specified URLs. If both URLs are NULL the default value will be returned.
    /// Returns nullptr if no value is configured. Must be called on the browser
    /// process UI thread.
    ///
    struct _cef_value_t* (CEF_CALLBACK* get_website_setting)(
        struct _cef_request_context_t* self,
        const cef_string_t* requesting_url,
        const cef_string_t* top_level_url,
        cef_content_setting_types_t content_type);

    ///
    /// Sets the current value for |content_type| for the specified URLs in the
    /// default scope. If both URLs are NULL, and the context is not incognito,
    /// the default value will be set. Pass nullptr for |value| to remove the
    /// default value for this content type.
    ///
    /// WARNING: Incorrect usage of this function may cause instability or
    /// security issues in Chromium. Make sure that you first understand the
    /// potential impact of any changes to |content_type| by reviewing the related
    /// source code in Chromium. For example, if you plan to modify
    /// CEF_CONTENT_SETTING_TYPE_POPUPS, first review and understand the usage of
    /// ContentSettingsType::POPUPS in Chromium:
    /// https://source.chromium.org/search?q=ContentSettingsType::POPUPS
    ///
    void(CEF_CALLBACK* set_website_setting)(
        struct _cef_request_context_t* self,
        const cef_string_t* requesting_url,
        const cef_string_t* top_level_url,
        cef_content_setting_types_t content_type,
        struct _cef_value_t* value);

    ///
    /// Returns the current value for |content_type| that applies for the
    /// specified URLs. If both URLs are NULL the default value will be returned.
    /// Returns CEF_CONTENT_SETTING_VALUE_DEFAULT if no value is configured. Must
    /// be called on the browser process UI thread.
    ///
    cef_content_setting_values_t(CEF_CALLBACK* get_content_setting)(
        struct _cef_request_context_t* self,
        const cef_string_t* requesting_url,
        const cef_string_t* top_level_url,
        cef_content_setting_types_t content_type);

    ///
    /// Sets the current value for |content_type| for the specified URLs in the
    /// default scope. If both URLs are NULL, and the context is not incognito,
    /// the default value will be set. Pass CEF_CONTENT_SETTING_VALUE_DEFAULT for
    /// |value| to use the default value for this content type.
    ///
    /// WARNING: Incorrect usage of this function may cause instability or
    /// security issues in Chromium. Make sure that you first understand the
    /// potential impact of any changes to |content_type| by reviewing the related
    /// source code in Chromium. For example, if you plan to modify
    /// CEF_CONTENT_SETTING_TYPE_POPUPS, first review and understand the usage of
    /// ContentSettingsType::POPUPS in Chromium:
    /// https://source.chromium.org/search?q=ContentSettingsType::POPUPS
    ///
    void(CEF_CALLBACK* set_content_setting)(
        struct _cef_request_context_t* self,
        const cef_string_t* requesting_url,
        const cef_string_t* top_level_url,
        cef_content_setting_types_t content_type,
        cef_content_setting_values_t value);
} cef_request_context_t;

typedef cef_urlrequest_t* (*PCEF_URLREQUEST_CREATE_T)(
        cef_request_t* request,
        struct _cef_urlrequest_client_t* client,
        cef_request_context_t* request_context);

typedef void (*PCEF_STRING_USERFREE_UTF16_FREE_T)(cef_string_userfree_utf16_t str);