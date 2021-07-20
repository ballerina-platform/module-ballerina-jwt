## Package Overview

The `jwt` library is one of the standard library modules of the <a target="_blank" href="https://ballerina.io/">Ballerina</a> language.

This module provides a framework for authentication/authorization with JWTs and generation/validation of JWTs as specified in the <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519</a>, <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515</a>, and <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a>.

JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure, enabling the claims to be signed digitally or protecting the integrity with a Message Authentication Code(MAC) and/or encrypted.

The Ballerina `jwt` module facilitates auth providers that are to be used by the clients and listeners of different protocol connectors. Also, it provides the APIs for issuing a self-signed JWT and validating a JWT.

### Report Issues

To report bugs, request new features, start new discussions, view project boards, etc., go to the <a target="_blank" href="https://github.com/ballerina-platform/ballerina-standard-library">Ballerina standard library parent repository</a>.

### Useful Links

- Chat live with us via our <a target="_blank" href="https://ballerina.io/community/slack/">Slack channel</a>.
- Post all technical questions on Stack Overflow with the <a target="_blank" href="https://stackoverflow.com/questions/tagged/ballerina">#ballerina</a> tag.
