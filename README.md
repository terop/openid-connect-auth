# openid-connect-auth

This is a small library to validate OpenID Connect JWTs. This is
specifically meant for my own project and not general usage.

## Usage

See `src/terop/openid_connect_auth.clj` for which functions are available
and how they are meant to be used.

Run the project's dummy tests:

    $ clojure -T:build test

Run the project's CI pipeline and build a JAR:

    $ clojure -T:build ci

This will produce an updated `pom.xml` file with synchronised dependencies inside the `META-INF`
directory inside `target/classes` and the JAR in `target`. You can update the version (and SCM tag)
information in generated `pom.xml` by updating `build.clj`.

Install it locally (requires the `ci` task be run first):

    $ clojure -T:build install

## License

Copyright © 2025 Tero Paloheimo

Distributed under the Eclipse Public License version 1.0.
