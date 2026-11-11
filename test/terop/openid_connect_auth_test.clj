(ns terop.openid-connect-auth-test
  (:require [clojure.test :refer [deftest is testing]]
            [terop.openid-connect-auth :as oidc])
  (:import com.sun.net.httpserver.HttpHandler
           com.sun.net.httpserver.HttpServer
           java.net.InetSocketAddress
           java.nio.charset.StandardCharsets
           org.jose4j.jwk.RsaJwkGenerator
           org.jose4j.jws.AlgorithmIdentifiers
           org.jose4j.jws.JsonWebSignature
           org.jose4j.json.JsonUtil
           org.jose4j.keys.resolvers.JwksVerificationKeyResolver))

;; Helpers

(def ^:private subject-uuid "9f830498-1c36-4cfe-b564-e8b0318fa397")
(def ^:private client-id "env-logger-browser")

(defn- now-seconds [] (quot (System/currentTimeMillis) 1000))

(defn- generate-key [kid]
  (doto (RsaJwkGenerator/generateJwk 2048)
    (.setKeyId kid)))

(defn- sign
  "Signs the claims map as a compact JWT with the RSA key."
  [jwk claims]
  (let [jws (JsonWebSignature.)]
    (.setPayload jws (JsonUtil/toJson claims))
    (.setKey jws (.getPrivateKey jwk))
    (.setKeyIdHeaderValue jws (.getKeyId jwk))
    (.setAlgorithmHeaderValue jws AlgorithmIdentifiers/RSA_USING_SHA256)
    (.getCompactSerialization jws)))

(defn- access-claims
  "Default valid access token claims for the issuer. Pass nil values to drop claims."
  [issuer overrides]
  (let [now (now-seconds)]
    (into {} (remove (comp nil? val))
          (merge {"iss" issuer
                  "aud" ["account"]
                  "sub" subject-uuid
                  "iat" now
                  "exp" (+ now 300)}
                 overrides))))

(defn- id-claims
  [issuer overrides]
  (let [now (now-seconds)]
    (into {} (remove (comp nil? val))
          (merge {"iss" issuer
                  "aud" client-id
                  "sub" subject-uuid
                  "iat" now
                  "exp" (+ now 300)}
                 overrides))))

(defn- resolver-for [jwk]
  (JwksVerificationKeyResolver. [jwk]))

(def ^:private issuer "https://idp.test/realms/webapps")

(def ^:private auth-config
  {:base-url issuer
   :client-id client-id
   :authorised-subject-uuids [subject-uuid]})

(defn- serve-idp
  "Starts a local HTTP IdP serving discovery and JWKS. Returns a map with the
  server, base URL and issuer. The issuer defaults to the server base URL.
  Options: :issuer-override, :trailing-slash-issuer?, :no-discovery? (serve
  only the Keycloak style certs path, like an IdP without a discovery
  document) and :no-end-session? (omit end_session_endpoint)."
  [jwk {:keys [issuer-override trailing-slash-issuer? no-discovery?
               no-end-session?]}]
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
        base (str "http://127.0.0.1:" (.getPort (.getAddress server)))
        issuer* (or issuer-override
                    (cond-> base trailing-slash-issuer? (str "/")))
        jwks-body (str "{\"keys\":[" (.toJson jwk
                                              org.jose4j.jwk.JsonWebKey$OutputControlLevel/PUBLIC_ONLY)
                       "]}")
        routes (cond-> {"/jwks" jwks-body
                        "/protocol/openid-connect/certs" jwks-body}
                 (not no-discovery?)
                 (assoc "/.well-known/openid-configuration"
                        (JsonUtil/toJson
                         (cond-> {"issuer" issuer*
                                  "jwks_uri" (str base "/jwks")}
                           (not no-end-session?)
                           (assoc "end_session_endpoint" (str base "/logout"))))))]
    (.createContext server "/"
                    (reify HttpHandler
                      (handle [_ exchange]
                        (let [body (get routes (.getPath (.getRequestURI exchange)))
                              bytes (.getBytes (or body "") StandardCharsets/UTF_8)]
                          (.add (.getResponseHeaders exchange) "Content-Type"
                                "application/json")
                          (.sendResponseHeaders exchange (if body 200 404)
                                                (count bytes))
                          (with-open [out (.getResponseBody exchange)]
                            (.write out bytes))))))
    (.start server)
    {:server server :base base :issuer issuer*}))

(defn- seed-discovery!
  "Puts a discovery document straight into the discovery cache."
  [issuer doc]
  (swap! @#'oidc/discovery-cache assoc issuer
         {:doc doc :at (System/currentTimeMillis)}))

(defn- with-idp
  "Calls f with a running local IdP and stops it afterwards."
  [jwk opts f]
  (let [idp (serve-idp jwk opts)]
    (try
      (f idp)
      (finally (.stop (:server idp) 0)))))

;; Access token validation (key resolver seam, no network)

(deftest access-token-valid-test
  (testing "a correctly signed, unexpired token for an authorised subject is accepted"
    (let [jwk (generate-key "kid-1")
          token (sign jwk (access-claims issuer {}))]
      (is (true? (oidc/check-access-token auth-config (resolver-for jwk) token))))))

(deftest access-token-wrong-audience-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (access-claims issuer {"aud" ["other"]}))]
    (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) token)))))

(deftest access-token-configured-audience-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (access-claims issuer {"aud" ["my-api"]}))
        cfg (assoc auth-config :access-token-audience "my-api")]
    (testing "a string audience from config is honoured"
      (is (true? (oidc/check-access-token cfg (resolver-for jwk) token))))
    (testing "the default audience account is no longer accepted"
      (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) token))))))

(deftest access-token-wrong-issuer-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (access-claims issuer {"iss" "https://evil.test/realms/x"}))]
    (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) token)))))

(deftest access-token-expired-test
  (let [jwk (generate-key "kid-1")
        now (now-seconds)
        token (sign jwk (access-claims issuer {"iat" (- now 900)
                                               "exp" (- now 600)}))]
    (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) token)))))

(deftest access-token-bad-signature-test
  (let [signing-key (generate-key "kid-1")
        trusted-key (generate-key "kid-1")
        token (sign signing-key (access-claims issuer {}))]
    (is (nil? (oidc/check-access-token auth-config (resolver-for trusted-key) token)))))

(deftest access-token-unauthorised-subject-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (access-claims issuer {"sub" "00000000-0000-0000-0000-000000000000"}))]
    (is (false? (oidc/check-access-token auth-config (resolver-for jwk) token)))))

(deftest access-token-missing-or-garbage-test
  (let [jwk (generate-key "kid-1")]
    (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) nil)))
    (is (nil? (oidc/check-access-token auth-config (resolver-for jwk) "not-a-jwt")))))

;; ID token validation

(deftest id-token-valid-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (id-claims issuer {}))]
    (is (true? (oidc/check-id-token auth-config (resolver-for jwk) token)))))

(deftest id-token-wrong-audience-test
  (let [jwk (generate-key "kid-1")
        token (sign jwk (id-claims issuer {"aud" "some-other-client"}))]
    (is (nil? (oidc/check-id-token auth-config (resolver-for jwk) token)))))

(deftest id-token-clock-skew-test
  (let [jwk (generate-key "kid-1")
        now (now-seconds)
        expired-token (sign jwk (id-claims issuer {"iat" (- now 900)
                                                   "exp" (- now 600)}))]
    (testing "a token expired 10 minutes ago is rejected with a 60 second skew"
      (is (nil? (oidc/check-id-token (assoc auth-config :id-token-clock-skew 60)
                                     (resolver-for jwk) expired-token))))
    (testing "the default skew accepts a token expired 10 minutes ago"
      (is (true? (oidc/check-id-token auth-config (resolver-for jwk) expired-token))))))

;; End to end against a local IdP (discovery, JWKS, logout)

(deftest end-to-end-access-ok-test
  (let [jwk (generate-key "kid-e2e")]
    (with-idp jwk {}
      (fn [{:keys [issuer base]}]
        (let [cfg {:base-url issuer
                   :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims issuer {}))]
          (testing "discovery + JWKS from the IdP accept a valid bearer token"
            (is (true? (oidc/access-ok? cfg {:headers {"bearer" token}}))))
          (testing "a token signed with another key is rejected"
            (let [other (generate-key "kid-e2e")
                  bad (sign other (access-claims issuer {}))]
              (is (nil? (oidc/access-ok? cfg {:headers {"bearer" bad}})))))
          (testing "logout URL comes from discovery end_session_endpoint"
            (is (= (str base "/logout?post_logout_redirect_uri="
                        "http%3A%2F%2Fapp.test%2Flogout&client_id=env-logger-browser")
                   (oidc/make-logout-url "http://app.test/logout" cfg)))))))))

(deftest discovery-issuer-mismatch-test
  (let [jwk (generate-key "kid-mismatch")]
    (with-idp jwk {:issuer-override "https://other.test/realms/x"}
      (fn [{:keys [base]}]
        (let [cfg {:base-url base :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims base {}))]
          (testing "a discovery document with a different issuer is not used"
            (is (nil? (oidc/discovery base)))
            (is (nil? (oidc/access-ok? cfg {:headers {"bearer" token}})))
            (is (nil? (oidc/make-logout-url "http://app.test/logout" cfg)))))))))

(deftest discovery-with-trailing-slash-issuer-test
  (let [jwk (generate-key "kid-trailing-slash")]
    (with-idp jwk {:trailing-slash-issuer? true}
      (fn [{:keys [issuer]}]
        (let [cfg {:base-url issuer
                   :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims issuer {}))]
          (testing "the discovery URL contains exactly one path separator"
            (is (true? (oidc/access-ok? cfg {:headers {"bearer" token}})))))))))

(deftest insecure-discovered-jwks-test
  (let [jwk (generate-key "kid-insecure-jwks")
        issuer "https://secure-idp.test"]
    (with-idp jwk {}
      (fn [{:keys [base]}]
        (seed-discovery! issuer {"issuer" issuer "jwks_uri" (str base "/jwks")})
        (let [cfg {:base-url issuer
                   :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims issuer {}))]
          (testing "an HTTPS issuer cannot supply keys over HTTP"
            (is (nil? (oidc/access-ok? cfg
                                       {:headers {"bearer" token}})))))))))

(deftest discovery-failure-test
  (let [unreachable {:base-url "http://127.0.0.1:1" :client-id client-id
                     :authorised-subject-uuids [subject-uuid]}
        jwk (generate-key "kid-down")
        token (sign jwk (access-claims "http://127.0.0.1:1" {}))]
    (testing "validation denies when the IdP cannot be reached"
      (is (nil? (oidc/access-ok? unreachable {:headers {"bearer" token}}))))
    (testing "logout falls back to the Keycloak path"
      (is (= (str "http://127.0.0.1:1/protocol/openid-connect/logout"
                  "?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Flogout"
                  "&client_id=env-logger-browser")
             (oidc/make-logout-url "http://app.test/logout" unreachable))))
    (testing "an explicit logout-url override still works without discovery"
      (is (= "https://idp.test/logout?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Fdo-logout&client_id=env-logger-browser"
             (oidc/make-logout-url "http://app.test/do-logout"
                                   (assoc unreachable
                                          :logout-url "https://idp.test/logout")))))))

(deftest keycloak-fallback-without-discovery-test
  (let [jwk (generate-key "kid-keycloak")]
    (with-idp jwk {:no-discovery? true}
      (fn [{:keys [base]}]
        (let [cfg {:base-url base :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims base {}))]
          (testing "keys are read from the Keycloak certs path"
            (is (true? (oidc/access-ok? cfg {:headers {"bearer" token}}))))
          (testing "the logout URL uses the Keycloak logout path"
            (is (= (str base "/protocol/openid-connect/logout"
                        "?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Flogout"
                        "&client_id=env-logger-browser")
                   (oidc/make-logout-url "http://app.test/logout" cfg)))))))))

(deftest discovery-cached-after-success-test
  (let [jwk (generate-key "kid-cache")
        issuer-seen (atom nil)]
    (with-idp jwk {}
      (fn [{:keys [issuer]}]
        (reset! issuer-seen issuer)
        (is (some? (oidc/discovery issuer)))))
    (testing "a successful discovery result is served from cache after the IdP stops"
      (is (some? (oidc/discovery @issuer-seen))))))

(defn- counting-fetch
  "Wraps the real fetch-json, counting calls in the returned atom."
  []
  (let [calls (atom 0)
        real @#'oidc/fetch-json]
    {:calls calls
     :fetch (fn [url] (swap! calls inc) (real url))}))

(defn- with-clock
  "Runs f with the discovery clock under the control of the clock atom. The
  discovery cache is emptied before and after, so entries stamped with the
  fake time never leak into other tests."
  [clock fetch f]
  (reset! @#'oidc/discovery-cache {})
  (try
    (with-redefs-fn {#'oidc/now-ms (fn [] @clock)
                     #'oidc/fetch-json fetch}
      f)
    (finally (reset! @#'oidc/discovery-cache {}))))

(deftest discovery-failure-is-cached-briefly-test
  (let [clock (atom 1000000)
        {:keys [calls fetch]} (counting-fetch)
        url "http://127.0.0.1:1"]
    (with-clock clock fetch
      (fn []
        (is (nil? (oidc/discovery url)))
        (is (nil? (oidc/discovery url)))
        (testing "a failure is remembered, so the IdP is not asked again"
          (is (= 1 @calls)))
        (swap! clock + 31000)
        (is (nil? (oidc/discovery url)))
        (testing "the failure expires after a short while"
          (is (= 2 @calls)))))))

(deftest discovery-document-expires-test
  (let [jwk (generate-key "kid-ttl")
        clock (atom 1000000)
        {:keys [calls fetch]} (counting-fetch)]
    (with-idp jwk {}
      (fn [{:keys [issuer server]}]
        (with-clock clock fetch
          (fn []
            (is (some? (oidc/discovery issuer)))
            (swap! clock + 3000000)
            (is (some? (oidc/discovery issuer)))
            (testing "the document is reused within the TTL"
              (is (= 1 @calls)))
            (swap! clock + 700000)
            (is (some? (oidc/discovery issuer)))
            (testing "the document is refetched after the TTL"
              (is (= 2 @calls)))
            (.stop server 0)
            (swap! clock + 3700000)
            (testing "an expired document is still used while the IdP is down"
              (is (some? (oidc/discovery issuer))))
            (testing "a refresh is retried soon after the failure"
              (is (= 3 @calls))
              (swap! clock + 31000)
              (oidc/discovery issuer)
              (is (= 4 @calls)))))))))

(deftest failed-id-token-keeps-existing-login-test
  (let [jwk (generate-key "kid-login")]
    (with-idp jwk {}
      (fn [{:keys [issuer]}]
        (let [cfg {:base-url issuer :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              request-with (fn [token] {:query-params {"id-token" token}})]
          (try
            (reset! oidc/id-token-valid false)
            (is (true? (oidc/receive-and-check-id-token
                        cfg (request-with (sign jwk (id-claims issuer {}))))))
            (is (true? @oidc/id-token-valid))
            (testing "an invalid ID token does not log out the existing session"
              (is (nil? (oidc/receive-and-check-id-token
                         cfg (request-with "not-a-jwt"))))
              (is (true? @oidc/id-token-valid)))
            (finally (reset! oidc/id-token-valid false))))))))

(deftest logout-without-end-session-test
  (let [jwk (generate-key "kid-no-end-session")]
    (with-idp jwk {:no-end-session? true}
      (fn [{:keys [base]}]
        (testing "a discovery document without end_session_endpoint yields nil"
          (is (nil? (oidc/make-logout-url "http://app.test/do-logout"
                                          {:base-url base
                                           :client-id client-id}))))))))

(deftest jwks-url-override-test
  (let [jwk (generate-key "kid-override")]
    (with-idp jwk {:no-discovery? true}
      (fn [{:keys [base]}]
        (let [cfg {:base-url "https://never-contacted.test/realms/x"
                   :jwks-url (str base "/jwks")
                   :client-id client-id
                   :authorised-subject-uuids [subject-uuid]}
              token (sign jwk (access-claims (:base-url cfg) {}))]
          (testing "the configured JWKS URL is used without discovery"
            (is (true? (oidc/access-ok? cfg {:headers {"bearer" token}})))))))))

(deftest unreachable-jwks-denies-test
  (let [jwk (generate-key "kid-jwks-down")
        issuer "http://jwks-down.test"
        token (sign jwk (access-claims issuer {}))]
    (seed-discovery! issuer {"issuer" issuer "jwks_uri" "http://127.0.0.1:1/jwks"})
    (testing "a JWKS fetch failure is a denial, not an exception"
      (is (nil? (oidc/access-ok? {:base-url issuer
                                  :client-id client-id
                                  :authorised-subject-uuids [subject-uuid]}
                                 {:headers {"bearer" token}}))))))

(deftest malformed-url-denies-test
  (let [jwk (generate-key "kid-malformed")
        token (sign jwk (access-claims issuer {}))]
    (testing "a malformed JWKS URL is a denial, not an exception"
      (is (nil? (oidc/access-ok? (assoc auth-config :jwks-url "http://bad host/jwks")
                                 {:headers {"bearer" token}}))))
    (testing "a malformed issuer URL is a denial, not an exception"
      (is (nil? (oidc/access-ok? (assoc auth-config :base-url "http://bad host")
                                 {:headers {"bearer" token}}))))))

(deftest resolver-exception-denies-test
  (let [jwk (generate-key "kid-throwing")
        token (sign jwk (access-claims issuer {}))
        throwing (reify org.jose4j.keys.resolvers.VerificationKeyResolver
                   (resolveKey [_ _ _] (throw (RuntimeException. "boom"))))]
    (is (nil? (oidc/check-access-token auth-config throwing token)))
    (is (nil? (oidc/check-id-token auth-config throwing token)))))

(deftest access-token-audience-config-test
  (let [jwk (generate-key "kid-aud")
        token (sign jwk (access-claims issuer {}))
        wrong (sign jwk (access-claims issuer {"aud" ["other"]}))]
    (doseq [value [nil [] ()]]
      (testing (str "audience " (pr-str value) " falls back to the default")
        (let [cfg (assoc auth-config :access-token-audience value)]
          (is (true? (oidc/check-access-token cfg (resolver-for jwk) token)))
          (is (nil? (oidc/check-access-token cfg (resolver-for jwk) wrong))))))))

(deftest logout-endpoint-with-query-and-fragment-test
  (is (= (str "https://idp.test/logout?tenant=example"
              "&post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Flogout"
              "&client_id=env-logger-browser#complete")
         (oidc/make-logout-url
          "http://app.test/logout"
          {:base-url issuer
           :client-id client-id
           :logout-url "https://idp.test/logout?tenant=example#complete"}))))
