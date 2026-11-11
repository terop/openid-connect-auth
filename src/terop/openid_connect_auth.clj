(ns terop.openid-connect-auth
  "Validation of OpenID Connect JWTs.

  The auth config map understands these keys:

  :base-url                  Issuer URL of the IdP (required).
  :client-id                 Client ID, the expected ID token audience and the
                             client_id sent on logout.
  :authorised-subject-uuids  Subjects that are allowed in.
  :access-token-audience     String or collection of expected access token
                             audiences. Default [\"account\"] (Keycloak).
  :id-token-clock-skew       Allowed clock skew for ID tokens in seconds.
                             Default 300 (5 minutes). ID tokens are accepted
                             this long after their exp, so a leaked token stays
                             usable for that long. Clients that re-validate a
                             stored ID token (e.g. after a backend restart)
                             should keep it fresh from refresh responses rather
                             than raise this value.
  :jwks-url                  Overrides the JWKS location.
  :logout-url                Overrides the end-session endpoint.

  Endpoints are resolved from the IdP's discovery document. If the discovery
  document cannot be fetched, the Keycloak paths under :base-url are used
  instead. A discovery document whose issuer does not match :base-url is
  rejected and there is no fallback in that case."
  (:require [clojure.string :as str]
            [taoensso.timbre :refer [error warn]])
  (:import java.net.URI
           java.net.URLEncoder
           (java.net.http HttpClient HttpRequest HttpResponse
                          HttpResponse$BodyHandlers)
           java.nio.charset.StandardCharsets
           java.time.Duration
           java.util.concurrent.ConcurrentHashMap
           java.util.function.Function
           org.jose4j.jwk.HttpsJwks
           org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
           org.jose4j.jwt.JwtClaims
           org.jose4j.json.JsonUtil
           (org.jose4j.jwt.consumer InvalidJwtException JwtConsumer JwtConsumerBuilder)))

(def id-token-valid (atom false))

;; Reproduces the original Keycloak behaviour so existing configs keep working
(def ^:private default-access-token-audience ["account"])
(def ^:private default-id-token-clock-skew 300)

(def ^:private ^HttpClient http-client
  (-> (HttpClient/newBuilder)
      (.connectTimeout (Duration/ofSeconds 10))
      (.build)))

;; Discovery

(def ^:private discovery-ttl-ms
  "How long a discovery document is used before it is refreshed."
  (* 60 60 1000))

(def ^:private discovery-failure-ttl-ms
  "How long a failed discovery is remembered before trying again. This keeps
  requests from blocking on a dead IdP."
  (* 30 1000))

(defn- now-ms [] (System/currentTimeMillis))

(defn- fetch-json
  "GET the URL and parse the JSON body. Returns nil on any failure."
  [url]
  (try
    (let [request (-> (HttpRequest/newBuilder (URI/create url))
                      (.timeout (Duration/ofSeconds 10))
                      (.GET)
                      (.build))
          ^HttpResponse response (.send http-client request
                                        (HttpResponse$BodyHandlers/ofString))]
      (if (= 200 (.statusCode response))
        (JsonUtil/parseJson (.body response))
        (warn "Fetching JSON from" url "failed with status"
              (.statusCode response))))
    (catch Exception e
      (warn "Fetching JSON from" url "failed:" (str e))
      nil)))

(defn- strip-trailing-slashes [url]
  (str/replace url #"/+$" ""))

(defn- fetch-discovery
  "Returns {:doc doc} or {:error :unavailable} / {:error :mismatch}."
  [issuer]
  (let [doc (fetch-json (str (strip-trailing-slashes issuer)
                             "/.well-known/openid-configuration"))]
    (cond
      ;; jose4j parses to a java.util.Map, not a Clojure map
      (not (instance? java.util.Map doc)) {:error :unavailable}
      (not= issuer (get doc "issuer"))
      (do (error "Discovery issuer" (get doc "issuer")
                 "does not match configured issuer" issuer)
          {:error :mismatch})
      :else {:doc doc})))

;; issuer -> {:doc doc | :error kw, :at timestamp-ms}
(def ^:private discovery-cache (atom {}))
(def ^:private discovery-lock (Object.))

(defn- fresh? [{:keys [doc at] :as entry}]
  (and entry
       (< (- (now-ms) at) (if doc discovery-ttl-ms discovery-failure-ttl-ms))))

(defn- discovery-result
  "Returns {:doc doc} or {:error :unavailable|:mismatch} for the issuer. Both
  outcomes are cached, successes for an hour and failures for a short while.
  When a refresh fails because the IdP is unreachable, the previous document
  keeps being used."
  [issuer]
  (letfn [(fresh-entry [] (let [entry (get @discovery-cache issuer)]
                            (when (fresh? entry) entry)))]
    (or (fresh-entry)
        ;; One fetch at a time, so concurrent requests do not all hit the IdP
        (locking discovery-lock
          (or (fresh-entry)
              (let [stale (get @discovery-cache issuer)
                    result (fetch-discovery issuer)
                    entry (if (and (= :unavailable (:error result)) (:doc stale))
                            ;; Retry after the failure TTL, not a full TTL
                            (assoc stale :at (- (now-ms) (- discovery-ttl-ms
                                                            discovery-failure-ttl-ms)))
                            (assoc result :at (now-ms)))]
                (swap! discovery-cache assoc issuer entry)
                entry))))))

(defn discovery
  "Returns the OIDC discovery document for the issuer, or nil if it cannot be
  fetched or its issuer does not match."
  [issuer]
  (when issuer
    (:doc (discovery-result issuer))))

(defn- idp-endpoint
  "Resolves an IdP endpoint: the config override if present, else the field in
  the discovery document, else the Keycloak path if the discovery document is
  unavailable. Returns nil if the IdP does not offer the endpoint."
  [auth-config override-key discovery-key keycloak-path]
  (or (get auth-config override-key)
      (when-let [issuer (:base-url auth-config)]
        (let [{:keys [doc error]} (discovery-result issuer)]
          (cond
            doc (get doc discovery-key)
            (= :unavailable error) (str (strip-trailing-slashes issuer)
                                        "/protocol/openid-connect/"
                                        keycloak-path))))))

;; Key resolution

(def ^:private ^ConcurrentHashMap jwks-cache (ConcurrentHashMap.))

(defn- https-jwks
  "One HttpsJwks instance per JWKS URL so keys are cached between requests."
  [jwks-uri]
  (.computeIfAbsent jwks-cache jwks-uri
                    (reify Function
                      (apply [_ uri] (HttpsJwks. ^String uri)))))

(defn- uri-scheme [uri]
  (some-> uri URI/create .getScheme str/lower-case))

(defn- key-resolver
  "Returns the verification key resolver for the configured IdP, or nil when
  the JWKS location cannot be determined or is not acceptable."
  [auth-config]
  (try
    (let [override (:jwks-url auth-config)
          jwks-uri (idp-endpoint auth-config :jwks-url "jwks_uri" "certs")]
      (when jwks-uri
        (if (and (nil? override)
                 (= "https" (uri-scheme (:base-url auth-config)))
                 (not= "https" (uri-scheme jwks-uri)))
          (do (error "Refusing non-HTTPS JWKS URI from HTTPS issuer" jwks-uri)
              nil)
          (HttpsJwksVerificationKeyResolver. (https-jwks jwks-uri)))))
    (catch IllegalArgumentException e
      (error "Invalid URL in the auth configuration or discovery document:"
             (ex-message e))
      nil)))

;; JWT consumers

(defn- audience-array
  "A nil or empty audience yields the default audience, so a misconfiguration
  can never turn the audience check off."
  [audience default]
  (let [audiences (cond
                    (string? audience) [audience]
                    (seq audience) audience
                    :else default)]
    (into-array String audiences)))

(defn access-token-consumer
  "Builds a JwtConsumer that validates access tokens using the given resolver."
  [auth-config resolver]
  (-> (JwtConsumerBuilder.)
      JwtConsumerBuilder/.setRequireExpirationTime
      (JwtConsumerBuilder/.setAllowedClockSkewInSeconds 30)
      JwtConsumerBuilder/.setRequireSubject
      JwtConsumerBuilder/.setRequireIssuedAt
      (JwtConsumerBuilder/.setExpectedAudience
       (audience-array (:access-token-audience auth-config)
                       default-access-token-audience))
      (JwtConsumerBuilder/.setExpectedIssuer (:base-url auth-config))
      (JwtConsumerBuilder/.setVerificationKeyResolver resolver)
      .build))

(defn id-token-consumer
  "Builds a JwtConsumer that validates ID tokens using the given resolver."
  [auth-config resolver]
  (-> (JwtConsumerBuilder.)
      (JwtConsumerBuilder/.setExpectedAudience
       (into-array String [(:client-id auth-config)]))
      (JwtConsumerBuilder/.setExpectedIssuer (:base-url auth-config))
      (JwtConsumerBuilder/.setVerificationKeyResolver resolver)
      (JwtConsumerBuilder/.setAllowedClockSkewInSeconds
       (int (or (:id-token-clock-skew auth-config)
                default-id-token-clock-skew)))
      JwtConsumerBuilder/.setRequireIssuedAt
      JwtConsumerBuilder/.setRequireSubject
      .build))

(defn- validate-jwt
  "Returns true if the JWT is valid and its subject is authorised, false if
  the subject is not authorised, nil if the JWT is invalid or could not be
  verified."
  [label auth-config consumer jwt-string]
  (when jwt-string
    (try
      (contains? (set (:authorised-subject-uuids auth-config))
                 (JwtClaims/.getSubject (JwtConsumer/.processToClaims consumer
                                                                      jwt-string)))
      (catch InvalidJwtException _
        (error label "JWT validation failed")
        nil)
      ;; Never let a verification problem escape as anything but a denial
      (catch Exception e
        (error e label "JWT could not be verified")
        nil))))

(defn check-access-token
  "Validates an access token against the given key resolver."
  [auth-config resolver jwt-string]
  (validate-jwt "Access token" auth-config
                (access-token-consumer auth-config resolver) jwt-string))

(defn check-id-token
  "Validates an ID token against the given key resolver."
  [auth-config resolver jwt-string]
  (validate-jwt "ID token" auth-config
                (id-token-consumer auth-config resolver) jwt-string))

(defn- validate-access-token [auth-config jwt-string]
  (when-let [resolver (key-resolver auth-config)]
    (check-access-token auth-config resolver jwt-string)))

(defn- validate-id-token [auth-config jwt-string]
  (when-let [resolver (key-resolver auth-config)]
    (check-id-token auth-config resolver jwt-string)))

;; Public API

(defn receive-and-check-id-token
  "Receives and validates the ID token and stores the information about this.
  A failed attempt leaves the stored state untouched, so an invalid token sent
  by anyone cannot log out an existing session."
  [auth-config request]
  (when (validate-id-token auth-config (get (:query-params request) "id-token"))
    (reset! id-token-valid true)
    true))

(defn user-authorized?
  "Checks if the user is authorised."
  [auth-config request]
  (when-let [token (:value (get (:cookies request)
                                "X-Authorization-Token"))]
    (validate-access-token auth-config token)))

(defn access-ok?
  "Checks the the user is both authenticated and authorised."
  [auth-config request]
  (if-let [bearer-token (get (:headers request) "bearer")]
    (validate-access-token auth-config bearer-token)
    (and @id-token-valid (user-authorized? auth-config request))))

(defn- url-encode [value]
  (URLEncoder/encode (str value) StandardCharsets/UTF_8))

(defn- append-query-params [endpoint params]
  (let [[base fragment] (str/split endpoint #"#" 2)
        separator (cond
                    (or (str/ends-with? base "?")
                        (str/ends-with? base "&")) ""
                    (str/includes? base "?") "&"
                    :else "?")]
    (str base separator params
         (when fragment (str "#" fragment)))))

(defn make-logout-url
  "Create log out URL to the authentication server. Returns nil when the IdP
  has no end-session endpoint and no :logout-url override is configured, in
  which case only local state should be cleared."
  [redirect-uri auth-config]
  (when-let [endpoint (idp-endpoint auth-config :logout-url
                                    "end_session_endpoint" "logout")]
    (append-query-params
     endpoint
     (str "post_logout_redirect_uri=" (url-encode redirect-uri)
          "&client_id=" (url-encode (:client-id auth-config))))))
