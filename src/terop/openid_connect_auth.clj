(ns terop.openid-connect-auth
  (:require [taoensso.timbre :refer [error]])
  (:import org.jose4j.jwk.HttpsJwks
           org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
           org.jose4j.jwt.JwtClaims
           (org.jose4j.jwt.consumer InvalidJwtException JwtConsumer JwtConsumerBuilder)))

(def id-token-valid (atom false))

(defn- validate-access-token
  "Validate provided access token in JWT format."
  [auth-config jwt-string]
  (let [http-jwks (HttpsJwks. (str (:base-url auth-config)
                                   "/protocol/openid-connect/certs"))
        http-key-resolver (HttpsJwksVerificationKeyResolver. http-jwks)
        jwt-consumer (-> (JwtConsumerBuilder.)
                         JwtConsumerBuilder/.setRequireExpirationTime
                         (JwtConsumerBuilder/.setAllowedClockSkewInSeconds 30)
                         JwtConsumerBuilder/.setRequireSubject
                         JwtConsumerBuilder/.setRequireIssuedAt
                         (JwtConsumerBuilder/.setExpectedAudience
                          (into-array ["account"]))
                         (JwtConsumerBuilder/.setExpectedIssuer
                          (:base-url auth-config))
                         (JwtConsumerBuilder/.setVerificationKeyResolver
                          http-key-resolver)
                         .build)]
    (try
      (contains? (set (:authorised-subject-uuids auth-config))
                 (JwtClaims/.getSubject (JwtConsumer/.processToClaims jwt-consumer
                                                                      jwt-string)))
      (catch InvalidJwtException _
        (error "Access token JWT validation failed")
        nil))))

(defn- validate-id-token
  "Validate provided ID token."
  [auth-config jwt-string]
  (let [http-jwks (HttpsJwks. (str (:base-url auth-config)
                                   "/protocol/openid-connect/certs"))
        http-key-resolver (HttpsJwksVerificationKeyResolver. http-jwks)
        jwt-consumer (-> (JwtConsumerBuilder.)
                         (JwtConsumerBuilder/.setExpectedAudience
                          (into-array [(:client-id auth-config)]))
                         (JwtConsumerBuilder/.setExpectedIssuer
                          (:base-url auth-config))
                         (JwtConsumerBuilder/.setVerificationKeyResolver
                          http-key-resolver)
                         ;; Allow big skew because ID tokens have the same value
                         ;; in iat and exp claims
                         (JwtConsumerBuilder/.setAllowedClockSkewInSeconds 2592000)
                         JwtConsumerBuilder/.setRequireIssuedAt
                         JwtConsumerBuilder/.setRequireSubject
                         .build)]
    (try
      (contains? (set (:authorised-subject-uuids auth-config))
                 (JwtClaims/.getSubject (JwtConsumer/.processToClaims jwt-consumer
                                                                      jwt-string)))
      (catch InvalidJwtException _
        (error "ID token JWT validation failed")
        nil))))

(defn receive-and-check-id-token
  "Receives and validates the ID token and stores the information about this."
  [auth-config request]
  (reset! id-token-valid false)
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

(defn make-logout-url
  "Create log out URL to the authentication server."
  [redirect-uri auth-config]
  (str (:base-url auth-config)
       "/protocol/openid-connect/logout?post_logout_redirect_uri=" redirect-uri
       "&client_id=" (:client-id auth-config)))
