#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::collections::HashMap;
use std::env;
use std::io::Read;
use base64::prelude::*;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, middleware, web};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug)]
struct StringError(String);

impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl actix_web::error::ResponseError for StringError {}

#[derive(Clone, Debug)]
struct Cert {
    priv_key: openssl::ec::EcKey<openssl::pkey::Private>,
    id_key: openssl::rsa::Rsa<openssl::pkey::Private>,
    key_id: String,
    client_secret: String,
}

#[derive(Clone)]
struct Config {
    certs: HashMap<String, Cert>,
}

fn config() -> Config {
    dotenv::dotenv().ok();

    let file_prefix = "APPLE_CERT_FILE_".to_string();
    let file_prefix_len = file_prefix.len();

    let mut certs = HashMap::new();

    for (key, value) in env::vars() {
        if key.starts_with(&file_prefix) {
            let client_id = &key[file_prefix_len..];
            let mut buf = Vec::new();
            std::fs::File::open(value).expect(&format!("Unable to open {} apple certificate", client_id))
                .read_to_end(&mut buf).expect(&format!("Unable to read {} apple certificate", client_id));

            let key = openssl::pkey::PKey::private_key_from_pem(&buf)
                .expect(&format!("{} apple certificate isn't a valid PEM private key", client_id));
            let ec_key = key.ec_key().expect(&format!("{} apple certificate isn't a ECDSA key", client_id));

            let key_id_key = format!("APPLE_CERT_ID_{}", client_id);
            let client_secret_key = format!("CLIENT_SECRET_{}", client_id);
            let id_cert_path_key = format!("ID_CERT_FILE_{}", client_id);

            let key_id = env::var(&key_id_key)
                .expect(&format!("{} must be set", key_id_key));
            let client_secret = env::var(&client_secret_key)
                .expect(&format!("{} must be set", client_secret_key));
            let id_cert_path = env::var(&id_cert_path_key)
                .expect(&format!("{} must be set", id_cert_path_key));

            let mut buf = Vec::new();
            std::fs::File::open(id_cert_path).expect(&format!("Unable to open {} id certificate", client_id))
                .read_to_end(&mut buf).expect(&format!("Unable to read {} id certificate", client_id));

            let key = openssl::pkey::PKey::private_key_from_pem(&buf)
                .expect(&format!("{} id certificate isn't a valid PEM private key", client_id));
            let id_key = key.rsa().expect(&format!("{} id certificate isn't a RSA key", client_id));

            let cert = Cert {
                priv_key: ec_key,
                id_key,
                key_id,
                client_secret,
            };
            certs.insert(client_id.to_string(), cert);
        }
    }

    Config {
        certs
    }
}

#[derive(Serialize, Deserialize)]
struct OauthState {
    redirect_url: String,
    orig_state: Option<String>,
    client_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AppleUserName {
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AppleUserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<AppleUserName>,
    email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct OauthCode {
    #[serde(skip_serializing_if = "Option::is_none")]
    user_info: Option<AppleUserInfo>,
    orig_code: String,
}

#[derive(Deserialize)]
struct OauthLoginInfo {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    nonce: Option<String>,
    state: Option<String>,
}

async fn start_login(req: HttpRequest, info: web::Query<OauthLoginInfo>) -> Result<impl actix_web::Responder, actix_web::error::Error> {
    let own_uri = format!("https://{}/auth/callback", req.connection_info().host());
    let mut redirect_uri =
        format!("https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&response_type=code&response_mode=form_post",
                info.client_id, urlencoding::encode(&own_uri));

    if let Some(scope) = &info.scope {
        redirect_uri.push_str(&format!("&scope={}", scope));
    }
    if let Some(nonce) = &info.nonce {
        redirect_uri.push_str(&format!("&nonce={}", nonce));
    }

    let state = serde_json::to_string(&OauthState {
        redirect_url: info.redirect_uri.clone(),
        orig_state: info.state.clone(),
        client_id: info.client_id.clone(),
    })?;
    redirect_uri.push_str(&format!("&state={}", BASE64_STANDARD.encode(&state)));

    Ok(
        HttpResponse::Found()
            .append_header((actix_web::http::header::LOCATION, redirect_uri))
            .finish()
    )
}

#[derive(Deserialize, Debug)]
struct OauthCallbackInfo {
    state: String,
    code: Option<String>,
    error: Option<String>,
    user: Option<String>,
}

async fn finish_login(info: web::Form<OauthCallbackInfo>, data: web::Data<Config>) -> Result<impl actix_web::Responder, actix_web::error::Error> {
    let state: OauthState = serde_json::from_slice(
        &BASE64_STANDARD.decode(&info.state)
            .map_err(|e| StringError(e.to_string()))?
    )?;
    let mut redirect_uri = state.redirect_url;

    if let Some(error) = &info.error {
        redirect_uri.push_str(&format!("?error={}", error))
    } else {
        let code = info.code.clone().unwrap_or("".to_string());
        let user: Option<AppleUserInfo> = match info.user {
            Some(ref u) => Some(serde_json::from_str(u)?),
            None => None
        };

        let cert = match data.certs.get(&state.client_id) {
            Some(c) => c,
            None => return Err(StringError("Client ID not found".to_string()).into())
        };

        let header = AppleSecretHeader {
            alg: "RS256".to_string(),
            kid: state.client_id.clone(),
        };
        let new_code = encode_jwt_rsa(&header, &OauthCode {
            orig_code: code,
            user_info: user,
        }, &cert.id_key)?;
        redirect_uri.push_str(&format!("?code={}", &new_code));
        if let Some(state) = &state.orig_state {
            redirect_uri.push_str(&format!("&state={}", state));
        }
    }

    Ok(
        HttpResponse::Found()
            .append_header((actix_web::http::header::LOCATION, redirect_uri))
            .finish()
    )
}


#[derive(Serialize, Deserialize, Debug)]
struct OauthTokenInfo {
    client_id: String,
    client_secret: String,
    code: Option<String>,
    grant_type: String,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleSecretHeader {
    alg: String,
    kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}


#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    id_token: String,
    refresh_token: String,
    token_type: String,
}

fn encode_jwt_ecdsa<H: serde::Serialize, C: serde::Serialize>(header: &H, claims: &C, priv_key: &openssl::ec::EcKeyRef<openssl::pkey::Private>) -> Result<String, actix_web::error::Error> {
    let header_str = URL_SAFE_NO_PAD.encode(
        &serde_json::to_string(header).map_err(|e| StringError(e.to_string()))?
    );
    let claims_str =  URL_SAFE_NO_PAD.encode(
        &serde_json::to_string(claims).map_err(|e| StringError(e.to_string()))?
    );

    let mut secret = String::new();
    secret.push_str(&header_str);
    secret.push('.');
    secret.push_str(&claims_str);

    let mut digester = openssl::sha::Sha256::new();
    digester.update(&secret.as_bytes());
    let signer = openssl::ecdsa::EcdsaSig::sign(&digester.finish(), priv_key)
        .map_err(|e| StringError(e.to_string()))?;
    let mut signature = signer.r().to_vec();
    signature.extend(signer.s().to_vec());
    let signature = URL_SAFE_NO_PAD.encode(&signature);

    secret.push('.');
    secret.push_str(&signature);

    Ok(secret)
}

fn encode_jwt_rsa<H: serde::Serialize, C: serde::Serialize>(header: &H, claims: &C, priv_key: &openssl::rsa::RsaRef<openssl::pkey::Private>) -> Result<String, actix_web::error::Error> {
    let header_str = URL_SAFE_NO_PAD.encode(
        &serde_json::to_string(header).map_err(|e| StringError(e.to_string()))?
    );
    let claims_str = URL_SAFE_NO_PAD.encode(
        &serde_json::to_string(claims).map_err(|e| StringError(e.to_string()))?
    );

    let mut secret = String::new();
    secret.push_str(&header_str);
    secret.push('.');
    secret.push_str(&claims_str);

    let pkey = openssl::pkey::PKey::from_rsa(priv_key.to_owned())
        .map_err(|e| StringError(e.to_string()))?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .map_err(|e| StringError(e.to_string()))?;
    signer.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| StringError(e.to_string()))?;
    signer.update(&secret.as_bytes()).map_err(|e| StringError(e.to_string()))?;
    let signature = URL_SAFE_NO_PAD.encode(
        &signer.sign_to_vec().map_err(|e| StringError(e.to_string()))?
    );

    secret.push('.');
    secret.push_str(&signature);

    Ok(secret)
}

async fn get_apple_keys() -> Result<JWKSet, actix_web::error::Error> {
    let client = reqwest::Client::new();
    Ok(client
        .get("https://appleid.apple.com/auth/keys")
        .send()
        .await.map_err(|e| StringError(e.to_string()))?
        .json::<JWKSet>()
        .await.map_err(|e| StringError(e.to_string()))?)
}

async fn get_token(req: HttpRequest, data: web::Data<Config>, info: web::Form<OauthTokenInfo>) -> Result<impl actix_web::Responder, actix_web::error::Error> {
    let cert = match data.certs.get(&info.client_id) {
        Some(c) => c,
        None => return Err(StringError("Client ID not found".to_string()).into())
    };

    if info.client_secret != cert.client_secret {
        return Ok(HttpResponse::Forbidden().finish());
    }

    let header = AppleSecretHeader {
        alg: "ES256".to_string(),
        kid: cert.key_id.clone(),
    };
    let now = std::time::SystemTime::now();
    let exp = now + std::time::Duration::new(5 * 60, 0);
    let claims = AppleSecretClaims {
        iss: "MQ9TN9772U".to_string(),
        iat: now.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|e| StringError(e.to_string()))?.as_secs(),
        exp: exp.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|e| StringError(e.to_string()))?.as_secs(),
        aud: "https://appleid.apple.com".to_string(),
        sub: info.client_id.clone(),
    };

    let secret = encode_jwt_ecdsa(&header, &claims, &cert.priv_key)?;

    let code: Option<OauthCode> = match &info.code {
        Some(code) => {
            let parts: Vec<&str> = code.split(".").collect();
            if parts.len() != 3 {
                return Err(StringError("Invalid number of parts to JWT".to_string()).into())
            }
            let header: AppleSecretHeader = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| StringError(e.to_string()))?
            ).map_err(|e| StringError(e.to_string()))?;
            if &header.kid != &info.client_id {
                return Err(StringError("Token not for requesting client".to_string()).into())
            }
            let pkey = openssl::pkey::PKey::from_rsa(cert.id_key.clone())
                .map_err(|e| StringError(e.to_string()))?;

            let sig = URL_SAFE_NO_PAD.decode(parts[2])
                .map_err(|e| StringError(e.to_string()))?;
            let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
                .map_err(|e| StringError(e.to_string()))?;
            verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| StringError(e.to_string()))?;
            verifier.update(parts[0].as_bytes()).map_err(|e| StringError(e.to_string()))?;
            verifier.update(".".as_bytes()).map_err(|e| StringError(e.to_string()))?;
            verifier.update(parts[1].as_bytes()).map_err(|e| StringError(e.to_string()))?;
            if !verifier.verify(&sig).map_err(|e| StringError(e.to_string()))? {
                return Err(StringError("Signature verification failed".to_string()).into());
            }

            Some(serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| StringError(e.to_string()))?
            ).map_err(|e| StringError(e.to_string()))?)
        }
        None => None
    };
    let orig_code = match &code {
        Some(code) => Some(code.orig_code.clone()),
        None => None
    };

    let own_uri = format!("https://{}/auth/callback", req.connection_info().host());
    let client = reqwest::Client::new();
    let resp = client.post("https://appleid.apple.com/auth/token")
        .form(&OauthTokenInfo {
            client_id: info.client_id.clone(),
            client_secret: secret,
            code: orig_code,
            grant_type: info.grant_type.clone(),
            refresh_token: info.refresh_token.clone(),
            redirect_uri: Some(own_uri),
        })
        .send().await.map_err(|e| StringError(e.to_string()))?;

    let token = resp.json::<TokenResponse>().await.map_err(|e| StringError(e.to_string()))?;

    let parts: Vec<&str> = token.id_token.split(".").collect();
    if parts.len() != 3 {
        return Err(StringError("Invalid number of parts to JWT".to_string()).into())
    }
    let header: AppleSecretHeader = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| StringError(e.to_string()))?
    )?;
    let keys = get_apple_keys().await?;
    let key = match keys.get_key(&header.kid) {
        Some(k) => k,
        None => return Err(StringError("Apple signing key not found".to_string()).into())
    };

    match key.kty.as_str() {
        "RSA" => {
            let e = URL_SAFE_NO_PAD.decode(&key.e).map_err(|e| StringError(e.to_string()))?;
            let n = URL_SAFE_NO_PAD.decode(&key.n).map_err(|e| StringError(e.to_string()))?;

            let e = openssl::bn::BigNum::from_slice(&e).map_err(|e| StringError(e.to_string()))?;
            let n = openssl::bn::BigNum::from_slice(&n).map_err(|e| StringError(e.to_string()))?;

            let key = openssl::rsa::Rsa::from_public_components(n, e)
                .map_err(|e| StringError(e.to_string()))?;
            let pkey = openssl::pkey::PKey::from_rsa(key)
                .map_err(|e| StringError(e.to_string()))?;

            let sig = URL_SAFE_NO_PAD.decode(parts[2])
                .map_err(|e| StringError(e.to_string()))?;
            let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
                .map_err(|e| StringError(e.to_string()))?;
            verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|e| StringError(e.to_string()))?;
            verifier.update(parts[0].as_bytes()).map_err(|e| StringError(e.to_string()))?;
            verifier.update(".".as_bytes()).map_err(|e| StringError(e.to_string()))?;
            verifier.update(parts[1].as_bytes()).map_err(|e| StringError(e.to_string()))?;
            if !verifier.verify(&sig).map_err(|e| StringError(e.to_string()))? {
                return Err(StringError("Signature verification failed".to_string()).into());
            }
        }
        _ => return Err(StringError("Apple ID token should be using RSA".to_string()).into())
    };

    let new_header = AppleSecretHeader {
        alg: "RS256".to_string(),
        kid: info.client_id.clone(),
    };
    let mut claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| StringError(e.to_string()))?
    )?;

    if let Some(code) = code {
        if let Some(user_info) = code.user_info {
            if let Some(user_name) = user_info.name {
                if let Some(user_first_name) = user_name.first_name {
                    claims.insert("given_name".to_string(), serde_json::value::Value::String(user_first_name));
                }
                if let Some(user_last_name) = user_name.last_name {
                    claims.insert("family_name".to_string(), serde_json::value::Value::String(user_last_name));
                }
            }
        }
    }

    let new_token = encode_jwt_rsa(&new_header, &claims, &cert.id_key)?;

    let new_token = TokenResponse {
        access_token: token.access_token,
        expires_in: token.expires_in,
        refresh_token: token.refresh_token,
        token_type: token.token_type,
        id_token: new_token,
    };

    Ok(
        HttpResponse::Ok()
            .json(new_token)
    )
}

#[derive(Deserialize, Serialize, Debug)]
struct JWK {
    kty: String,
    r#use: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWKSet {
    keys: Vec<JWK>
}

impl JWKSet {
    fn get_key(&self, kid: &str) -> Option<&JWK> {
        for key in self.keys.iter() {
            if key.kid == kid {
                return Some(key);
            }
        }
        None
    }
}

async fn jwks(data: web::Data<Config>) -> impl actix_web::Responder {
    let keys: Vec<_> = data.certs.iter()
        .map(|(client_id, cert)| {
            let n = cert.id_key.n().to_vec();
            let e = cert.id_key.e().to_vec();

            JWK {
                kty: "RSA".to_string(),
                r#use: "sig".to_string(),
                alg: "RS256".to_string(),
                kid: client_id.to_string(),
                n: URL_SAFE_NO_PAD.encode(&n),
                e: URL_SAFE_NO_PAD.encode(&e),
            }
        })
        .collect();

    HttpResponse::Ok()
        .json(&JWKSet {
            keys
        })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    openssl_probe::init_ssl_cert_env_vars();

    let data = config();

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route("/auth/authorize", web::get().to(start_login))
            .route("/auth/callback", web::post().to(finish_login))
            .route("/auth/token", web::post().to(get_token))
            .route("/auth/keys", web::get().to(jwks))
    });

    let mut listenfd = listenfd::ListenFd::from_env();

    info!("Start listening...");
    server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        server.listen(l).unwrap()
    } else {
        server.bind("0.0.0.0:3000").unwrap()
    };

    server.run().await
}
