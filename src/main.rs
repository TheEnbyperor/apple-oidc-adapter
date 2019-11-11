#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, middleware, web};
use dotenv::dotenv;
use std::io::Read;
use std::env;
use futures::compat::Future01CompatExt;

#[derive(Clone)]
struct Config {
    priv_key: Vec<u8>,
    key_id: String,
    client_secret: String,
}

fn config() -> Config {
    dotenv().ok();
    let cert_path = env::var("APPLE_CERT")
        .expect("APPLE_CERT must be set");
    let key_id = env::var("APPLE_CERT_ID")
        .expect("APPLE_CERT_ID must be set");
    let client_secret = env::var("CLIENT_SECRET")
        .expect("CLIENT_SECRET must be set");

    let mut buf = Vec::new();

    std::fs::File::open(cert_path).expect("Unable to open apple certificate")
        .read_to_end(&mut buf).expect("Unable to read apple certificate");

    Config {
        priv_key: buf,
        client_secret,
        key_id
    }
}

#[derive(Serialize, Deserialize)]
struct OauthState {
    redirect_url: String,
    orig_state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AppleUserName {
    #[serde(rename = "firstName")]
    first_name: String,
    #[serde(rename = "lastName")]
    last_name: String
}
#[derive(Serialize, Deserialize, Debug)]
struct AppleUserInfo {
    name: AppleUserName,
    email: String
}

#[derive(Serialize, Deserialize)]
struct OauthCode<'a> {
    user_info: Option<&'a AppleUserInfo>,
    orig_code: String
}

#[derive(Deserialize)]
struct OauthLoginInfo {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    nonce: Option<String>,
    state: Option<String>
}

async fn start_login(req: HttpRequest, info: web::Query<OauthLoginInfo>) -> actix_web::Result<impl actix_web::Responder> {
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
        orig_state: info.state.clone()
    }).unwrap();
    redirect_uri.push_str(&format!("&state={}", base64::encode(&state)));

    Ok(
        HttpResponse::Found()
            .header(actix_web::http::header::LOCATION, redirect_uri)
            .finish()
    )
}

#[derive(Deserialize, Debug)]
struct OauthCallbackInfo {
    state: String,
    code: Option<String>,
    error: Option<String>,
    user: Option<AppleUserInfo>
}


async fn finish_login(info: web::Form<OauthCallbackInfo>) -> actix_web::Result<impl actix_web::Responder> {
    println!("{:?}",&info.state);
    let state: OauthState = serde_json::from_slice(&base64::decode(&info.state).unwrap()).unwrap();
    let mut redirect_uri = state.redirect_url;

    if let Some(error) = &info.error {
        redirect_uri.push_str(&format!("?error={}", error))
    } else {
        let code = info.code.clone().unwrap_or("".to_string());
        let new_code = base64::encode(&serde_json::to_string(&OauthCode {
            orig_code: code,
            user_info: info.user.as_ref()
        }).unwrap());
        redirect_uri.push_str(&format!("?code={}", &new_code));
        if let Some(state) = &state.orig_state {
            redirect_uri.push_str(&format!("&state={}",state));
        }
    }

    Ok(
        HttpResponse::Found()
            .header(actix_web::http::header::LOCATION, redirect_uri)
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
    redirect_uri: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

async fn get_token(req: HttpRequest, data: web::Data<Config>, info: web::Form<OauthTokenInfo>) -> actix_web::Result<impl actix_web::Responder> {
    if info.client_secret != data.client_secret {
        return Ok(HttpResponse::Forbidden().finish());
    }

    let mut header = jsonwebtoken::Header::default();
    header.alg = jsonwebtoken::Algorithm::ES256;
    header.kid = Some(data.key_id.clone());
    let now = std::time::SystemTime::now();
    let exp = now + std::time::Duration::new(5*60, 0);
    let claims = AppleSecretClaims {
        iss: "MQ9TN9772U".to_string(),
        iat: now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        exp: exp.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        aud: "https://appleid.apple.com".to_string(),
        sub: info.client_id.clone()
    };
    let secret = jsonwebtoken::encode(&header, &claims, &data.priv_key).unwrap();

    let code: Option<OauthCode> = match &info.code {
        Some(code) => Some(serde_json::from_slice(&base64::decode(&code).unwrap()).unwrap()),
        None => None
    };
    let orig_code = match code {
        Some(code) => Some(code.orig_code),
        None => None
    };

    let own_uri = format!("https://{}/auth/callback", req.connection_info().host());
    let client = reqwest::r#async::Client::new();
    let mut resp = client.post("https://appleid.apple.com/auth/token")
        .form(&OauthTokenInfo {
            client_id: info.client_id.clone(),
            client_secret: secret,
            code: orig_code,
            grant_type: info.grant_type.clone(),
            refresh_token: info.refresh_token.clone(),
            redirect_uri: Some(own_uri)
        })
        .send().compat().await.unwrap();

    let text = resp.text().compat().await.unwrap();

    Ok(
        HttpResponse::Ok()
            .body(text)
    )
}

fn main() {
    pretty_env_logger::init();

    let sys = actix::System::new("apple-oidc-adaptor");

    let data = config();

    let mut server = HttpServer::new(move || {
        App::new()
            .data(data.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route(".well-known/apple-developer-domain-association.txt", web::get().to(|| HttpResponse::Ok().body(
                actix_web::dev::Body::from_slice(include_bytes!("../apple-developer-domain-association.txt")))))
            .route("/auth/authorize", web::get().to_async(actix_web_async_await::compat2(start_login)))
            .route("/auth/callback", web::post().to_async(actix_web_async_await::compat(finish_login)))
            .route("/auth/token", web::post().to_async(actix_web_async_await::compat3(get_token)))
    });

    let mut listenfd = listenfd::ListenFd::from_env();

    info!("Start listening...");
    server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        server.listen(l).unwrap()
    } else {
        server.bind("127.0.0.1:3000").unwrap()
    };

    server.start();
    let _ = sys.run();
}