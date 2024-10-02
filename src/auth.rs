use create::{error::Error, Result, WebResult};
use chrono::prelude::*;
use chrono::Duration;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Error;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};

// Secret key (for example purposes)
const BEARER: &str = "Bearer";
const JWT_SECRET: &[u8] = b"your_secret_key";

// Define the Role enum
#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn from_str(role: &str) -> Role {
        match role {
            "User" => Role::User,
            "Admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

imp fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self{
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

// Claims struct to be encoded in JWT
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    role: Role,
}

// Filter for authentication
pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
}

// Function to create a JWT token
pub fn create_jwt_token(uid: &str, role: &str) -> Result<String, Error> {
    // Set token expiration time (60 seconds from now)
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(60))
        .expect("Valid TimeStamp")
        .timestamp();

    // Create claims
    let claims = Claims {
        sub: uid.to_string(),
        exp: expiration as usize,
        role: Role::from_str(role),
    };

    // Set the header
    let header = Header::new(Algorithm::HS512);

    // Create the JWT token
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| Error::JWTTokenCreationError)
}

// Function to authorize user based on JWT
async fn authorize((role, headers): (Role, HeaderMap<HeaderValue>)) -> Result<String, Rejection> {
    match jwt_from_headers(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|_| reject::custom(Error::JWTTokenDecodingError))?;

            if role == Role::Admin && decoded.claims.role != Role::Admin {
                return Err(reject::custom(Error::NoPermissionError));
            }

            Ok(decoded.claims.sub)
        }
        Err(e) => Err(reject::custom(e)),
    }
}

// Function to extract JWT from headers
fn jwt_from_headers(headers: &HeaderMap<HeaderValue>) -> Result<String, Rejection> {
    let header = match headers.get(AUTHORIZATION) {
        Some(value) => value,
        None => return Err(reject::custom(Error::NoAuthHeaderError)),
    };

    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(s) => s,
        Err(_) => return Err(reject::custom(Error::InvalidAuthHeaderError)),
    };

    if !auth_header.starts_with(BEARER) {
        return Err(reject::custom(Error::InvalidAuthHeaderError));
    }

    Ok(auth_header.trim_start_matches(BEARER).trim().to_owned())
}
