use serde::{Deserialize, Serialize};
use core::sync;
use std::fmt::format;
use std::io::Read;
use std::{collections::HashMap, sync::Arc};
use std::convert::Infallible;
// use std::sync::Arc;   // instead seperate importing from standard library
use warp::{Filter, Rejection, Reply, http::StatusCode};

mod auth;
mod error;

use auth::{with_auth, Role};
use error::Error::*;

type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;
type Users = Arc<HashMap<String, User>>

// Rust does not understand the JSON representation, so we require Deserialization.
#[derive(Clone)]
pub struct User {
    pub uid: u32,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[tokio::main]
async fn main() {
    // Initialize the user database
    let users = Arc::new(init_users());

    // Login route
    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    // User route
    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);

    // Admin route
    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    // Combine all routes
    let routes = login_route
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    // Print server start information
    println!("Server is running on http://127.0.0.1:3030");

    // Start the server
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

// Assuming Users is Arc<HashMap<String, User>>
fn with_users(users: Arc<HashMap<String, User>>) -> impl Filter<Extract = (Arc<HashMap<String, User>>,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}

// pub async fn login_handler(
//     users: Arc<HashMap<String, User>>, 
//     login_req: LoginRequest
// ) -> WebResult<impl Reply> {
//     // Check if the user exists
//     if let Some(user) = users.get(&login_req.email) {
//         // Validate password
//         if user.password == login_req.password {
//             // Generate a token (for simplicity, we are returning a hardcoded token here)
//             let token = "some_generated_token"; // In reality, you would generate a real token (JWT, etc.)
            
//             // Return the token in a response
//             let response = LoginResponse {
//                 token: token.to_string(),
//             };
            
//             return Ok(warp::reply::json(&response));
//         }
//     }

//     // If credentials are invalid, return an error
//     let json = warp::reply::json(&"Invalid email or password");
//     Ok(warp::reply::with_status(json, StatusCode::UNAUTHORIZED))
// }

// pub async fn login_handler(
//     users: Arc<HashMap<String, User>>, 
//     login_req: LoginRequest
// ) -> WebResult<impl Reply> {
//     match users.get(&login_req.email) {
//         Some(user) => {
//             // Validate password
//             if user.password == login_req.password {
//                 // Generate a token (for simplicity, we are returning a hardcoded token here)
//                 let token = "some_generated_token"; // In reality, you would generate a real token (JWT, etc.)

//                 // Return the token in a response
//                 let response = LoginResponse {
//                     token: token.to_string(),
//                 };

//                 return Ok(warp::reply::json(&response));
//             }

//             // Password is incorrect
//             let json = warp::reply::json(&"Invalid email or password");
//             Ok(warp::reply::with_status(json, StatusCode::UNAUTHORIZED))
//         }
//         None => {
//             // If user doesn't exist, return an error
//             let json = warp::reply::json(&"Invalid email or password");
//             Ok(warp::reply::with_status(json, StatusCode::UNAUTHORIZED))
//         }
//     }
// }



pub async fn login_handler(
    users: Arc<HashMap<String, User>>, 
    login_req: LoginRequest
) -> WebResult<impl Reply> {
    // Using .iter().find() to search for a user by email and password
    match users.iter().find(|(_uid, user)| user.email == login_req.email && user.password == login_req.password) {
        Some((uid, user)) => {
            // Generate a JWT token based on the user ID and role
            let token = auth::create_jwt_token(uid, &Role::from_str(&user.role))
            .map_err(|e| reject::custom(e))?;
            
            // Return the token in the response
            Ok(warp::reply::json(&LoginResponse { token }))
        }
        None => {
            // If no matching user is found, return an error response
            let json = warp::reply::json(&"Invalid email or password");
            Ok(warp::reply::with_status(json, StatusCode::UNAUTHORIZED))
        }
    }
}

pub async fn user_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello User: {}", uid))
}

pub async fn admin_handler(uid: String) -> WebResult<impl Reply> {
    Ok(format!("Hello Admin: {}", uid))
}

fn init_users() -> HashMap<String, User> {
    let mut map = HashMap::new();
    
    // Adding a sample regular user
    map.insert(
        String::from("1"),
        User {
            uid: 1,
            email: "user1@example.com".to_string(),
            password: "password1".to_string(), // This is an example; you should hash passwords in a real app!
            role: "User".to_string(),
        },
    );

    // Adding a sample admin user
    map.insert(
        String::from("2"),
        User {
            uid: 2,
            email: "admin@example.com".to_string(),
            password: "adminpass".to_string(), // Same as above, hash the password in production!
            role: "Admin".to_string(),
        },
    );

    map
}
