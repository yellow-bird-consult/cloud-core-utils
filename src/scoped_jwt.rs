//! defines the middleware for a JWT that expires after a certain amount of time.
use actix_web::dev::Payload;
use actix_web::{Error, FromRequest, HttpRequest};
use actix_web::error::ErrorUnauthorized;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use futures::future::{Ready, ok, err};
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::config::GetConfigVariable;
use crate::structs::entity_type::EntityType;


/// The attributes extracted from the scoped auth token hiding in the header.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
/// * `unique_id`: the unique ID of the session (should be different every time with new login sessions)
/// * `role`: the role of the user for the login session
/// * `entity_id`: the ID of the entity the user is associated with
/// * `entity_type`: the type of entity the user is associated with
/// * `expire_time`: the time the token expires
#[derive(Debug, Serialize, Deserialize)]
pub struct ScopedTokenBody {
    pub user_id: i32,
    pub unique_id: String,
    pub role: Option<String>,
    pub entity_id: Option<i32>,
    pub entity_type: Option<EntityType>,
    pub expire_time: NaiveDateTime
}


/// JWT for authentication that can expire for an API request.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
/// * `unique_id`: the unique ID of the session
/// * `role`: the role of the user for the login session
/// * `entity_id`: the ID of the entity the user is associated with
/// * `entity_type`: the type of entity the user is associated with
/// * `expire_time`: the time the token expires
/// * `handle`: the handle for the config struct to get config variables
#[derive(Debug, Serialize, Deserialize)]
pub struct ScopedJwToken<X: GetConfigVariable> {
    pub user_id: i32,
    pub unique_id: String,
    pub role: Option<String>,
    pub entity_id: Option<i32>,
    pub entity_type: Option<EntityType>,
    pub expire_time: NaiveDateTime,
    pub handle: Option<X>
}


impl <X: GetConfigVariable>ScopedJwToken<X> {

    /// Gets the secret key from the environment for encoding and decoding tokens.
    ///
    /// # Returns
    /// the key from the environment
    pub fn get_key() -> Result<String, String> {
        let key = <X>::get_config_variable("SECRET_KEY".to_string())?;
        return Ok(key)
    }

    /// Gets the expire time from the environment for encoding and decoding tokens.
    /// 
    /// # Returns
    /// the expire time from the environment
    pub fn get_expire_mins() -> Result<usize, String> {
        let expire_mins = <X>::get_config_variable("EXPIRE_MINS".to_string())?;
        let expire_mins = expire_mins.parse::<usize>().map_err(|_| "EXPIRE_MINS is not a number".to_string())?;
        return Ok(expire_mins)
    }

    /// Checks if the token has expired.
    /// 
    /// # Returns
    /// true if the token has expired, false otherwise
    pub fn has_expired(&self) -> bool {
        let expire_time = DateTime::<Utc>::from_naive_utc_and_offset(self.expire_time, Utc);
        let now = Utc::now();
        return now > expire_time
    }

    /// Updates the `self.expire_time` of the token with not + EXPIRE_MINS config var.
    pub fn update_time(&mut self) {
        let expire_mins = ScopedJwToken::<X>::get_expire_mins().unwrap();
        let expire_time = Utc::now().naive_utc() + chrono::Duration::minutes(expire_mins as i64);
        self.expire_time = expire_time;
    }

    /// Encodes the struct into a token.
    ///
    /// # Returns
    /// encoded token with fields of the current struct
    pub fn encode(&mut self) -> Result<String, String> {
        let key = EncodingKey::from_secret(ScopedJwToken::<X>::get_key()?.as_ref());
        let body = ScopedTokenBody {
            user_id: self.user_id,
            expire_time: self.expire_time,
            role: self.role.clone(),
            entity_id: self.entity_id,
            entity_type: self.entity_type.clone(),
            unique_id: self.unique_id.clone()
        };
        match encode(&Header::default(), &body, &key) {
            Ok(token) => return Ok(token),
            Err(error) => return Err(error.to_string())
        };
    }

    /// Decodes the token into a struct.
    /// 
    /// # Arguments
    /// * `token` - The token to be decoded.
    /// 
    /// # Returns
    /// decoded token with fields of the current struct
    pub fn decode(token: &str) -> Result<ScopedTokenBody, String> {
        let key = DecodingKey::from_secret(ScopedJwToken::<X>::get_key()?.as_ref());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.remove("exp");

        match decode::<ScopedTokenBody>(token, &key, &validation) {
            Ok(token_data) => return Ok(token_data.claims),
            Err(error) => return Err(error.to_string())
        };
    }

}


impl<X: GetConfigVariable> FromRequest for ScopedJwToken<X> {
    type Error = Error;
    type Future = Ready<Result<ScopedJwToken<X>, Error>>;

    /// This gets fired when the JwToken is attached to a request. It fires before the request hits the view.
    /// # Arguments
    /// The arguments are needed in order for the impl of FromRequest to work.
    ///
    /// * req (&HttpRequest): the request that the token is going to be extracted from
    /// * _ (Payload): the payload stream (not used in this function but is needed)
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {

        match req.headers().get("token") {
            Some(data) => {
                let raw_token = data.to_str().unwrap().to_string();
                let token_result = ScopedJwToken::<X>::decode(&raw_token.as_str());

                match token_result {
                    Ok(token) => {
                        let jwt = ScopedJwToken::<X> {
                            user_id: token.user_id,
                            handle: None,
                            expire_time: token.expire_time,
                            unique_id: token.unique_id,
                            role: token.role,
                            entity_id: token.entity_id,
                            entity_type: token.entity_type
                        };
                        if jwt.has_expired() {
                            return err(ErrorUnauthorized("token expired"))
                        }
                        return ok(jwt)
                    },
                    Err(message) => {
                        if message == "ExpiredSignature".to_owned() {
                            return err(ErrorUnauthorized("token expired"))
                        }
                        return err(ErrorUnauthorized("token can't be decoded"))
                    }
                }
            },
            None => {
                return err(ErrorUnauthorized("token not in header under key 'token'"))
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{HttpRequest, HttpResponse, test::TestRequest, web, App};
    use actix_web::http::header::ContentType;
    use actix_web::test::{init_service, call_service};
    use actix_web::{self, body};
    use serde_json::json;
    use serde::{Deserialize, Serialize};
    use chrono::{DateTime, Utc};

    struct FakeConfig;

    impl GetConfigVariable for FakeConfig {

        fn get_config_variable(variable: String) -> Result<String, String> {
            match variable.as_str() {
                "SECRET_KEY" => Ok("secret".to_string()),
                "EXPIRE_MINS" => Ok("20".to_string()),
                _ => Ok("".to_string())
            }
        }

    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ResponseFromTest {
        pub user_id: i32,
    }

    async fn pass_handle(token: ScopedJwToken<FakeConfig>, _: HttpRequest) -> HttpResponse {
        return HttpResponse::Ok().json(json!({
            "user_id": token.user_id,
            "unique_id": token.unique_id,
            "expire_time": token.expire_time
        }))
    }

    #[test]
    fn test_encode_decode() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1bmlxdWVfaWQiOiJ1bmlxdWVfaWQiLCJyb2xlIjoiQURNSU4iLCJlbnRpdHlfaWQiOm51bGwsImVudGl0eV90eXBlIjpudWxsLCJleHBpcmVfdGltZSI6IjIwMjEtMDEtMDdUMDY6MTM6MjAifQ.FH8xRtgA1eDYPXH2IpYD7kvWz5mQI4gS5UrpnTyIGCI";
        let seconds_since_epoch = 1_610_000_000;
        let naive_date_time = NaiveDateTime::from_timestamp_opt(seconds_since_epoch, 0).unwrap();
        let mut jwt = ScopedJwToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: naive_date_time,
            unique_id: "unique_id".to_string(),
            role: Some("ADMIN".to_string()),
            entity_id: None,
            entity_type: None
        };
        let token = jwt.encode().unwrap();
        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_decode_token() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1bmlxdWVfaWQiOiJ1bmlxdWVfaWQiLCJyb2xlIjoiQURNSU4iLCJlbnRpdHlfaWQiOm51bGwsImVudGl0eV90eXBlIjpudWxsLCJleHBpcmVfdGltZSI6IjIwMjEtMDEtMDdUMDY6MTM6MjAifQ.FH8xRtgA1eDYPXH2IpYD7kvWz5mQI4gS5UrpnTyIGCI";
        let decoded_token = ScopedJwToken::<FakeConfig>::decode(expected_token).unwrap();
        assert_eq!(decoded_token.user_id, 1);
        assert_eq!(decoded_token.unique_id, "unique_id");
        assert_eq!(decoded_token.role, Some("ADMIN".to_string()));
    }

    #[actix_web::test]
    async fn test_no_token_request() {
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .to_request();

        let resp = call_service(&app, req).await;
        assert_eq!("401", resp.status().as_str());
    }

    #[actix_web::test]
    async fn test_pass_check() {
        let mut jwt = ScopedJwToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: Utc::now().naive_utc(),
            unique_id: "unique_id".to_string(),
            role: Some("ADMIN".to_string()),
            entity_id: None,
            entity_type: None
        };
        jwt.update_time();
        let token = jwt.encode().unwrap();
        
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .insert_header(("token", token))
            .to_request();

        let resp = call_service(&app, req).await;
        assert_eq!("200", resp.status().as_str());
    }

    #[actix_web::test]
    async fn test_expired_check() {
        let dt = DateTime::parse_from_str("1983 Apr 13 12:09:14.274 +0000", "%Y %b %d %H:%M:%S%.3f %z").unwrap().naive_utc();
        let mut jwt = ScopedJwToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: dt,
            unique_id: "unique_id".to_string(),
            role: Some("ADMIN".to_string()),
            entity_id: None,
            entity_type: None
        };
        let token = jwt.encode().unwrap();
        
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .insert_header(("token", token))
            .to_request();

        let resp = call_service(&app, req).await;

        let status = resp.status();
        assert_eq!("401", status.as_str());

        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!("token expired", body);
    }

}
