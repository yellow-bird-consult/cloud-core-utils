//! defines the middleware for a refresh that expires after a certain amount of time.
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::config::GetConfigVariable;

#[cfg(feature = "actix")]
use futures::future::{Ready, ok, err};

#[cfg(feature = "actix")]
use actix_web::{
    dev::Payload, 
    Error, 
    FromRequest, 
    HttpRequest, 
    error::ErrorUnauthorized
};


/// The attributes extracted from the scoped auth token hiding in the header.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenBody {
    pub user_id: i32,
    pub unique_id: String,
    pub expire_time: NaiveDateTime
}


/// JWT for authentication that can expire for an API request.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
/// * `unique_id`: the unique ID of the session
/// * `expire_time`: the time the token expires
/// * `handle`: the handle for the config struct to get config variables
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken<X: GetConfigVariable> {
    pub user_id: i32,
    pub unique_id: String,
    pub expire_time: NaiveDateTime,
    pub handle: Option<X>
}


impl <X: GetConfigVariable>RefreshToken<X> {

    /// Gets the secret key from the environment for encoding and decoding tokens.
    ///
    /// # Returns
    /// the key from the environment
    pub fn get_key() -> Result<String, String> {
        let key = <X>::get_config_variable("REFRESH_SECRET_KEY".to_string())?;
        return Ok(key)
    }

    /// Gets the expire time from the environment for encoding and decoding tokens.
    /// 
    /// # Returns
    /// the expire time from the environment
    pub fn get_expire_mins() -> Result<usize, String> {
        let expire_mins = <X>::get_config_variable("REFRESH_EXPIRE_MINS".to_string())?;
        let expire_mins = expire_mins.parse::<usize>().map_err(|_| "REFRESH_EXPIRE_MINS is not a number".to_string())?;
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
        let expire_mins = RefreshToken::<X>::get_expire_mins().unwrap();
        let expire_time = Utc::now().naive_utc() + chrono::Duration::minutes(expire_mins as i64);
        self.expire_time = expire_time;
    }

    /// Encodes the struct into a token.
    ///
    /// # Returns
    /// encoded token with fields of the current struct
    pub fn encode(&mut self) -> Result<String, String> {
        let key = EncodingKey::from_secret(RefreshToken::<X>::get_key()?.as_ref());
        let body = RefreshTokenBody {
            user_id: self.user_id,
            expire_time: self.expire_time,
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
    pub fn decode(token: &str) -> Result<RefreshTokenBody, String> {
        let key = DecodingKey::from_secret(RefreshToken::<X>::get_key()?.as_ref());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.remove("exp");

        match decode::<RefreshTokenBody>(token, &key, &validation) {
            Ok(token_data) => return Ok(token_data.claims),
            Err(error) => return Err(error.to_string())
        };
    }

}


#[cfg(feature = "actix")]
impl<X: GetConfigVariable> FromRequest for RefreshToken<X> {
    type Error = Error;
    type Future = Ready<Result<RefreshToken<X>, Error>>;

    /// This gets fired when the JwToken is attached to a request. It fires before the request hits the view.
    /// # Arguments
    /// The arguments are needed in order for the impl of FromRequest to work.
    ///
    /// * req (&HttpRequest): the request that the token is going to be extracted from
    /// * _ (Payload): the payload stream (not used in this function but is needed)
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {

        match req.headers().get("refresh_token") {
            Some(data) => {
                let raw_token = data.to_str().unwrap().to_string();
                let token_result = RefreshToken::<X>::decode(&raw_token.as_str());

                match token_result {
                    Ok(token) => {
                        let jwt = RefreshToken::<X> {
                            user_id: token.user_id,
                            handle: None,
                            expire_time: token.expire_time,
                            unique_id: token.unique_id
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
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "actix")]
    use chrono::{DateTime, Utc};

    #[cfg(feature = "actix")]
    use serde_json::json;

    #[cfg(feature = "actix")]
    use actix_web::{
        self, body, web, App, HttpRequest, HttpResponse, 
        http::header::ContentType, 
        test::{TestRequest, init_service, call_service},
    };
    

    struct FakeConfig;

    impl GetConfigVariable for FakeConfig {

        fn get_config_variable(variable: String) -> Result<String, String> {
            match variable.as_str() {
                "REFRESH_SECRET_KEY" => Ok("secret".to_string()),
                "REFRESH_EXPIRE_MINS" => Ok("20".to_string()),
                _ => Ok("".to_string())
            }
        }

    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ResponseFromTest {
        pub user_id: i32,
    }

    #[cfg(feature = "actix")]
    async fn pass_handle(token: RefreshToken<FakeConfig>, _: HttpRequest) -> HttpResponse {
        return HttpResponse::Ok().json(json!({
            "user_id": token.user_id,
            "unique_id": token.unique_id,
            "expire_time": token.expire_time
        }))
    }

    #[test]
    fn test_encode_decode() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1bmlxdWVfaWQiOiJ1bmlxdWVfaWQiLCJleHBpcmVfdGltZSI6IjIwMjEtMDEtMDdUMDY6MTM6MjAifQ.sm2pefMwYAio4QvdU3dOrCf6nRVnfmTmUN56egQhKso";
        let seconds_since_epoch = 1_610_000_000;
        let naive_date_time = NaiveDateTime::from_timestamp_opt(seconds_since_epoch, 0).unwrap();
        let mut jwt = RefreshToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: naive_date_time,
            unique_id: "unique_id".to_string()
        };
        let token = jwt.encode().unwrap();
        assert_eq!(token, expected_token);
    }

    #[test]
    fn test_decode_token() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1bmlxdWVfaWQiOiJ1bmlxdWVfaWQiLCJleHBpcmVfdGltZSI6IjIwMjMtMTItMTJUMjM6NDM6MDMuNzEyMjc2In0.z_-G5d3gXhxHwhVyMPehbcw_E6vXo8OCzdQgGyde7pI";
        let decoded_token = RefreshToken::<FakeConfig>::decode(expected_token).unwrap();
        assert_eq!(decoded_token.user_id, 1);
        assert_eq!(decoded_token.unique_id, "unique_id");
    }

    #[cfg(feature = "actix")]
    #[actix_web::test]
    async fn test_no_token_request() {
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .to_request();

        let resp = call_service(&app, req).await;
        assert_eq!("401", resp.status().as_str());
    }

    #[cfg(feature = "actix")]
    #[actix_web::test]
    async fn test_pass_check() {
        let mut jwt = RefreshToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: Utc::now().naive_utc(),
            unique_id: "unique_id".to_string()
        };
        jwt.update_time();
        let token = jwt.encode().unwrap();
        
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .insert_header(("refresh_token", token))
            .to_request();

        let resp = call_service(&app, req).await;
        assert_eq!("200", resp.status().as_str());
    }

    #[cfg(feature = "actix")]
    #[actix_web::test]
    async fn test_expired_check() {
        let dt = DateTime::parse_from_str("1983 Apr 13 12:09:14.274 +0000", "%Y %b %d %H:%M:%S%.3f %z").unwrap().naive_utc();
        let mut jwt = RefreshToken { 
            user_id: 1,
            handle: Some(FakeConfig),
            expire_time: dt,
            unique_id: "unique_id".to_string()
        };
        let token = jwt.encode().unwrap();
        
        let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
        let req = TestRequest::default()
            .insert_header(ContentType::plaintext())
            .insert_header(("refresh_token", token))
            .to_request();

        let resp = call_service(&app, req).await;

        let status = resp.status();
        assert_eq!("401", status.as_str());

        let body = body::to_bytes(resp.into_body()).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!("token expired", body);
    }

}
