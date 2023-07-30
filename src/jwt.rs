//! defines the middleware for the views that require authentication.
use actix_web::dev::Payload;
use actix_web::{Error, FromRequest, HttpRequest};
use actix_web::error::ErrorUnauthorized;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use futures::future::{Ready, ok, err};
use crate::config::GetConfigVariable;


/// The attributes extracted from the auth token hiding in the header.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenBody {
    pub user_id: i32
}


/// JWT for authentication for an API request.
/// 
/// # Fields
/// * `user_id`: the ID of the user who's token it belongs to
/// * `handle`: the handle of the user who's token it belongs to
#[derive(Debug, Serialize, Deserialize)]
pub struct JwToken<X: GetConfigVariable> {
    pub user_id: i32,
    pub handle: Option<X>
}


impl <X: GetConfigVariable>JwToken<X> {

    /// Gets the secret key from the environment for encoding and decoding tokens.
    ///
    /// # Returns
    /// the key from the environment
    pub fn get_key() -> Result<String, String> {
        let key = <X>::get_config_variable("SECRET_KEY".to_string())?;
        return Ok(key)
    }

    /// Encodes the struct into a token.
    ///
    /// # Returns
    /// encoded token with fields of the current struct
    pub fn encode(self) -> Result<String, String> {
        let key = EncodingKey::from_secret(JwToken::<X>::get_key()?.as_ref());

        let body = TokenBody {
            user_id: self.user_id
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
    pub fn decode(token: &str) -> Result<TokenBody, String> {
        let key = DecodingKey::from_secret(JwToken::<X>::get_key()?.as_ref());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.remove("exp");

        match decode::<TokenBody>(token, &key, &validation) {
            Ok(token_data) => return Ok(token_data.claims),
            Err(error) => return Err(error.to_string())
        };
    }

}


impl<X: GetConfigVariable> FromRequest for JwToken<X> {
    type Error = Error;
    type Future = Ready<Result<JwToken<X>, Error>>;

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
                let token_result = JwToken::<X>::decode(&raw_token.as_str());

                match token_result {
                    Ok(token) => {
                        let jwt = JwToken::<X> {
                            user_id: token.user_id,
                            handle: None
                        };
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
    use actix_web;
    use serde_json::json;
    use serde::{Deserialize, Serialize};

    struct FakeConfig;

    impl GetConfigVariable for FakeConfig {

        fn get_config_variable(variable: String) -> Result<String, String> {
            match variable.as_str() {
                "SECRET_KEY" => Ok("secret".to_string()),
                _ => Ok("".to_string())
            }
        }

    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ResponseFromTest {
        pub user_id: i32,
    }

    async fn pass_handle(token: JwToken<FakeConfig>, _: HttpRequest) -> HttpResponse {
        return HttpResponse::Ok().json(json!({"user_id": token.user_id}))
    }

    #[test]
    fn test_encode_decode() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.J_RIIkoOLNXtd5IZcEwaBDGKGA3VnnYmuXnmhsmDEOs";
        let jwt = JwToken { 
            user_id: 1,
            handle: Some(FakeConfig)
        };
        let encoded_token = jwt.encode().unwrap();
        assert_eq!(encoded_token, expected_token);
    }

    #[test]
    fn test_decode_token() {
        let expected_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.J_RIIkoOLNXtd5IZcEwaBDGKGA3VnnYmuXnmhsmDEOs";
        let decoded_token = JwToken::<FakeConfig>::decode(expected_token).unwrap();
        assert_eq!(decoded_token.user_id, 1);
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
            
            let app = init_service(App::new().route("/", web::get().to(pass_handle))).await;
            let req = TestRequest::default()
                .insert_header(ContentType::plaintext())
                .insert_header(("token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.J_RIIkoOLNXtd5IZcEwaBDGKGA3VnnYmuXnmhsmDEOs"))
                .to_request();
    
            let resp = call_service(&app, req).await;
            assert_eq!("200", resp.status().as_str());
    }

}
