//! Defines extracting config variables.
use std::env;


/// Defines the trait for getting config variables
pub trait GetConfigVariable {

    /// Gets the config variable
    /// 
    /// # Arguments
    /// * `variable` - The name of the config variable to get
    /// 
    /// # Returns
    /// * `Result<String, String>` - The result of getting the config variable
    fn get_config_variable(variable: String) -> Result<String, String>;
}


/// Defines the struct for getting config variables from the environment
pub struct EnvConfig;

impl GetConfigVariable for EnvConfig {

    /// Gets the config variable from the environment
    /// 
    /// # Arguments
    /// * `variable` - The name of the config variable to get
    /// 
    /// # Returns
    /// * `Result<String, String>` - The result of getting the config variable
    fn get_config_variable(variable: String) -> Result<String, String> {
        match env::var(&variable) {
            Ok(val) => Ok(val),
            Err(_) => Err(format!("{} is not set", variable))
        }
    }
}
