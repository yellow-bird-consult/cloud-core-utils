use serde::{
    Deserialize,
    Serialize,
    ser::Serializer,
    de::{self, Deserializer},
};


/// The different entities that can issue licenses.
/// 
/// # Fields
/// * Department: a department can issue licenses
/// * Institution: an institution can issue licenses
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum EntityType {
    Department,
    Institution,
}


impl<'de> Deserialize<'de> for EntityType {

    fn deserialize<D>(deserializer: D) -> Result<EntityType, D::Error>
        where
            D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "department" => Ok(EntityType::Department),
            "institution" => Ok(EntityType::Institution),
            _ => Err(de::Error::custom(format!("unknown issue type: {}", s))),
        }
    }
}


impl Serialize for EntityType {

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let s = match self {
            EntityType::Department => "department",
            EntityType::Institution => "institution",
        };
        serializer.serialize_str(s)
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_entity_type_deserialize() {
        let json = r#""department""#;
        let entity_type: EntityType = serde_json::from_str(json).unwrap();
        assert_eq!(entity_type, EntityType::Department);
    }

    #[test]
    fn test_entity_type_serialize() {
        let entity_type = EntityType::Department;
        let json = serde_json::to_string(&entity_type).unwrap();
        assert_eq!(json, r#""department""#);
    }
}
