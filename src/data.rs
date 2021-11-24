use std::collections::HashMap;
use std::fs;

pub fn load_data(database: &str) -> HashMap<String, String> {
  let db_file = ["./", database, ".json"].join("");
  let data: String = fs::read_to_string(db_file).unwrap_or_else(|_| "{}".to_string());
  serde_json::from_str(&data).unwrap_or_default()
}

pub fn save_data(database: &str, data: &HashMap<String, String>) -> std::io::Result<()> {
  let db_file = ["./", database, ".json"].join("");    
  let save = serde_json::to_string(&data).unwrap();
  fs::write(db_file, save)?;
  Ok(())
}