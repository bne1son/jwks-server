use rusqlite::{
    Connection,
    Result
};
use crate::key::Key;

pub fn init_db() -> Result<Connection> {
    let connection = Connection::open(
        "totally_not_my_privateKeys.db"
    )?;
    connection.execute(
        "CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )",
        [],
    )?;
    return Ok(connection);
}

pub fn insert_key(connection: &Connection, key: &Key) -> Result<()> {
    let pem = key.private_to_pem();
    connection.execute(
        "INSERT INTO keys (key, exp) VALUES (?1, ?2)",
        (&pem, key.expires_at() as i64)
    )?;
    return Ok(());
}

pub fn get_key(connection: &Connection, current_time: u64) -> Result<Key> {
    let mut statement = connection.prepare(
        "SELECT kid, key, exp
         FROM keys
         WHERE exp > ?1
         LIMIT 1"
    )?;
    let key = statement.query_row(
        [current_time as i64],
        |row| {
            let kid: i64 = row.get(0)?;
            let pem: String = row.get(1)?;
            let exp: i64 = row.get(2)?;
            Ok(Key::from_pem(
                kid.to_string(),
                exp as u64,
                &pem
            ))
        }
    )?;
    return Ok(key);
}