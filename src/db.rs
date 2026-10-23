use rusqlite::{
    Connection,
    Result,
    Row
};
use crate::db::KeyType::{
    Expired,
    Valid
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

#[derive(PartialEq)]
pub enum KeyType{
    Valid,
    Expired
}

pub fn map_key(row: &Row) -> Result<Key> {
    let kid: i64 = row.get(0)?;
    let pem: String = row.get(1)?;
    let exp: i64 = row.get(2)?;
    return Ok(Key::from_pem(
        kid.to_string(),
        exp as u64,
        &pem,
    ))
}

pub fn get_key(connection: &Connection, key_type: KeyType, now: u64) -> Result<Key> {
    let mut statement = if key_type == Valid {
        connection.prepare(
            "SELECT kid, key, exp
             FROM keys
             WHERE exp > ?1
             LIMIT 1"
        )?
    } else {
        connection.prepare(
            "SELECT kid, key, exp
             FROM keys
             WHERE exp <= ?1
             LIMIT 1"
        )?
    };
    let key = statement.query_row(
        [now as i64],
        |row| map_key(&row),
    )?;
    return Ok(key);
}

pub fn get_valid_key_set(connection: &Connection, current: u64) -> Result<Vec<Key>> {
    let mut statement = connection.prepare(
        "SELECT kid, key, exp
         FROM keys
         WHERE exp > ?1"
    )?;
    let keys = statement.query_map(
        [current as i64],
        |row| map_key(&row),
    )?;
    return keys.collect()
}