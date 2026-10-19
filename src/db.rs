use rusqlite::{
    Connection,
    Result
};

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

    Ok(connection)
}