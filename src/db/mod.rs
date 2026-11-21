mod query_logger;

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use diesel::{
    Connection, RunQueryDsl,
    connection::SimpleConnection,
    r2d2::{CustomizeConnection, Pool, PooledConnection},
};
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    CONFIG,
    error::{Error, MapResult},
};

// These changes are based on Rocket 0.5-rc wrapper of Diesel: https://github.com/SergioBenitez/Rocket/blob/v0.5-rc/contrib/sync_db_pools
// A wrapper around spawn_blocking that propagates panics to the calling code.
pub async fn run_blocking<F, R>(job: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(ret) => ret,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => unreachable!("spawn_blocking tasks are never cancelled"),
        },
    }
}

// This is used to generate the main DbConn and DbPool enums, which contain one variant for each database supported
#[derive(diesel::MultiConnection)]
pub enum DbConnInner {
    #[cfg(mysql)]
    Mysql(diesel::mysql::MysqlConnection),
    #[cfg(postgresql)]
    Postgresql(diesel::pg::PgConnection),
    #[cfg(sqlite)]
    Sqlite(diesel::sqlite::SqliteConnection),
}

/// Custom connection manager that implements manual connection establishment
pub struct DbConnManager {
    database_url: String,
}

impl DbConnManager {
    pub fn new(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_owned(),
        }
    }

    fn establish_connection(&self) -> Result<DbConnInner, diesel::r2d2::Error> {
        match DbConnType::from_url(&self.database_url) {
            #[cfg(mysql)]
            Ok(DbConnType::Mysql) => {
                let conn = diesel::mysql::MysqlConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Mysql(conn))
            }
            #[cfg(postgresql)]
            Ok(DbConnType::Postgresql) => {
                let conn = diesel::pg::PgConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Postgresql(conn))
            }
            #[cfg(sqlite)]
            Ok(DbConnType::Sqlite) => {
                let conn = diesel::sqlite::SqliteConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Sqlite(conn))
            }

            Err(e) => Err(diesel::r2d2::Error::ConnectionError(diesel::ConnectionError::InvalidConnectionUrl(
                format!("Unable to estabilsh a connection: {e:?}"),
            ))),
        }
    }
}

impl diesel::r2d2::ManageConnection for DbConnManager {
    type Connection = DbConnInner;
    type Error = diesel::r2d2::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        self.establish_connection()
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        use diesel::r2d2::R2D2Connection;
        conn.ping().map_err(diesel::r2d2::Error::QueryError)
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        use diesel::r2d2::R2D2Connection;
        conn.is_broken()
    }
}

#[derive(Eq, PartialEq)]
pub enum DbConnType {
    #[cfg(mysql)]
    Mysql,
    #[cfg(postgresql)]
    Postgresql,
    #[cfg(sqlite)]
    Sqlite,
}

pub static ACTIVE_DB_TYPE: OnceLock<DbConnType> = OnceLock::new();

pub struct DbConn {
    conn: Arc<Mutex<Option<PooledConnection<DbConnManager>>>>,
    permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub struct DbConnOptions {
    pub init_stmts: String,
}

impl CustomizeConnection<DbConnInner, diesel::r2d2::Error> for DbConnOptions {
    fn on_acquire(&self, conn: &mut DbConnInner) -> Result<(), diesel::r2d2::Error> {
        if !self.init_stmts.is_empty() {
            conn.batch_execute(&self.init_stmts).map_err(diesel::r2d2::Error::QueryError)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct DbPool {
    // This is an 'Option' so that we can drop the pool in a 'spawn_blocking'.
    pool: Option<Pool<DbConnManager>>,
    semaphore: Arc<Semaphore>,
}

impl Drop for DbConn {
    fn drop(&mut self) {
        let conn = Arc::clone(&self.conn);
        let permit = self.permit.take();

        // Since connection can't be on the stack in an async fn during an
        // await, we have to spawn a new blocking-safe thread...
        tokio::task::spawn_blocking(move || {
            // And then re-enter the runtime to wait on the async mutex, but in a blocking fashion.
            let mut conn = tokio::runtime::Handle::current().block_on(conn.lock_owned());

            if let Some(conn) = conn.take() {
                drop(conn);
            }

            // Drop permit after the connection is dropped
            drop(permit);
        });
    }
}

impl Drop for DbPool {
    fn drop(&mut self) {
        let pool = self.pool.take();
        // Only use spawn_blocking if the Tokio runtime is still available
        // Otherwise the pool will be dropped on the current thread
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || drop(pool));
        }
    }
}

/// Keykeeper: how a unit test's SQLite file is named in the temporary folder
/// (`DbPool::for_test_pool_of`).
#[cfg(all(test, sqlite))]
const TEST_DATABASE_PREFIX: &str = "keykeeper-test-";

/// Keykeeper: removes the unit tests' SQLite files (and their journals) that
/// are more than an hour old, once per test run. A test's file is only used
/// while that test runs, and nothing removes it after, so without this every
/// run left a few hundred files, gigabytes after a few days. A file from a
/// run still going on is minutes old at most, so it's never touched.
#[cfg(all(test, sqlite))]
fn sweep_old_test_databases() {
    static SWEPT: OnceLock<()> = OnceLock::new();
    SWEPT.get_or_init(|| {
        if let Some(hour_ago) = std::time::SystemTime::now().checked_sub(Duration::from_secs(60 * 60)) {
            remove_test_databases(&std::env::temp_dir(), hour_ago);
        }
    });
}

/// Keykeeper: removes the unit tests' SQLite files in `dir` last changed
/// before `before`, and nothing else.
#[cfg(all(test, sqlite))]
fn remove_test_databases(dir: &std::path::Path, before: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let ours = name.to_str().is_some_and(|n| n.starts_with(TEST_DATABASE_PREFIX) && n.contains(".sqlite3"));
        let old = entry.metadata().and_then(|m| m.modified()).is_ok_and(|modified| modified < before);
        if ours && old && entry.file_type().is_ok_and(|t| t.is_file()) {
            // One that can't be removed now goes at a later run.
            drop(std::fs::remove_file(entry.path()));
        }
    }
}

#[cfg(all(test, sqlite))]
mod test_database_tests {
    use std::time::{Duration, SystemTime};

    use super::{TEST_DATABASE_PREFIX, remove_test_databases};

    /// Only a test's own files, and only old ones, go.
    #[test]
    fn old_test_databases_go_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("keykeeper-sweep-{}", crate::util::get_uuid()));
        std::fs::create_dir(&dir).unwrap();
        let two_hours_ago = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        let make = |name: &str, old: bool| {
            let path = dir.join(name);
            let file = std::fs::File::create(&path).unwrap();
            if old {
                file.set_modified(two_hours_ago).unwrap();
            }
            path
        };
        let old_db = make(&format!("{TEST_DATABASE_PREFIX}a.sqlite3"), true);
        let old_journal = make(&format!("{TEST_DATABASE_PREFIX}a.sqlite3-wal"), true);
        let new_db = make(&format!("{TEST_DATABASE_PREFIX}b.sqlite3"), false);
        let someone_elses = make("other.sqlite3", true);
        let not_a_database = make(&format!("{TEST_DATABASE_PREFIX}notes.txt"), true);

        remove_test_databases(&dir, SystemTime::now() - Duration::from_secs(60 * 60));

        assert!(!old_db.exists() && !old_journal.exists(), "an old test database and its journal go");
        assert!(new_db.exists(), "a test database from a run going on stays");
        assert!(someone_elses.exists() && not_a_database.exists(), "nothing else is touched");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

impl DbPool {
    // For the given database URL, guess its type, run migrations, create pool, and return it
    pub fn from_config() -> Result<Self, Error> {
        let db_url = CONFIG.database_url();
        let conn_type = DbConnType::from_url(&db_url)?;

        // Only set the default instrumentation if the log level is specifically set to either warn, info or debug
        if log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Warn)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Info)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Debug)
        {
            drop(diesel::connection::set_default_instrumentation(query_logger::simple_logger));
        }

        match conn_type {
            #[cfg(mysql)]
            DbConnType::Mysql => {
                mysql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(postgresql)]
            DbConnType::Postgresql => {
                postgresql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(sqlite)]
            DbConnType::Sqlite => {
                sqlite_migrations::run_migrations(&db_url)?;
            }
        }

        let max_conns = CONFIG.database_max_conns();
        let manager = DbConnManager::new(&db_url);
        let pool = Pool::builder()
            .max_size(max_conns)
            .min_idle(Some(CONFIG.database_min_conns()))
            .idle_timeout(Some(Duration::from_secs(u64::from(CONFIG.database_idle_timeout()))))
            .connection_timeout(Duration::from_secs(u64::from(CONFIG.database_timeout())))
            .connection_customizer(Box::new(DbConnOptions {
                init_stmts: conn_type.get_init_stmts(),
            }))
            .build(manager)
            .map_res("Failed to create pool")?;

        // Set a global to determine the database more easily throughout the rest of the code
        if ACTIVE_DB_TYPE.set(conn_type).is_err() {
            error!("Tried to set the active database connection type more than once.");
        }

        Ok(DbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(max_conns as usize)),
        })
    }

    /// Keykeeper: a database of its own for one unit test, a new SQLite file
    /// in the temporary folder with every migration run, so a test can call
    /// the server's own functions on real rows. Its one connection is the
    /// test's.
    #[cfg(all(test, sqlite))]
    pub async fn for_test() -> DbConn {
        Self::for_test_pool().get().await.expect("a connection to the test's database")
    }

    /// Keykeeper: the same database as a pool, for a test that hands a
    /// route its connection and then checks the rows with another.
    #[cfg(all(test, sqlite))]
    pub fn for_test_pool() -> DbPool {
        Self::for_test_pool_of(1)
    }

    /// Keykeeper: the same, with `size` connections, for a test of requests
    /// that arrive at once.
    #[cfg(all(test, sqlite))]
    pub fn for_test_pool_of(size: u32) -> DbPool {
        sweep_old_test_databases();
        let path = std::env::temp_dir().join(format!("{TEST_DATABASE_PREFIX}{}.sqlite3", crate::util::get_uuid()));
        let url = path.to_string_lossy().into_owned();
        sqlite_migrations::run_migrations(&url).expect("the migrations run");
        drop(ACTIVE_DB_TYPE.set(DbConnType::Sqlite));
        let pool = Pool::builder()
            .max_size(size)
            .connection_customizer(Box::new(DbConnOptions {
                init_stmts: DbConnType::Sqlite.default_init_stmts(),
            }))
            .build(DbConnManager::new(&url))
            .expect("a pool for the test's database");
        DbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(usize::try_from(size).expect("a pool size fits"))),
        }
    }

    /// Keykeeper: holds the test database's write lock on a connection of
    /// its own, as a write elsewhere (another request, or a scheduled job)
    /// holds it for a moment, and lets it go after `for_how_long`. Await
    /// the answer to know it's been let go.
    #[cfg(all(test, sqlite))]
    pub async fn hold_write_lock(&self, for_how_long: Duration) -> tokio::task::JoinHandle<()> {
        let busy = self.get().await.expect("a connection to hold the write lock on");
        busy.run(|conn| conn.batch_execute("BEGIN IMMEDIATE")).await.expect("the write lock");
        tokio::spawn(async move {
            tokio::time::sleep(for_how_long).await;
            busy.run(|conn| conn.batch_execute("COMMIT")).await.expect("the write lock let go");
        })
    }

    // Get a connection from the pool
    pub async fn get(&self) -> Result<DbConn, Error> {
        let duration = Duration::from_secs(u64::from(CONFIG.database_timeout()));
        let permit = match timeout(duration, Arc::clone(&self.semaphore).acquire_owned()).await {
            Ok(p) => p.expect("Semaphore should be open"),
            Err(_) => {
                err!("Timeout waiting for database connection");
            }
        };

        let p = self.pool.as_ref().expect("DbPool.pool should always be Some()");
        let pool = p.clone();
        let c =
            run_blocking(move || pool.get_timeout(duration)).await.map_res("Error retrieving connection from pool")?;
        Ok(DbConn {
            conn: Arc::new(Mutex::new(Some(c))),
            permit: Some(permit),
        })
    }
}

impl DbConnType {
    pub fn from_url(url: &str) -> Result<Self, Error> {
        // Mysql
        if url.len() > 6 && &url[..6] == "mysql:" {
            #[cfg(mysql)]
            return Ok(DbConnType::Mysql);

            #[cfg(not(mysql))]
            err!("`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled")

        // Postgresql
        } else if url.len() > 11 && (&url[..11] == "postgresql:" || &url[..9] == "postgres:") {
            #[cfg(postgresql)]
            return Ok(DbConnType::Postgresql);

            #[cfg(not(postgresql))]
            err!("`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled")

        // Sqlite (explicit)
        } else if url.len() > 7 && &url[..7] == "sqlite:" {
            #[cfg(sqlite)]
            return Ok(DbConnType::Sqlite);

            #[cfg(not(sqlite))]
            err!("`DATABASE_URL` is a SQLite URL, but the 'sqlite' feature is not enabled")
        }

        // No recognized scheme — assume legacy bare-path SQLite, but the database file must already exist.
        // This prevents misconfigured URLs (typos, quoted strings) from silently creating a new empty SQLite database.
        #[cfg(sqlite)]
        {
            if std::path::Path::new(url).exists() {
                return Ok(DbConnType::Sqlite);
            }
            err!(format!(
                "`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://) \
                    and no existing SQLite database was found at '{url}'. \
                    If you intend to use SQLite, use an explicit `sqlite://` scheme in your `DATABASE_URL`. \
                    Otherwise, check your DATABASE_URL for typos or quoting issues."
            ))
        }

        #[cfg(not(sqlite))]
        err!("`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://)")
    }

    pub fn get_init_stmts(&self) -> String {
        let init_stmts = CONFIG.database_conn_init();
        if init_stmts.is_empty() {
            self.default_init_stmts()
        } else {
            init_stmts
        }
    }

    pub fn default_init_stmts(&self) -> String {
        match self {
            #[cfg(mysql)]
            Self::Mysql => String::new(),
            #[cfg(postgresql)]
            Self::Postgresql => String::new(),
            #[cfg(sqlite)]
            // Keykeeper: foreign keys on, whichever SQLite the server is built
            // with (the bundled one has them on already), so deletes cascade
            // to tables like keykeeper_cipher_versions.
            Self::Sqlite => {
                "PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;".to_owned()
            }
        }
    }
}

impl DbConn {
    pub async fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DbConnInner) -> R + Send,
        R: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        let mut conn = conn.lock_owned().await;
        let conn = conn.as_mut().expect("Internal invariant broken: self.conn is Some");

        // Run blocking can't be used due to the 'static limitation, use block_in_place instead
        tokio::task::block_in_place(move || f(conn))
    }
}

/// Keykeeper: runs `write`, which reads and then writes, in a transaction
/// that holds the lock for its writes from its start. What it read is still
/// so when it writes, and a write at the same moment (another request, or a
/// job such as the plans' clock or event streaming's worker) waits its turn
/// instead of failing. Use it for any transaction that reads before it
/// writes.
///
/// - SQLite: `BEGIN IMMEDIATE`, which takes the database's write lock first,
///   waiting for it as long as the busy timeout allows. A transaction begun
///   the usual way that has read can't wait when it comes to write while
///   another connection writes: SQLite answers "database is locked" at once.
/// - PostgreSQL: `lock` runs first, and locks for update the row that writers
///   of the same thing all lock (the item, the organization, or the plan's
///   owner), so they go one at a time. On SQLite the transaction holds the
///   write lock already, and `lock` does nothing.
///
/// Inside a transaction the caller holds (a move to another MSP is one), it's
/// a savepoint in that transaction, which on SQLite holds the write lock
/// already.
pub fn write_locked<T>(
    conn: &mut DbConnInner,
    lock: impl FnOnce(&mut DbConnInner) -> diesel::QueryResult<()>,
    write: impl FnOnce(&mut DbConnInner) -> diesel::QueryResult<T>,
) -> diesel::QueryResult<T> {
    use diesel::connection::TransactionManager;
    type Manager = <DbConnInner as Connection>::TransactionManager;
    begin_write_locked(conn)?;
    match lock(conn).and_then(|()| write(conn)) {
        Ok(written) => {
            Manager::commit_transaction(conn)?;
            Ok(written)
        }
        // As diesel's own transactions: the error that made it roll back is
        // the one to answer, unless rolling back failed too.
        Err(e) => match Manager::rollback_transaction(conn) {
            Ok(()) | Err(diesel::result::Error::BrokenTransactionManager) => Err(e),
            Err(rollback) => Err(rollback),
        },
    }
}

/// Begins `write_locked`'s transaction: immediate on SQLite, unless the
/// caller holds one already, when it's a savepoint.
fn begin_write_locked(conn: &mut DbConnInner) -> diesel::QueryResult<()> {
    use diesel::connection::TransactionManager;
    type Manager = <DbConnInner as Connection>::TransactionManager;
    if Manager::transaction_manager_status_mut(conn).transaction_depth()?.is_some() {
        return Manager::begin_transaction(conn);
    }
    match conn {
        #[cfg(postgresql)]
        DbConnInner::Postgresql(_) => Manager::begin_transaction(conn),
        #[cfg(sqlite)]
        DbConnInner::Sqlite(sqlite) => {
            diesel::connection::AnsiTransactionManager::begin_transaction_sql(sqlite, "BEGIN IMMEDIATE")
        }
    }
}

#[macro_export]
macro_rules! db_run {
    ( $conn:ident: $body:block ) => {
        $conn.run(move |$conn| $body).await
    };

    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {
        $conn.run(move |$conn| {
            match $conn {
                $($(
                #[cfg($db)]
                pastey::paste!(&mut $crate::db::DbConnInner::[<$db:camel>](ref mut $conn)) => {
                    $body
                },
            )+)+}
        }).await
    };
}

// Write all ToSql<Text, DB> and FromSql<Text, DB> given a serializable/deserializable type.
#[macro_export]
macro_rules! impl_FromToSqlText {
    ($name:ty) => {
        #[cfg(mysql)]
        impl ToSql<Text, diesel::mysql::Mysql> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(postgresql)]
        impl ToSql<Text, diesel::pg::Pg> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(sqlite)]
        impl ToSql<Text, diesel::sqlite::Sqlite> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
                serde_json::to_string(self).map_err(Into::into).map(|str| {
                    out.set_value(str);
                    diesel::serialize::IsNull::No
                })
            }
        }

        impl<DB: diesel::backend::Backend> FromSql<Text, DB> for $name
        where
            String: FromSql<Text, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                <String as FromSql<Text, DB>>::from_sql(bytes)
                    .and_then(|str| serde_json::from_str(&str).map_err(Into::into))
            }
        }
    };
}

pub mod schema;
// Keykeeper: our own tables.
pub mod keykeeper_schema;

// Reexport the models, needs to be after the macros are defined so it can access them
pub mod models;

/// Creates a back-up of the sqlite database
/// MySQL/MariaDB and PostgreSQL are not supported.
#[cfg(sqlite)]
pub fn backup_sqlite() -> Result<String, Error> {
    use diesel::Connection;

    let db_url = CONFIG.database_url();
    if DbConnType::from_url(&CONFIG.database_url()).is_ok_and(|t| t == DbConnType::Sqlite) {
        // Strip the sqlite:// prefix if present to get the raw file path
        let file_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        // Open a read-only connection for the backup
        let mut conn = diesel::sqlite::SqliteConnection::establish(&format!("sqlite://{file_path}?mode=ro"))?;

        let db_path = std::path::Path::new(file_path).parent().unwrap();
        let backup_file = db_path
            .join(format!("db_{}.sqlite3", chrono::Utc::now().format("%Y%m%d_%H%M%S")))
            .to_string_lossy()
            .into_owned();

        diesel::sql_query("VACUUM INTO ?")
            .bind::<diesel::sql_types::Text, _>(&backup_file)
            .execute(&mut conn)
            .map(|_| ())
            .map_res("VACUUM INTO failed")?;

        Ok(backup_file)
    } else {
        err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
    }
}

#[cfg(not(sqlite))]
pub fn backup_sqlite() -> Result<String, Error> {
    err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
}

/// Get the SQL Server version
pub async fn get_sql_server_version(conn: &DbConn) -> String {
    db_run! { conn:
        postgresql,mysql {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
        }
        sqlite {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("sqlite_version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
        }
    }
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for DbConn {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.rocket().state::<DbPool>() {
            Some(p) => match p.get().await {
                Ok(dbconn) => Outcome::Success(dbconn),
                _ => Outcome::Error((Status::ServiceUnavailable, ())),
            },
            None => Outcome::Error((Status::InternalServerError, ())),
        }
    }
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Establish a connection to the sqlite database (this will create a new one, if it does
        // not exist, and exit if there is an error).
        let mut connection = diesel::sqlite::SqliteConnection::establish(db_url)?;

        // Run the migrations after successfully establishing a connection
        // Disable Foreign Key Checks during migration
        // Scoped to a connection.
        diesel::sql_query("PRAGMA foreign_keys = OFF")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        // Turn on WAL in SQLite
        if crate::CONFIG.enable_db_wal() {
            diesel::sql_query("PRAGMA journal_mode=wal").execute(&mut connection).expect("Failed to turn on WAL");
        }

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(mysql)]
mod mysql_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::mysql::MysqlConnection::establish(db_url)?;

        // Disable Foreign Key Checks during migration
        // Scoped to a connection/session.
        diesel::sql_query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(postgresql)]
mod postgresql_migrations {
    use diesel::Connection;
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgresql");

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::pg::PgConnection::establish(db_url)?;

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

// Keykeeper: diesel runs one migration per version (a folder's name up to its
// first underscore), so a folder whose version another already has never runs,
// and its tables are missing from every new database. Two branches made the
// same day can each take the day's first version.
#[cfg(test)]
mod migration_version_tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn every_migration_has_a_version_of_its_own() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        for backend in ["sqlite", "mysql", "postgresql"] {
            let mut seen: BTreeMap<String, String> = BTreeMap::new();
            for entry in std::fs::read_dir(root.join(backend)).unwrap() {
                let entry = entry.unwrap();
                if !entry.file_type().unwrap().is_dir() {
                    continue;
                }
                let name = entry.file_name().into_string().unwrap();
                let version = name.split('_').next().unwrap().replace('-', "");
                if let Some(other) = seen.insert(version, name.clone()) {
                    panic!("{backend}: {other} and {name} have the same version, so only one of them runs");
                }
            }
        }
    }
}
