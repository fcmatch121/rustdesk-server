use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Peer {
    // Modified: web console — extract "ip" from the info JSON blob
    pub fn info_ip(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.info)
            .ok()
            .and_then(|v| v.get("ip").and_then(|x| x.as_str().map(|s| s.to_owned())))
            .unwrap_or_default()
    }
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}

// ---------- console (web UI) storage ----------
// Uses runtime (unchecked) queries because the console tables are created at
// runtime and are unknown to the compile-time query macros.
impl Database {
    pub async fn console_init(&self) -> ResultType<()> {
        sqlx::query(
            "
            create table if not exists console_config (
                key varchar(100) primary key not null,
                value text not null
            );
            create table if not exists console_events (
                ts integer not null,
                kind varchar(50) not null,
                peer_id varchar(300) not null,
                detail text not null
            );
            create table if not exists console_geo (
                ip text primary key not null,
                country text not null default '',
                city text not null default '',
                lat real not null default 0,
                lon real not null default 0,
                updated_at integer not null default 0
            );
            create table if not exists console_peer_location (
                id varchar(300) primary key not null,
                country text not null default '',
                city text not null default '',
                lat real not null default 0,
                lon real not null default 0
            );
            ",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn console_get_config(&self, key: &str) -> ResultType<Option<String>> {
        use sqlx::Row;
        let row = sqlx::query("select value from console_config where key = ?")
            .bind(key)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.map(|r| r.get::<String, _>("value")))
    }

    pub async fn console_set_config(&self, key: &str, value: &str) -> ResultType<()> {
        sqlx::query("replace into console_config (key, value) values (?, ?)")
            .bind(key)
            .bind(value)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn console_add_event(
        &self,
        kind: &str,
        peer_id: &str,
        detail: &str,
    ) -> ResultType<()> {
        sqlx::query("insert into console_events (ts, kind, peer_id, detail) values (?, ?, ?, ?)")
            .bind(crate::common::now() as i64)
            .bind(kind)
            .bind(peer_id)
            .bind(detail)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        // keep the log bounded
        sqlx::query("delete from console_events where ts <= (select ts from console_events order by ts desc limit -1 offset 5000)")
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn console_get_events(
        &self,
        limit: i64,
    ) -> ResultType<Vec<serde_json::Value>> {
        use sqlx::Row;
        let rows = sqlx::query(
            "select ts, kind, peer_id, detail from console_events order by ts desc limit ?",
        )
        .bind(limit)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "ts": r.get::<i64, _>("ts"),
                    "kind": r.get::<String, _>("kind"),
                    "peer_id": r.get::<String, _>("peer_id"),
                    "detail": r.get::<String, _>("detail"),
                })
            })
            .collect())
    }

    pub async fn console_set_geo(
        &self,
        ip: &str,
        country: &str,
        city: &str,
        lat: f64,
        lon: f64,
    ) -> ResultType<()> {
        sqlx::query("replace into console_geo (ip, country, city, lat, lon, updated_at) values (?, ?, ?, ?, ?, ?)")
            .bind(ip)
            .bind(country)
            .bind(city)
            .bind(lat)
            .bind(lon)
            .bind(crate::common::now() as i64)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn console_list_geo(
        &self,
    ) -> ResultType<std::collections::HashMap<String, serde_json::Value>> {
        use sqlx::Row;
        let rows = sqlx::query("select ip, country, city, lat, lon from console_geo")
            .fetch_all(self.pool.get().await?.deref_mut())
            .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("ip"),
                    serde_json::json!({
                        "country": r.get::<String, _>("country"),
                        "city": r.get::<String, _>("city"),
                        "lat": r.get::<f64, _>("lat"),
                        "lon": r.get::<f64, _>("lon"),
                    }),
                )
            })
            .collect())
    }

    pub async fn console_set_location(
        &self,
        id: &str,
        country: &str,
        city: &str,
        lat: f64,
        lon: f64,
    ) -> ResultType<()> {
        sqlx::query("replace into console_peer_location (id, country, city, lat, lon) values (?, ?, ?, ?, ?)")
            .bind(id)
            .bind(country)
            .bind(city)
            .bind(lat)
            .bind(lon)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn console_delete_location(&self, id: &str) -> ResultType<()> {
        sqlx::query("delete from console_peer_location where id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn console_list_locations(
        &self,
    ) -> ResultType<std::collections::HashMap<String, serde_json::Value>> {
        use sqlx::Row;
        let rows =
            sqlx::query("select id, country, city, lat, lon from console_peer_location")
                .fetch_all(self.pool.get().await?.deref_mut())
                .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("id"),
                    serde_json::json!({
                        "country": r.get::<String, _>("country"),
                        "city": r.get::<String, _>("city"),
                        "lat": r.get::<f64, _>("lat"),
                        "lon": r.get::<f64, _>("lon"),
                    }),
                )
            })
            .collect())
    }

    pub async fn console_distinct_countries(&self) -> ResultType<i64> {
        use sqlx::Row;
        let row = sqlx::query(
            "select count(distinct country) as n from (
                select country from console_peer_location where country != ''
                union
                select country from console_geo where country != ''
            )",
        )
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row.get::<i64, _>("n"))
    }

    pub async fn list_peers(&self) -> ResultType<Vec<Peer>> {
        let peers = sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer"
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(peers)
    }

    pub async fn count_peers(&self) -> ResultType<i64> {
        use sqlx::Row;
        let row = sqlx::query("select count(*) as n from peer")
            .fetch_one(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.get::<i64, _>("n"))
    }

    // ---------- console v2: peer management actions ----------

    /// Modified: console v2 — remove a peer row (and its manual location) entirely.
    pub async fn console_delete_peer(&self, id: &str) -> ResultType<()> {
        sqlx::query("delete from peer where id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        sqlx::query("delete from console_peer_location where id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Modified: console v2 — disable / re-enable a device. status=0 means the
    /// console blocked this peer: hbbs refuses punch-hole and relay requests
    /// for it, so no connection can be established.
    pub async fn console_set_peer_disabled(&self, id: &str, disabled: bool) -> ResultType<()> {
        let status: Option<i64> = if disabled { Some(0) } else { None };
        sqlx::query("update peer set status = ? where id = ?")
            .bind(status)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }
}
