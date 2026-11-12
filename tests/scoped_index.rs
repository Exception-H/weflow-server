//! Prevent scoped watchers from loading unrelated histories or replaying trimmed rows.
//! Fixtures build real encrypted source databases, never inject in-memory index contents.
mod common;

use std::sync::Arc;
use parking_lot::RwLock;
use weflow_server::db::{live::LivePool, scan};
use weflow_server::keystore::{self, KeyMap};
use weflow_server::store::{index, IndexScope, Store};
use weflow_server::sync::{AccountSync, Event};

#[test]
fn scoped_tail_merges_shards_and_leaves_other_conversations_unindexed() {
    let dir = common::tmp_dir("scoped-shards");
    let key = keystore::parse_db_key(common::FAKE_KEY_HEX).unwrap();
    let storage = common::build_wechat_account(&dir, &key.0);
    let table = format!("Msg_{}", common::md5_hex(common::FAKE_GROUP));
    let connection = common::wx_conn(&storage.join("message/message_1.db"), &key.0, false);
    connection.execute_batch(&format!(
        "CREATE TABLE \"{table}\" (local_id INTEGER PRIMARY KEY, server_id INTEGER,
         local_type INTEGER, create_time INTEGER, sort_seq INTEGER, sender_username TEXT,
         message_content TEXT);
         INSERT INTO \"{table}\" VALUES (1, 90001, 1, 1900000000, 0, 'friend', 'latest one'),
                                      (2, 90002, 1, 1900000001, 0, 'friend', 'latest two');"
    )).unwrap();
    drop(connection);
    let scope = IndexScope { sessions: vec![common::FAKE_GROUP.into()], messages_per_session: Some(2) };
    let mut pool = LivePool::new();
    let files = scan::enum_db_files(&storage);
    let store = index::build_scoped_live(&mut pool, &KeyMap::from(key), common::FAKE_WXID,
        &files, &index::IndexProgress::default(), &scope).unwrap();
    assert_eq!(store.convs.len(), 1);
    let records = &store.convs[common::FAKE_GROUP];
    assert_eq!(records.iter().map(|row| row.create_time).collect::<Vec<_>>(), vec![1900000000, 1900000001]);
    assert_eq!(store.watermarks[&format!("message/message_1.db:{table}")].local_id, 2);
}

#[test]
fn trimmed_tail_does_not_replay_events_or_stop_incremental_watermarks() {
    let dir = common::tmp_dir("scoped-incremental");
    let key = keystore::parse_db_key(common::FAKE_KEY_HEX).unwrap();
    let storage = common::build_wechat_account(&dir, &key.0);
    let store = Arc::new(RwLock::new(Store::default()));
    let mut sync = AccountSync::new(common::FAKE_WXID, &storage, KeyMap::from(key), store.clone());
    sync.configure(IndexScope { sessions: vec![common::FAKE_GROUP.into()], messages_per_session: Some(2) }, None);
    sync.full_sync().unwrap();
    sync.drain_events();
    for sequence in 0..7 {
        common::append_group_message_unique(&storage, &key.0, sequence);
    }
    assert_eq!(sync.poll_once().unwrap().0, 7);
    let events = sync.drain_events();
    assert_eq!(events.iter().filter(|event| matches!(event, Event::New(_))).count(), 7);
    assert_eq!(store.read().convs[common::FAKE_GROUP].len(), 2);
    assert_eq!(sync.poll_once().unwrap(), (0, 0));
    assert!(sync.drain_events().is_empty());
}

#[test]
fn corrected_key_closes_a_warm_connection_and_recovers_a_rejected_key() {
    let dir = common::tmp_dir("scoped-key-reload");
    let key = keystore::parse_db_key(common::FAKE_KEY_HEX).unwrap();
    let storage = common::build_wechat_account(&dir, &key.0);
    let file = scan::enum_db_files(&storage).into_iter()
        .find(|file| file.rel == "message/message_0.db").unwrap();
    let replacement = keystore::DbKey([0xab; 32]);
    let mut pool = LivePool::new();
    pool.get_or_open(&file, key).unwrap();
    let connection = common::wx_conn(&file.abs, &key.0, false);
    connection.execute_batch(&format!("PRAGMA rekey = \"x'{}'\"", hex::encode(replacement.0))).unwrap();
    drop(connection);
    // A changed registered key must replace the old SQLCipher connection, not just its key string.
    let connection = pool.get_or_open(&file, replacement).unwrap();
    assert!(connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0)).unwrap() > 0);
    let mut rejected = LivePool::new();
    assert!(rejected.get_or_open(&file, key).is_err());
    assert!(rejected.is_keyless(&file.rel));
    assert!(rejected.get_or_open(&file, replacement).is_ok());
}

#[test]
fn external_registration_refresh_makes_a_new_message_shard_visible() {
    let dir = common::tmp_dir("scoped-new-shard");
    let key = keystore::parse_db_key(common::FAKE_KEY_HEX).unwrap();
    let storage = common::build_wechat_account(&dir, &key.0);
    let mut mapping = std::collections::HashMap::new();
    mapping.insert("session/session.db".into(), common::FAKE_KEY_HEX.to_owned());
    mapping.insert("message/message_0.db".into(), common::FAKE_KEY_HEX.to_owned());
    let keys = KeyMap::from_parts(None, Some(mapping.clone())).unwrap();
    let store = Arc::new(RwLock::new(Store::default()));
    let mut sync = AccountSync::new(common::FAKE_WXID, &storage, keys, store.clone());
    let registration = dir.join("registration.json");
    sync.configure(IndexScope { sessions: vec![common::FAKE_GROUP.into()], messages_per_session: Some(2) }, Some(registration.clone()));
    sync.full_sync().unwrap();
    sync.drain_events();
    let table = format!("Msg_{}", common::md5_hex(common::FAKE_GROUP));
    let connection = common::wx_conn(&storage.join("message/message_1.db"), &key.0, false);
    connection.execute_batch(&format!(
        "CREATE TABLE \"{table}\" (local_id INTEGER PRIMARY KEY, server_id INTEGER,
         local_type INTEGER, create_time INTEGER, sort_seq INTEGER, sender_username TEXT, message_content TEXT);
         INSERT INTO \"{table}\" VALUES (1, 99001, 1, 1900000000, 0, 'friend', 'new shard');"
    )).unwrap();
    drop(connection);
    mapping.insert("message/message_1.db".into(), common::FAKE_KEY_HEX.to_owned());
    std::fs::write(&registration, serde_json::to_vec(&serde_json::json!({
        "wxid": common::FAKE_WXID, "db_path": storage, "keys": mapping
    })).unwrap()).unwrap();
    assert_eq!(sync.poll_once().unwrap().0, 1);
    assert!(store.read().convs[common::FAKE_GROUP].iter().any(|row| row.server_id == 99001));
}

#[test]
fn invalid_library_retention_is_rejected_before_indexing() {
    let scope = IndexScope { sessions: Vec::new(), messages_per_session: Some(0) };
    let result = index::build_scoped_live(&mut LivePool::new(), &KeyMap::Empty, "fake", &[],
        &index::IndexProgress::default(), &scope);
    assert!(result.is_err());
}
