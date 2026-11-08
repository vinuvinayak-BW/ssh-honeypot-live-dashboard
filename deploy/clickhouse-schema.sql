-- ClickHouse schema for events shipped by forwarder.py.
--
-- Apply with:
--   clickhouse-client --secure --host ch.example.com --user honeypot \
--     --password '...' --queries-file deploy/clickhouse-schema.sql
--
-- ReplacingMergeTree(ingested_at) plus the event id in ORDER BY makes retries
-- converge: duplicates with the same (src_ip, ts, id) keep the newest row.
-- Use FINAL or OPTIMIZE TABLE ... FINAL when you need deduplicated reads.
--
-- The password column contains plaintext attempted credentials.  Restrict
-- access to this table and apply a retention policy that matches your policy
-- for logs/events.jsonl.

CREATE DATABASE IF NOT EXISTS ssh_honeypot;

CREATE TABLE IF NOT EXISTS ssh_honeypot.events
(
    id               String,
    ts               DateTime64(3, 'UTC'),
    event            LowCardinality(String),
    connection_id    String,
    src_ip           String,
    src_port         UInt16,
    client_version   String,
    username         String,
    auth_type        LowCardinality(String),
    password         String,
    key_type         String,
    key_bits         Nullable(UInt32),
    key_fingerprint  String,
    external         Bool,
    dshield_listed   Bool,
    source_id        LowCardinality(String),
    source_name      String,
    source_url       String,
    external_id      String,
    reports          Nullable(Int64),
    targets          Nullable(Int64),
    rank             Nullable(Int64),
    severity         String,
    category         String,
    first_seen       String,
    last_seen        String,
    geo_lat          Nullable(Float64),
    geo_lon          Nullable(Float64),
    geo_city         String,
    geo_country      String,
    geo_country_code LowCardinality(String),
    geo_region       String,
    geo_source       LowCardinality(String),
    geo_status       LowCardinality(String),
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64(3),

    INDEX idx_username username TYPE bloom_filter GRANULARITY 4,
    INDEX idx_source_id source_id TYPE set(100) GRANULARITY 4,
    INDEX idx_country geo_country_code TYPE set(300) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (src_ip, ts, id);

-- Optional retention (uncomment and adjust):
-- ALTER TABLE ssh_honeypot.events
--     MODIFY TTL toDateTime(ts) + INTERVAL 365 DAY;
