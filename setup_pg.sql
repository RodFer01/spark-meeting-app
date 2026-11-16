-- spark-meeting-app — PostgreSQL schema
-- Run once on a fresh database:  psql -d spark_meeting -f setup_pg.sql

CREATE TABLE IF NOT EXISTS spark_sessions (
    id          VARCHAR(128) PRIMARY KEY,
    title       VARCHAR(512),
    area        VARCHAR(128),
    data_json   TEXT,
    updated_at  VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_registrations (
    id          VARCHAR(256) PRIMARY KEY,
    email       VARCHAR(256),
    session     VARCHAR(1024),
    attended    BOOLEAN DEFAULT FALSE,
    data_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_reg_email   ON spark_registrations(email);
CREATE INDEX IF NOT EXISTS idx_reg_session ON spark_registrations(session);

CREATE TABLE IF NOT EXISTS spark_users (
    id          VARCHAR(128) PRIMARY KEY,
    email       VARCHAR(256) UNIQUE,
    data_json   TEXT
);

CREATE TABLE IF NOT EXISTS spark_ess_templates (
    key         VARCHAR(256) PRIMARY KEY,
    container   VARCHAR(256),
    slot        VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS spark_email_jobs (
    id          VARCHAR(128) PRIMARY KEY,
    status      VARCHAR(64),
    to_email    VARCHAR(256),
    to_name     VARCHAR(256),
    subject     TEXT,
    html        TEXT,
    container   VARCHAR(256),
    slot        VARCHAR(256),
    created_at  VARCHAR(64),
    updated_at  VARCHAR(64),
    from_email  VARCHAR(256),
    error       TEXT
);

CREATE TABLE IF NOT EXISTS spark_intelligence_snapshots (
    id           VARCHAR(256) PRIMARY KEY,
    session      VARCHAR(512),
    session_area VARCHAR(128),
    analyzed_at  VARCHAR(64),
    data_json    TEXT
);

CREATE TABLE IF NOT EXISTS spark_analytics_campaigns (
    id          VARCHAR(256) PRIMARY KEY,
    data_json   TEXT,
    uploaded_at VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_analytics_registrations (
    id          VARCHAR(256) PRIMARY KEY,
    data_json   TEXT,
    uploaded_at VARCHAR(64)
);

-- These are created automatically by the app on first use,
-- but pre-creating them here avoids the runtime CREATE TABLE call.

CREATE TABLE IF NOT EXISTS spark_activity_log (
    id          VARCHAR(64) PRIMARY KEY,
    user_email  VARCHAR(256),
    user_name   TEXT,
    action      VARCHAR(128),
    entity      VARCHAR(128),
    entity_id   VARCHAR(256),
    detail      TEXT,
    created_at  VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_list_sources (
    id          VARCHAR(64) PRIMARY KEY,
    name        TEXT,
    description TEXT,
    created_at  VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_campaigns (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(256),
    lob         VARCHAR(128),
    description TEXT,
    owner       VARCHAR(256),
    start_date  VARCHAR(32),
    end_date    VARCHAR(32),
    created_at  VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_campaign_contacts (
    id                    VARCHAR(128) PRIMARY KEY,
    campaign_id           VARCHAR(64),
    planning_entity_name  VARCHAR(512),
    first_name            VARCHAR(256),
    last_name             VARCHAR(256),
    email                 VARCHAR(256),
    lob                   VARCHAR(128),
    erp                   VARCHAR(128),
    country               VARCHAR(128),
    role                  VARCHAR(256),
    invited               BOOLEAN DEFAULT FALSE,
    invite_status         VARCHAR(64),
    campaign_ref          TEXT,
    invited_at            VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_cc_campaign ON spark_campaign_contacts(campaign_id);

CREATE TABLE IF NOT EXISTS spark_presence (
    user_id     VARCHAR(128) PRIMARY KEY,
    user_email  VARCHAR(256),
    user_name   VARCHAR(256),
    last_seen   VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS spark_crm_sessions (
    id                  VARCHAR(128) PRIMARY KEY,
    title               VARCHAR(512),
    presentation_date   VARCHAR(64),
    area                VARCHAR(128),
    target_audience     VARCHAR(256),
    regions             VARCHAR(256),
    imported_at         VARCHAR(64),
    solution_advisor    VARCHAR(256),
    crm_id              VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS spark_crm_leads (
    id              VARCHAR(128) PRIMARY KEY,
    fecha           VARCHAR(128),
    sesion          VARCHAR(512),
    empresa         VARCHAR(512),
    imported_at     VARCHAR(64),
    crm_session_id  VARCHAR(128),
    mu              VARCHAR(256),
    pais            VARCHAR(256),
    area            VARCHAR(128),
    sales_qualifier VARCHAR(512)
);
