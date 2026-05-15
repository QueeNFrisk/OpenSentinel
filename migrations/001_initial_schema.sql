CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE advisory_source AS ENUM ('osv', 'github', 'nvd', 'mitre');
CREATE TYPE severity_level AS ENUM ('safe', 'low', 'medium', 'high', 'critical');
CREATE TYPE pattern_type AS ENUM (
    'credential_harvesting',
    'crypto_mining',
    'network_exfiltration',
    'install_hook',
    'typosquatting',
    'reverseshell_code',
    'obfuscated_code'
);

CREATE TABLE packages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    registry_url    TEXT,
    checksum        TEXT,
    is_direct       BOOLEAN NOT NULL DEFAULT false,
    depth           INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT packages_unique UNIQUE (name, version, ecosystem)
);

CREATE INDEX idx_packages_name ON packages (name);
CREATE INDEX idx_packages_ecosystem ON packages (ecosystem);

CREATE TABLE scan_results (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_path    TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    total_packages  INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    safe_count      INTEGER NOT NULL DEFAULT 0,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_results_path ON scan_results (project_path);
CREATE INDEX idx_scan_results_scanned_at ON scan_results (scanned_at DESC);

CREATE TABLE scan_packages (
    scan_id         UUID NOT NULL REFERENCES scan_results (id) ON DELETE CASCADE,
    package_id      UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, package_id)
);

CREATE TABLE dependencies (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    parent_id           UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    child_id            UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    version_constraint  TEXT NOT NULL,
    is_dev              BOOLEAN NOT NULL DEFAULT false,
    is_optional         BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT dep_unique UNIQUE (parent_id, child_id)
);

CREATE INDEX idx_dependencies_parent ON dependencies (parent_id);
CREATE INDEX idx_dependencies_child ON dependencies (child_id);

CREATE TABLE advisories (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_id          UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    source              advisory_source NOT NULL,
    external_id         TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    severity            severity_level NOT NULL,
    cvss_score          REAL,
    affected_versions   TEXT NOT NULL,
    patched_versions    TEXT,
    published_at        TIMESTAMPTZ,
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT advisories_unique UNIQUE (package_id, source, external_id)
);

CREATE INDEX idx_advisories_package ON advisories (package_id);
CREATE INDEX idx_advisories_severity ON advisories (severity);
CREATE INDEX idx_advisories_source ON advisories (source);

CREATE TABLE detected_patterns (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_id      UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    pattern_type    pattern_type NOT NULL,
    description     TEXT NOT NULL,
    file_path       TEXT,
    line_number     INTEGER,
    code_snippet    TEXT,
    confidence      REAL NOT NULL DEFAULT 0.0,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_patterns_package ON detected_patterns (package_id);
CREATE INDEX idx_patterns_type ON detected_patterns (pattern_type);

CREATE TABLE mitre_mappings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pattern_id      UUID NOT NULL REFERENCES detected_patterns (id) ON DELETE CASCADE,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    url             TEXT NOT NULL,
    CONSTRAINT mitre_unique UNIQUE (pattern_id, technique_id)
);

CREATE TABLE risk_scores (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_id          UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
    scan_id             UUID NOT NULL REFERENCES scan_results (id) ON DELETE CASCADE,
    overall_severity    severity_level NOT NULL,
    advisory_score      REAL NOT NULL DEFAULT 0.0,
    pattern_score       REAL NOT NULL DEFAULT 0.0,
    reputation_score    REAL NOT NULL DEFAULT 0.0,
    final_score         REAL NOT NULL DEFAULT 0.0,
    recommendation      TEXT NOT NULL DEFAULT '',
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT risk_scores_unique UNIQUE (package_id, scan_id)
);

CREATE INDEX idx_risk_scores_scan ON risk_scores (scan_id);
CREATE INDEX idx_risk_scores_severity ON risk_scores (overall_severity);

CREATE TABLE ignored_advisories (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_path    TEXT NOT NULL,
    advisory_id     UUID REFERENCES advisories (id) ON DELETE CASCADE,
    external_id     TEXT,
    reason          TEXT,
    ignored_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
