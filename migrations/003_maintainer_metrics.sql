CREATE TABLE maintainer_metrics (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_name    TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    repo_url        TEXT,
    days_since_push INTEGER NOT NULL DEFAULT 9999,
    releases_last_year INTEGER NOT NULL DEFAULT 0,
    open_issues     INTEGER NOT NULL DEFAULT 0,
    stars           INTEGER NOT NULL DEFAULT 0,
    forks           INTEGER NOT NULL DEFAULT 0,
    contributor_count INTEGER NOT NULL DEFAULT 0,
    reputation_score REAL NOT NULL DEFAULT 0.5,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT maintainer_metrics_unique UNIQUE (package_name, ecosystem)
);

CREATE INDEX idx_maintainer_metrics_package ON maintainer_metrics (package_name);
CREATE INDEX idx_maintainer_metrics_score ON maintainer_metrics (reputation_score);
