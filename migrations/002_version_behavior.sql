CREATE TYPE version_change_type AS ENUM (
	'files_removed',
	'license_changed',
	'manifest_changed',
	'dependencies_changed',
	'permissions_changed'
);

CREATE TABLE version_diffs (
	id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	package_id      UUID NOT NULL REFERENCES packages (id) ON DELETE CASCADE,
	from_version    TEXT NOT NULL,
	to_version      TEXT NOT NULL,
	change_type     version_change_type NOT NULL,
	description     TEXT NOT NULL,
	severity        severity_level NOT NULL DEFAULT 'low',
	detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT version_diffs_unique UNIQUE (package_id, from_version, to_version, change_type)
);

CREATE INDEX idx_version_diffs_package ON version_diffs (package_id);
CREATE INDEX idx_version_diffs_type ON version_diffs (change_type);
CREATE INDEX idx_version_diffs_severity ON version_diffs (severity);
