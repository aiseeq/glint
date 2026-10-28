package patterntest

const SyncMigrations = `CREATE TABLE journals (id UUID PRIMARY KEY, status TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE postings (id UUID PRIMARY KEY, journal_id UUID NOT NULL REFERENCES journals(id), account TEXT, amount NUMERIC, period TEXT);
CREATE TABLE batches (id UUID PRIMARY KEY, name TEXT, notes TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE batch_members (batch_id UUID NOT NULL REFERENCES batches(id), member TEXT NOT NULL);
CREATE TABLE items (id UUID PRIMARY KEY, batch_id UUID REFERENCES batches(id), note TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

CREATE OR REPLACE FUNCTION touch_row() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER batches_touch BEFORE UPDATE ON batches FOR EACH ROW EXECUTE FUNCTION touch_row();
`
