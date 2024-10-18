-- Start a transaction
BEGIN TRANSACTION;

-- Create a new table with the desired structure
CREATE TABLE no_consent_new (
    id INTEGER PRIMARY KEY,
    created DATETIME NOT NULL,
    edited DATETIME NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    school VARCHAR(120) NOT NULL,
    moodle_id VARCHAR(50),
    year INTEGER NOT NULL DEFAULT (strftime('%Y', 'now'))
);

-- Copy data from the old table to the new one
INSERT INTO no_consent_new (id, created, edited, email, school, moodle_id)
SELECT id, created, edited, email, school, moodle_id FROM no_consent;

-- Update the year for existing rows (you might want to adjust this logic)
UPDATE no_consent_new SET year = strftime('%Y', created);

-- Drop the old table
DROP TABLE no_consent;

-- Rename the new table to the original name
ALTER TABLE no_consent_new RENAME TO no_consent;

-- Commit the transaction
COMMIT;

-- Vacuum the database to optimize it after the changes
VACUUM;