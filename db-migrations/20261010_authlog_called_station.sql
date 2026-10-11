-- Existing installations: preserve historical post-auth rows; older entries have no Called-Station-Id.
ALTER TABLE radpostauth ADD COLUMN calledstationid VARCHAR(50) NOT NULL DEFAULT '' AFTER callingstationid;
