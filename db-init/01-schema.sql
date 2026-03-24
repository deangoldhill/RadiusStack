
CREATE TABLE IF NOT EXISTS radcheck ( id int(11) unsigned NOT NULL auto_increment, username varchar(64) NOT NULL default '', attribute varchar(64)  NOT NULL default '', op char(2) NOT NULL default '==', value varchar(253) NOT NULL default '', PRIMARY KEY  (id), KEY username (username(32)) );
CREATE TABLE IF NOT EXISTS radreply ( id int(11) unsigned NOT NULL auto_increment, username varchar(64) NOT NULL default '', attribute varchar(64) NOT NULL default '', op char(2) NOT NULL default '=', value varchar(253) NOT NULL default '', PRIMARY KEY  (id), KEY username (username(32)) );
CREATE TABLE IF NOT EXISTS radgroupcheck ( id int(11) unsigned NOT NULL auto_increment, groupname varchar(64) NOT NULL default '', attribute varchar(64)  NOT NULL default '', op char(2) NOT NULL default '==', value varchar(253)  NOT NULL default '', PRIMARY KEY  (id), KEY groupname (groupname(32)) );
CREATE TABLE IF NOT EXISTS radgroupreply ( id int(11) unsigned NOT NULL auto_increment, groupname varchar(64) NOT NULL default '', attribute varchar(64)  NOT NULL default '=', op char(2) NOT NULL default '=', value varchar(253)  NOT NULL default '', PRIMARY KEY  (id), KEY groupname (groupname(32)) );
CREATE TABLE IF NOT EXISTS radusergroup ( id int(11) unsigned NOT NULL auto_increment, username varchar(64) NOT NULL default '', groupname varchar(64) NOT NULL default '', priority int(11) NOT NULL default '1', PRIMARY KEY  (id), KEY username (username(32)) );
CREATE TABLE IF NOT EXISTS radacct ( radacctid bigint(21) NOT NULL auto_increment, acctsessionid varchar(64) NOT NULL default '', acctuniqueid varchar(32) NOT NULL default '', username varchar(64) NOT NULL default '', realm varchar(64) default '', nasipaddress varchar(15) NOT NULL default '', nasportid varchar(32) default NULL, nasporttype varchar(32) default NULL, acctstarttime datetime NULL default NULL, acctupdatetime datetime NULL default NULL, acctstoptime datetime NULL default NULL, acctinterval int(12) default NULL, acctsessiontime int(12) unsigned default NULL, acctauthentic varchar(32) default NULL, connectinfo_start varchar(128) default NULL, connectinfo_stop varchar(128) default NULL, acctinputoctets bigint(20) default NULL, acctoutputoctets bigint(20) default NULL, calledstationid varchar(50) NOT NULL default '', callingstationid varchar(50) NOT NULL default '', acctterminatecause varchar(32) NOT NULL default '', servicetype varchar(32) default NULL, framedprotocol varchar(32) default NULL, framedipaddress varchar(15) NOT NULL default '', framedipv6address varchar(45) NOT NULL default '', framedipv6prefix varchar(45) NOT NULL default '', framedinterfaceid varchar(44) NOT NULL default '', delegatedipv6prefix varchar(45) NOT NULL default '', PRIMARY KEY (radacctid), UNIQUE KEY acctuniqueid (acctuniqueid), KEY username (username(32)), KEY framedipaddress (framedipaddress), KEY acctsessionid (acctsessionid(32)), KEY acctsessiontime (acctsessiontime), KEY acctstarttime (acctstarttime), KEY acctinterval (acctinterval), KEY acctstoptime (acctstoptime), KEY nasipaddress (nasipaddress) );
CREATE TABLE IF NOT EXISTS radpostauth ( id int(11) NOT NULL auto_increment, username varchar(64) NOT NULL default '', pass varchar(64) NOT NULL default '', reply varchar(32) NOT NULL default '', authdate timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6), class varchar(64) NOT NULL default '', PRIMARY KEY  (id), KEY username (username(32)), KEY class (class) );
CREATE TABLE IF NOT EXISTS nas ( id int(10) NOT NULL auto_increment, nasname varchar(128) NOT NULL, shortname varchar(32) default NULL, type varchar(30) default 'other', ports int(5) default NULL, secret varchar(60) NOT NULL default 'secret', server varchar(64) default NULL, community varchar(50) default NULL, description varchar(200) default 'RADIUS Client', PRIMARY KEY  (id), KEY nasname (nasname) );

CREATE TABLE IF NOT EXISTS admins ( id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, require_password_change BOOLEAN DEFAULT FALSE, two_factor_enabled BOOLEAN DEFAULT FALSE, two_factor_secret VARCHAR(100), two_factor_setup_complete BOOLEAN DEFAULT FALSE, api_key VARCHAR(100) UNIQUE, permissions JSON NOT NULL );
CREATE TABLE IF NOT EXISTS settings ( setting_key VARCHAR(50) PRIMARY KEY, setting_value VARCHAR(255) );

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    admin_username VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6),
    origin VARCHAR(10) NOT NULL,
    action TEXT NOT NULL,
    result VARCHAR(20) NOT NULL,
    details TEXT,
    ip_address VARCHAR(50),
    KEY idx_admin (admin_username),
    KEY idx_timestamp (timestamp),
    KEY idx_result (result)
);

INSERT INTO settings (setting_key, setting_value) VALUES ('enforce_2fa', 'false') ON DUPLICATE KEY UPDATE setting_key=setting_key;
INSERT INTO nas (nasname, shortname, secret, description) VALUES ('127.0.0.1', 'all', 'testing123', 'Sample internal-only NAS');

INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('ui_theme', 'blue');


CREATE TABLE IF NOT EXISTS plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) UNIQUE,
  data_limit_mb INT DEFAULT 0,
  time_limit_seconds INT DEFAULT 0,
  reset_period ENUM('daily', 'weekly', 'monthly', 'never') DEFAULT 'never'
);

CREATE TABLE IF NOT EXISTS user_plans (
  username VARCHAR(64) PRIMARY KEY,
  plan_id INT,
  manual_reset_date DATETIME,
  FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_plan_usage (
  username VARCHAR(64) PRIMARY KEY,
  cycle_started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  base_input_octets BIGINT UNSIGNED NOT NULL DEFAULT 0,
  base_output_octets BIGINT UNSIGNED NOT NULL DEFAULT 0,
  base_session_seconds BIGINT UNSIGNED NOT NULL DEFAULT 0,
  KEY idx_cycle_started_at (cycle_started_at)
);


CREATE TABLE IF NOT EXISTS user_totp (
    username varchar(64) NOT NULL,
    enabled tinyint(1) NOT NULL DEFAULT 0,
    secret varchar(64) DEFAULT NULL,
    pending_secret varchar(64) DEFAULT NULL,
    enrolled_at datetime DEFAULT NULL,
    enrollment_code_hash varchar(255) DEFAULT NULL,
    enrollment_expires_at datetime DEFAULT NULL,
    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (username),
    KEY idx_user_totp_enabled (enabled)
);
