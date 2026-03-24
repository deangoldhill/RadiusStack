FROM freeradius/freeradius-server:3.2.3-alpine

RUN apk add --no-cache openssl mariadb-client mariadb-connector-c

RUN ln -s /opt/etc/raddb/mods-available/sql /opt/etc/raddb/mods-enabled/sql

# Completely overwrite the SQL module file to prevent any ghost variables or TLS requirements
RUN cat << 'EOF' > /opt/etc/raddb/mods-available/sql
sql {
    driver = "rlm_sql_mysql"
    dialect = "mysql"
    server = "mariadb"
    port = 3306
    login = "radius"
    password = "radiusdbpass"
    radius_db = "radius"
    read_clients = yes
    read_groups = yes
    read_profiles = yes

    # Default string attributes
    group_attribute = "SQL-Group"

    # Table configuration for queries.conf
    acct_table1 = "radacct"
    acct_table2 = "radacct"
    postauth_table = "radpostauth"
    authcheck_table = "radcheck"
    authreply_table = "radreply"
    groupcheck_table = "radgroupcheck"
    groupreply_table = "radgroupreply"
    usergroup_table = "radusergroup"
    client_table = "nas"

    group_membership_query = "SELECT groupname FROM radusergroup WHERE username = '%{SQL-User-Name}' ORDER BY priority"

    $INCLUDE ${modconfdir}/${.:name}/main/${dialect}/queries.conf
}
EOF


RUN sed -i 's/^[[:space:]]*#[[:space:]]*sql[[:space:]]*$/\tsql/g' /opt/etc/raddb/sites-available/default && \
    sed -i 's/^[[:space:]]*#[[:space:]]*sql[[:space:]]*$/\tsql/g' /opt/etc/raddb/sites-available/inner-tunnel && \
    sed -i 's/^[[:space:]]*#[[:space:]]*-sql[[:space:]]*$/\t-sql/g' /opt/etc/raddb/sites-available/default && \
    sed -i 's/^[[:space:]]*#[[:space:]]*-sql[[:space:]]*$/\t-sql/g' /opt/etc/raddb/sites-available/inner-tunnel

RUN sed -i 's|private_key_file =.*|private_key_file = /certs_shared/server.key|g' /opt/etc/raddb/mods-available/eap && \
    sed -i 's|certificate_file =.*|certificate_file = /certs_shared/server.pem|g' /opt/etc/raddb/mods-available/eap

# 1. Ensure the deprecated automatic copying is OFF
RUN sed -i 's/use_tunneled_reply = yes/use_tunneled_reply = no/g' /opt/etc/raddb/mods-available/eap

# 2. Fixed Filter: Explicitly use outer.session-state to avoid parse errors
RUN awk '/post-auth \{/ && !done { \
    print; \
    print "\tupdate reply {"; \
    print "\t\t&MS-MPPE-Send-Key !* ANY"; \
    print "\t\t&MS-MPPE-Recv-Key !* ANY"; \
    print "\t\t&MS-MPPE-Encryption-Policy !* ANY"; \
    print "\t\t&MS-MPPE-Encryption-Types !* ANY"; \
    print "\t\t&EAP-Message !* ANY"; \
    print "\t\t&Message-Authenticator !* ANY"; \
    print "\t}"; \
    print "\tupdate outer.session-state {"; \
    print "\t\t&outer.session-state: := &reply:[*]"; \
    print "\t}"; \
    done=1; next } 1' /opt/etc/raddb/sites-available/inner-tunnel > /tmp/inner-tunnel.tmp && \
    mv /tmp/inner-tunnel.tmp /opt/etc/raddb/sites-available/inner-tunnel

RUN mkdir -p /opt/etc/raddb/policy.d
RUN cat << 'EOF' > /opt/etc/raddb/policy.d/check_plan_limits
plan_cycle_baseline {
    update request {
        &Tmp-String-0 := "%{sql: INSERT INTO user_plan_usage (username, cycle_started_at, base_input_octets, base_output_octets, base_session_seconds) SELECT up.username, NOW(), COALESCE(SUM(a.acctinputoctets), 0), COALESCE(SUM(a.acctoutputoctets), 0), COALESCE(SUM(a.acctsessiontime), 0) FROM user_plans up LEFT JOIN radacct a ON a.username = up.username LEFT JOIN user_plan_usage pu ON pu.username = up.username WHERE up.username = '%{User-Name}' AND pu.username IS NULL GROUP BY up.username}"
        &Tmp-String-1 := "%{sql: UPDATE user_plan_usage pu JOIN user_plans up ON up.username = pu.username JOIN plans p ON p.id = up.plan_id LEFT JOIN (SELECT username, COALESCE(SUM(acctinputoctets), 0) AS total_input_octets, COALESCE(SUM(acctoutputoctets), 0) AS total_output_octets, COALESCE(SUM(acctsessiontime), 0) AS total_session_seconds FROM radacct WHERE username = '%{User-Name}' GROUP BY username) t ON t.username = pu.username SET pu.cycle_started_at = NOW(), pu.base_input_octets = COALESCE(t.total_input_octets, 0), pu.base_output_octets = COALESCE(t.total_output_octets, 0), pu.base_session_seconds = COALESCE(t.total_session_seconds, 0) WHERE pu.username = '%{User-Name}' AND ((p.reset_period = 'daily' AND DATE(pu.cycle_started_at) < CURDATE()) OR (p.reset_period = 'weekly' AND YEARWEEK(pu.cycle_started_at, 1) < YEARWEEK(CURDATE(), 1)) OR (p.reset_period = 'monthly' AND DATE_FORMAT(pu.cycle_started_at, '%Y-%m') < DATE_FORMAT(CURDATE(), '%Y-%m')))}"
    }
}

check_plan_limits {
    plan_cycle_baseline

    update request {
        &Tmp-String-2 := "%{sql: SELECT CASE WHEN p.data_limit_mb > 0 AND ((COALESCE(t.total_input_octets, 0) - COALESCE(pu.base_input_octets, 0) + COALESCE(t.total_output_octets, 0) - COALESCE(pu.base_output_octets, 0)) / 1048576) >= p.data_limit_mb THEN 'EXCEEDED' WHEN p.time_limit_seconds > 0 AND (COALESCE(t.total_session_seconds, 0) - COALESCE(pu.base_session_seconds, 0)) >= p.time_limit_seconds THEN 'EXCEEDED' ELSE 'OK' END FROM user_plans up JOIN plans p ON p.id = up.plan_id LEFT JOIN user_plan_usage pu ON pu.username = up.username LEFT JOIN (SELECT username, COALESCE(SUM(acctinputoctets), 0) AS total_input_octets, COALESCE(SUM(acctoutputoctets), 0) AS total_output_octets, COALESCE(SUM(acctsessiontime), 0) AS total_session_seconds FROM radacct WHERE username = '%{User-Name}' GROUP BY username) t ON t.username = up.username WHERE up.username = '%{User-Name}' LIMIT 1}"
    }

    if (&Tmp-String-2 == "EXCEEDED") {
        update reply {
            &Reply-Message := "Access Denied: Plan limits exceeded"
        }
        reject
    }
}
EOF

RUN cat << 'EOF' > /opt/etc/raddb/policy.d/strict_nas
strict_nas_check {
    update request {
        # 1. Get the group for the user [cite: 14]
        &Tmp-String-1 := "%{sql: SELECT groupname FROM radusergroup WHERE username = '%{User-Name}' LIMIT 1}"
        
        # 2. Check if this group even has a NAS restriction [cite: 2]
        &Tmp-Integer-0 := "%{sql: SELECT COUNT(*) FROM radgroupcheck WHERE groupname = '%{Tmp-String-1}' AND attribute = 'NAS-IP-Address'}"
        
        # 3. FIX: Use %{request:NAS-IP-Address} or the fallback %{outer.request:NAS-IP-Address}
        # This syntax works for both standard and tunneled requests
        &Tmp-Integer-1 := "%{sql: SELECT COUNT(*) FROM radgroupcheck WHERE groupname = '%{Tmp-String-1}' AND attribute = 'NAS-IP-Address' AND value = '%{%{outer.request:NAS-IP-Address}:-%{NAS-IP-Address}}'}"
    }
    
    # 
    if (&Tmp-String-1 != "" && &Tmp-Integer-0 > 0 && &Tmp-Integer-1 == 0) {
        update reply {
            &Reply-Message := "Access Denied: NAS-IP-Address not permitted"
        }
        reject
    }
}
EOF

RUN awk '/post-auth \{/ && !done { print; print "\tcheck_plan_limits\n\tstrict_nas_check"; done=1; next } 1' /opt/etc/raddb/sites-available/default > /tmp/default.tmp && mv /tmp/default.tmp /opt/etc/raddb/sites-available/default &&     awk '/post-auth \{/ && !done { print; print "\tcheck_plan_limits\n\tstrict_nas_check"; done=1; next } 1' /opt/etc/raddb/sites-available/inner-tunnel > /tmp/inner-tunnel.tmp && mv /tmp/inner-tunnel.tmp /opt/etc/raddb/sites-available/inner-tunnel

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
