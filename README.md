# MySQL Installation Guide

MySQL is a free and open-source relational database management system (RDBMS). Originally developed by Michael "Monty" Widenius and now owned by Oracle Corporation, MySQL is the world's second-most widely used relational database management system. It serves as a FOSS alternative to commercial databases like Oracle Database, Microsoft SQL Server, or IBM Db2, offering enterprise-grade reliability, performance, and scalability without licensing costs, with features like ACID compliance, transactions, replication, and clustering.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (4+ cores recommended for production)
  - RAM: 1GB minimum (8GB+ recommended for production)
  - Storage: 5GB minimum (SSD recommended for performance)
  - Network: Stable connectivity for replication setups
- **Operating System**: 
  - Linux: Any modern distribution with kernel 2.6+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 3306 (default MySQL port)
  - Port 33060 (MySQL X Protocol)
  - Additional ports for replication and clustering
- **Dependencies**:
  - libc6, libssl, zlib (usually included in distributions)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Add MySQL official repository
sudo dnf install -y https://dev.mysql.com/get/mysql80-community-release-el9-1.noarch.rpm

# Import MySQL GPG key
sudo rpm --import https://repo.mysql.com/RPM-GPG-KEY-mysql-2022

# Install MySQL server
sudo dnf install -y mysql-community-server mysql-community-client

# Enable and start service
sudo systemctl enable --now mysqld

# Get temporary root password
sudo grep 'temporary password' /var/log/mysqld.log

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo firewall-cmd --permanent --add-service=mysql
sudo firewall-cmd --reload
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install prerequisite packages
sudo apt install -y wget lsb-release gnupg

# Add MySQL APT repository
wget https://dev.mysql.com/get/mysql-apt-config_0.8.29-1_all.deb
sudo dpkg -i mysql-apt-config_0.8.29-1_all.deb

# Update package index
sudo apt update

# Install MySQL server
sudo apt install -y mysql-server mysql-client

# Enable and start service
sudo systemctl enable --now mysql

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo ufw allow mysql
```

### Arch Linux

```bash
# Install MySQL from official repositories
sudo pacman -S mysql

# Initialize database
sudo mysqld --initialize --user=mysql --basedir=/usr --datadir=/var/lib/mysql

# Enable and start service
sudo systemctl enable --now mysqld

# Get temporary root password
sudo cat /var/lib/mysql/$(hostname).err | grep 'temporary password'

# Secure installation
sudo mysql_secure_installation

# Optional: Install MariaDB instead (more common on Arch)
sudo pacman -S mariadb
sudo mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
sudo systemctl enable --now mariadb
```

### Alpine Linux

```bash
# Install MySQL (MariaDB is the default MySQL implementation)
apk add --no-cache mariadb mariadb-client

# Initialize database
mysql_install_db --user=mysql --datadir=/var/lib/mysql

# Create mysql user if not exists
adduser -D -H -s /sbin/nologin mysql

# Set permissions
chown -R mysql:mysql /var/lib/mysql

# Enable and start service
rc-update add mariadb default
rc-service mariadb start

# Secure installation
mysql_secure_installation
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y mysql-community-server mysql-community-client

# Alternative: Install MariaDB (more commonly available)
sudo zypper install -y mariadb mariadb-client mariadb-tools

# SLES 15
sudo SUSEConnect -p sle-module-server-applications/15.5/x86_64
sudo zypper install -y mariadb mariadb-client

# Initialize database (MariaDB)
sudo mysql_install_db --user=mysql

# Enable and start service
sudo systemctl enable --now mysql
# or for MariaDB:
sudo systemctl enable --now mariadb

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo firewall-cmd --permanent --add-service=mysql
sudo firewall-cmd --reload
```

### macOS

```bash
# Using Homebrew
brew install mysql

# Start MySQL service
brew services start mysql

# Or run manually
mysql.server start

# Secure installation
mysql_secure_installation

# Configuration location: /usr/local/etc/my.cnf
# Alternative: /opt/homebrew/etc/my.cnf (Apple Silicon)

# Alternative: Install MariaDB
brew install mariadb
brew services start mariadb
```

### FreeBSD

```bash
# Using pkg
pkg install mysql80-server mysql80-client

# Using ports
cd /usr/ports/databases/mysql80-server
make install clean

# Enable MySQL
echo 'mysql_enable="YES"' >> /etc/rc.conf

# Initialize database
service mysql-server start

# Secure installation
mysql_secure_installation

# Configuration location: /usr/local/etc/mysql/my.cnf
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install mysql

# Method 2: Using Scoop
scoop bucket add main
scoop install mysql

# Method 3: Manual installation
# Download MySQL Installer from https://dev.mysql.com/downloads/installer/
# Run mysql-installer-community-8.0.xx.x.msi

# Install as Windows service
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld" --install MySQL80
net start MySQL80

# Configuration location: C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
```

## Initial Configuration

### First-Run Setup

1. **Create mysql user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/mysql -s /sbin/nologin -c "MySQL Server" mysql
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/my.cnf`
- Debian/Ubuntu: `/etc/mysql/mysql.conf.d/mysqld.cnf`
- Arch Linux: `/etc/my.cnf`
- Alpine Linux: `/etc/my.cnf.d/mariadb-server.cnf`
- openSUSE/SLES: `/etc/my.cnf`
- macOS: `/usr/local/etc/my.cnf`
- FreeBSD: `/usr/local/etc/mysql/my.cnf`
- Windows: `C:\ProgramData\MySQL\MySQL Server 8.0\my.ini`

3. **Essential settings to change**:

```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf
[mysqld]
# Basic settings
bind-address = 127.0.0.1
port = 3306
socket = /var/run/mysqld/mysqld.sock
datadir = /var/lib/mysql

# Security settings
sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
local_infile = 0
skip_name_resolve = 1

# Character set
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

# Performance settings
max_connections = 200
thread_cache_size = 50
table_open_cache = 2048

# InnoDB settings
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2

# Logging
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Binary logging (for replication)
log_bin = mysql-bin
binlog_format = ROW
expire_logs_days = 7
```

### Testing Initial Setup

```bash
# Check if MySQL is running
sudo systemctl status mysql

# Test connection
mysql -u root -p -e "SELECT VERSION();"

# Check user accounts
mysql -u root -p -e "SELECT User, Host FROM mysql.user;"

# Test database operations
mysql -u root -p -e "CREATE DATABASE test_db; DROP DATABASE test_db;"

# Check configuration
mysql -u root -p -e "SHOW VARIABLES LIKE 'character_set%';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'collation%';"
```

**WARNING:** Change the default root password immediately and remove anonymous users!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable MySQL to start on boot
sudo systemctl enable mysql

# Start MySQL
sudo systemctl start mysql

# Stop MySQL
sudo systemctl stop mysql

# Restart MySQL
sudo systemctl restart mysql

# Reload configuration
sudo systemctl reload mysql

# Check status
sudo systemctl status mysql

# View logs
sudo journalctl -u mysql -f
```

### OpenRC (Alpine Linux)

```bash
# Enable MySQL/MariaDB to start on boot
rc-update add mariadb default

# Start MariaDB
rc-service mariadb start

# Stop MariaDB
rc-service mariadb stop

# Restart MariaDB
rc-service mariadb restart

# Check status
rc-service mariadb status

# View logs
tail -f /var/log/mysql/error.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'mysql_enable="YES"' >> /etc/rc.conf

# Start MySQL
service mysql-server start

# Stop MySQL
service mysql-server stop

# Restart MySQL
service mysql-server restart

# Check status
service mysql-server status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start mysql
brew services stop mysql
brew services restart mysql

# Check status
brew services list | grep mysql

# Manual control
mysql.server start
mysql.server stop
mysql.server restart
```

### Windows Service Manager

```powershell
# Start MySQL service
net start MySQL80

# Stop MySQL service
net stop MySQL80

# Using PowerShell
Start-Service MySQL80
Stop-Service MySQL80
Restart-Service MySQL80

# Check status
Get-Service MySQL80

# View logs
Get-EventLog -LogName Application -Source MySQL
```

## Advanced Configuration

### High Availability Configuration

```ini
# Master-Slave Replication Configuration
# Master server configuration
[mysqld]
server-id = 1
log_bin = mysql-bin
binlog_format = ROW
binlog_do_db = production_db

# Slave server configuration
[mysqld]
server-id = 2
relay-log = relay-bin
read_only = 1
```

### MySQL 8.0 Group Replication

```ini
# Group Replication settings
[mysqld]
# Group Replication configuration
loose-group_replication_group_name = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
loose-group_replication_start_on_boot = off
loose-group_replication_local_address = "mysql1.example.com:33061"
loose-group_replication_group_seeds = "mysql1.example.com:33061,mysql2.example.com:33061,mysql3.example.com:33061"
loose-group_replication_bootstrap_group = off

# Required settings
gtid_mode = ON
enforce_gtid_consistency = ON
master_info_repository = TABLE
relay_log_info_repository = TABLE
binlog_checksum = NONE
log_slave_updates = ON
log_bin = binlog
binlog_format = ROW
transaction_write_set_extraction = XXHASH64
```

### Advanced Security Settings

```ini
# Security hardening
[mysqld]
# SSL/TLS configuration
ssl_cert = /etc/mysql/ssl/server-cert.pem
ssl_key = /etc/mysql/ssl/server-key.pem
ssl_ca = /etc/mysql/ssl/ca-cert.pem
require_secure_transport = ON
tls_version = TLSv1.2,TLSv1.3

# Authentication
default_authentication_plugin = caching_sha2_password

# Connection security
max_user_connections = 100
max_connect_errors = 10

# Disable dangerous functions
local_infile = 0
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/mysql-proxy
upstream mysql_backend {
    server 127.0.0.1:3306 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3307 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 3306;
    proxy_pass mysql_backend;
    proxy_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/mysql.log;
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend mysql_frontend
    bind *:3306
    mode tcp
    option tcplog
    default_backend mysql_servers

backend mysql_servers
    mode tcp
    balance roundrobin
    option mysql-check user haproxy
    server mysql1 127.0.0.1:3306 check
    server mysql2 127.0.0.1:3307 check backup
```

### ProxySQL Configuration

```sql
-- ProxySQL configuration for MySQL load balancing
INSERT INTO mysql_servers(hostgroup_id, hostname, port, weight) VALUES
(0, '127.0.0.1', 3306, 900),
(0, '127.0.0.1', 3307, 100);

INSERT INTO mysql_query_rules(rule_id, active, match_pattern, destination_hostgroup, apply) VALUES
(1, 1, '^SELECT.*', 0, 1),
(2, 1, '^INSERT.*', 0, 1);

LOAD MYSQL SERVERS TO RUNTIME;
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL QUERY RULES TO DISK;
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate SSL certificates for MySQL
sudo mkdir -p /etc/mysql/ssl

# Create CA certificate
sudo openssl genrsa 2048 > /etc/mysql/ssl/ca-key.pem
sudo openssl req -new -x509 -nodes -days 3650 -key /etc/mysql/ssl/ca-key.pem -out /etc/mysql/ssl/ca-cert.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-CA"

# Create server certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/server-key.pem -out /etc/mysql/ssl/server-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=mysql.example.com"
sudo openssl rsa -in /etc/mysql/ssl/server-key.pem -out /etc/mysql/ssl/server-key.pem
sudo openssl x509 -req -in /etc/mysql/ssl/server-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 01 -out /etc/mysql/ssl/server-cert.pem

# Create client certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/client-key.pem -out /etc/mysql/ssl/client-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=mysql-client"
sudo openssl rsa -in /etc/mysql/ssl/client-key.pem -out /etc/mysql/ssl/client-key.pem
sudo openssl x509 -req -in /etc/mysql/ssl/client-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 01 -out /etc/mysql/ssl/client-cert.pem

# Set permissions
sudo chown -R mysql:mysql /etc/mysql/ssl
sudo chmod 600 /etc/mysql/ssl/*-key.pem
sudo chmod 644 /etc/mysql/ssl/*-cert.pem /etc/mysql/ssl/ca-cert.pem
```

### User Security and Privileges

```sql
-- Create secure users with SSL requirements
CREATE USER 'appuser'@'%' IDENTIFIED BY 'SecurePassword123!' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'%';

-- Create backup user
CREATE USER 'backup'@'localhost' IDENTIFIED BY 'BackupPassword123!' REQUIRE SSL;
GRANT SELECT, RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* TO 'backup'@'localhost';

-- Create monitoring user
CREATE USER 'monitor'@'localhost' IDENTIFIED BY 'MonitorPassword123!';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'monitor'@'localhost';

-- Set password policies
INSTALL COMPONENT 'file://component_validate_password';
SET GLOBAL validate_password.policy = STRONG;
SET GLOBAL validate_password.length = 12;

-- Remove dangerous defaults
DELETE FROM mysql.user WHERE User = '';
DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 3306
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=mysql
sudo firewall-cmd --permanent --zone=mysql --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=mysql --add-port=3306/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 3306 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 3306

# Windows Firewall
New-NetFirewallRule -DisplayName "MySQL" -Direction Inbound -Protocol TCP -LocalPort 3306 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### Database Creation and Management

```sql
-- Create application database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user with specific privileges
CREATE USER 'appuser'@'%' IDENTIFIED BY 'SecurePassword123!' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'%';

-- Create tables with proper character set
USE myapp;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Example of partitioned table for large datasets
CREATE TABLE logs (
    id BIGINT AUTO_INCREMENT,
    log_date DATE NOT NULL,
    message TEXT,
    PRIMARY KEY (id, log_date)
) ENGINE=InnoDB
PARTITION BY RANGE (YEAR(log_date)) (
    PARTITION p2023 VALUES LESS THAN (2024),
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);
```

### Database Optimization

```sql
-- Analyze and optimize tables
ANALYZE TABLE myapp.users;
OPTIMIZE TABLE myapp.users;

-- Check table status
SHOW TABLE STATUS FROM myapp;

-- Index optimization
SHOW INDEX FROM myapp.users;
ALTER TABLE myapp.users ADD INDEX idx_created (created_at);

-- View performance schema statistics
SELECT * FROM performance_schema.table_io_waits_summary_by_table 
WHERE OBJECT_SCHEMA = 'myapp' ORDER BY SUM_TIMER_WAIT DESC;
```

## Performance Optimization

### System Tuning

```bash
# MySQL-specific kernel parameters
sudo tee -a /etc/sysctl.conf <<EOF
# MySQL optimizations
vm.swappiness = 1
fs.file-max = 65535
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
EOF

sudo sysctl -p

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
mysql soft nofile 65535
mysql hard nofile 65535
EOF
```

### MySQL Performance Tuning

```ini
# High-performance MySQL configuration
[mysqld]
# Memory settings
innodb_buffer_pool_size = 8G  # 70-80% of available RAM
innodb_buffer_pool_instances = 8
innodb_log_file_size = 1G
innodb_log_buffer_size = 64M

# Thread settings
thread_cache_size = 100
table_open_cache = 4096
table_definition_cache = 2048

# Connection settings
max_connections = 500
max_user_connections = 450
interactive_timeout = 3600
wait_timeout = 600

# Query cache (MySQL 5.7 and earlier)
query_cache_type = 1
query_cache_size = 256M

# Temporary tables
tmp_table_size = 128M
max_heap_table_size = 128M

# MyISAM settings (if used)
key_buffer_size = 256M
myisam_sort_buffer_size = 128M

# InnoDB optimization
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 2000
innodb_read_io_threads = 8
innodb_write_io_threads = 8
```

### Query Optimization

```sql
-- Enable performance schema
SET GLOBAL performance_schema = ON;

-- Query optimization analysis
SELECT * FROM performance_schema.events_statements_summary_by_digest 
ORDER BY SUM_TIMER_WAIT DESC LIMIT 10;

-- Index usage analysis
SELECT * FROM performance_schema.table_io_waits_summary_by_index_usage 
WHERE OBJECT_SCHEMA = 'myapp' ORDER BY SUM_TIMER_WAIT DESC;

-- Slow query analysis
SELECT * FROM mysql.slow_log ORDER BY start_time DESC LIMIT 10;
```

## Monitoring

### Built-in Monitoring

```sql
-- Performance monitoring queries
SHOW GLOBAL STATUS LIKE 'Threads_connected';
SHOW GLOBAL STATUS LIKE 'Queries';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read_requests';
SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_reads';

-- Connection monitoring
SELECT 
    USER,
    HOST,
    DB,
    COMMAND,
    TIME,
    STATE,
    INFO
FROM INFORMATION_SCHEMA.PROCESSLIST
WHERE USER != 'system user'
ORDER BY TIME DESC;

-- Database size monitoring
SELECT 
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables 
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;
```

### External Monitoring Setup

```bash
# Install MySQL Exporter for Prometheus
wget https://github.com/prometheus/mysqld_exporter/releases/download/v0.14.0/mysqld_exporter-0.14.0.linux-amd64.tar.gz
tar xzf mysqld_exporter-*.tar.gz
sudo cp mysqld_exporter /usr/local/bin/

# Create monitoring user
mysql -u root -p <<EOF
CREATE USER 'exporter'@'localhost' IDENTIFIED BY 'ExporterPassword123!';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
EOF

# Create systemd service
sudo tee /etc/systemd/system/mysqld_exporter.service <<EOF
[Unit]
Description=MySQL Exporter
After=network.target

[Service]
Type=simple
User=mysql
Environment=DATA_SOURCE_NAME="exporter:ExporterPassword123!@(localhost:3306)/"
ExecStart=/usr/local/bin/mysqld_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now mysqld_exporter
```

### Health Check Scripts

```bash
#!/bin/bash
# mysql-health-check.sh

# Check MySQL service
if ! systemctl is-active mysql >/dev/null 2>&1; then
    echo "CRITICAL: MySQL service is not running"
    exit 2
fi

# Check connectivity
if ! mysql -e "SELECT 1;" >/dev/null 2>&1; then
    echo "CRITICAL: Cannot connect to MySQL"
    exit 2
fi

# Check replication (if configured)
SLAVE_STATUS=$(mysql -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep "Slave_IO_Running:")
if [ -n "$SLAVE_STATUS" ]; then
    IO_RUNNING=$(echo "$SLAVE_STATUS" | awk '{print $2}')
    if [ "$IO_RUNNING" != "Yes" ]; then
        echo "WARNING: Replication IO thread not running"
        exit 1
    fi
fi

# Check connections
CONNECTIONS=$(mysql -e "SHOW STATUS LIKE 'Threads_connected';" | tail -1 | awk '{print $2}')
MAX_CONNECTIONS=$(mysql -e "SHOW VARIABLES LIKE 'max_connections';" | tail -1 | awk '{print $2}')
CONNECTION_USAGE=$((CONNECTIONS * 100 / MAX_CONNECTIONS))

if [ $CONNECTION_USAGE -gt 80 ]; then
    echo "WARNING: High connection usage: ${CONNECTION_USAGE}%"
    exit 1
fi

echo "OK: MySQL is healthy"
exit 0
```

## 9. Backup and Restore

### Backup Procedures

```bash
#!/bin/bash
# mysql-backup.sh

BACKUP_DIR="/backup/mysql/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Full database backup
mysqldump --all-databases \
  --single-transaction \
  --routines \
  --triggers \
  --events \
  --master-data=2 \
  --user=backup \
  --password=BackupPassword123! \
  --ssl-cert=/etc/mysql/ssl/client-cert.pem \
  --ssl-key=/etc/mysql/ssl/client-key.pem \
  --ssl-ca=/etc/mysql/ssl/ca-cert.pem \
  | gzip > "$BACKUP_DIR/full-backup.sql.gz"

# Individual database backup
mysqldump --single-transaction \
  --routines \
  --triggers \
  myapp \
  --user=backup \
  --password=BackupPassword123! \
  --ssl-cert=/etc/mysql/ssl/client-cert.pem \
  --ssl-key=/etc/mysql/ssl/client-key.pem \
  --ssl-ca=/etc/mysql/ssl/ca-cert.pem \
  | gzip > "$BACKUP_DIR/myapp-backup.sql.gz"

# Binary log backup
cp /var/lib/mysql/mysql-bin.* "$BACKUP_DIR/" 2>/dev/null || true

# Configuration backup
tar czf "$BACKUP_DIR/mysql-config.tar.gz" /etc/mysql/

echo "Backup completed: $BACKUP_DIR"
```

### Restore Procedures

```bash
#!/bin/bash
# mysql-restore.sh

BACKUP_FILE="$1"
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.sql.gz>"
    exit 1
fi

# Stop applications using the database
echo "Stopping applications..."

# Restore database
echo "Restoring database from $BACKUP_FILE..."
zcat "$BACKUP_FILE" | mysql -u root -p

# Verify restore
mysql -u root -p -e "SHOW DATABASES;"

echo "Restore completed"
```

### Point-in-Time Recovery

```bash
#!/bin/bash
# mysql-pitr.sh

BACKUP_FILE="$1"
RECOVERY_TIME="$2"

if [ -z "$BACKUP_FILE" ] || [ -z "$RECOVERY_TIME" ]; then
    echo "Usage: $0 <backup-file.sql.gz> <recovery-time>"
    echo "Example: $0 backup.sql.gz '2024-01-15 14:30:00'"
    exit 1
fi

# Restore base backup
zcat "$BACKUP_FILE" | mysql -u root -p

# Apply binary logs up to recovery point
mysqlbinlog --stop-datetime="$RECOVERY_TIME" /var/lib/mysql/mysql-bin.* | mysql -u root -p

echo "Point-in-time recovery completed to $RECOVERY_TIME"
```

## 6. Troubleshooting

### Common Issues

1. **MySQL won't start**:
```bash
# Check logs
sudo journalctl -u mysql -f
sudo tail -f /var/log/mysql/error.log

# Check disk space
df -h /var/lib/mysql

# Check permissions
ls -la /var/lib/mysql

# Test configuration
mysqld --help --verbose
```

2. **Connection issues**:
```bash
# Check if MySQL is listening
sudo ss -tlnp | grep :3306

# Test local connection
mysql -u root -p -e "SELECT 1;"

# Check user privileges
mysql -u root -p -e "SELECT User, Host FROM mysql.user;"

# Check bind address
mysql -u root -p -e "SHOW VARIABLES LIKE 'bind_address';"
```

3. **Performance issues**:
```bash
# Check slow queries
mysql -u root -p -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';"

# Analyze table statistics
mysql -u root -p -e "SHOW TABLE STATUS FROM myapp;"

# Check buffer pool efficiency
mysql -u root -p -e "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read%';"
```

### Debug Mode

```bash
# Start MySQL with debug options
sudo mysqld --debug --user=mysql --console

# Enable general query log
mysql -u root -p -e "SET GLOBAL general_log = 1;"
mysql -u root -p -e "SET GLOBAL general_log_file = '/var/log/mysql/general.log';"

# Analyze queries
sudo tail -f /var/log/mysql/general.log
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update mysql-community-server
sudo dnf update mysql-community-server

# Debian/Ubuntu
sudo apt update
sudo apt upgrade mysql-server

# Arch Linux
sudo pacman -Syu mysql

# Alpine Linux
apk update
apk upgrade mariadb

# openSUSE
sudo zypper update mysql-community-server

# FreeBSD
pkg update
pkg upgrade mysql80-server

# Always backup before updates
mysql -u backup -p < backup.sql

# Run mysql_upgrade after major updates
sudo mysql_upgrade -u root -p
sudo systemctl restart mysql
```

### Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# mysql-maintenance.sh

# Analyze tables
mysql -u root -p <<EOF
ANALYZE TABLE myapp.users;
ANALYZE TABLE myapp.logs;
EOF

# Optimize tables
mysql -u root -p <<EOF
OPTIMIZE TABLE myapp.users;
OPTIMIZE TABLE myapp.logs;
EOF

# Purge old binary logs
mysql -u root -p -e "PURGE BINARY LOGS BEFORE DATE_SUB(NOW(), INTERVAL 7 DAY);"

# Check for corrupted tables
mysqlcheck --all-databases --check -u root -p

echo "MySQL maintenance completed"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "*/5 * * * * /usr/local/bin/mysql-health-check.sh" | sudo crontab -

# Log rotation
sudo tee /etc/logrotate.d/mysql <<EOF
/var/log/mysql/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 mysql adm
    sharedscripts
    postrotate
        /usr/bin/mysqladmin flush-logs
    endscript
}
EOF
```

## Integration Examples

### Django Integration

```python
# Django settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'myapp',
        'USER': 'appuser',
        'PASSWORD': 'SecurePassword123!',
        'HOST': 'localhost',
        'PORT': '3306',
        'OPTIONS': {
            'ssl': {
                'cert': '/etc/mysql/ssl/client-cert.pem',
                'key': '/etc/mysql/ssl/client-key.pem',
                'ca': '/etc/mysql/ssl/ca-cert.pem',
            },
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}
```

### WordPress Integration

```php
// wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'SecureWpPassword123!');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', 'utf8mb4_unicode_ci');

// Enable SSL
define('MYSQL_SSL_CA', '/etc/mysql/ssl/ca-cert.pem');
define('MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL);
```

### Node.js Integration

```javascript
// Using mysql2 with SSL
const mysql = require('mysql2/promise');

const connection = await mysql.createConnection({
    host: 'localhost',
    user: 'appuser',
    password: 'SecurePassword123!',
    database: 'myapp',
    ssl: {
        ca: fs.readFileSync('/etc/mysql/ssl/ca-cert.pem'),
        cert: fs.readFileSync('/etc/mysql/ssl/client-cert.pem'),
        key: fs.readFileSync('/etc/mysql/ssl/client-key.pem')
    }
});
```

## Additional Resources

- [Official MySQL Documentation](https://dev.mysql.com/doc/)
- [MySQL 8.0 Reference Manual](https://dev.mysql.com/doc/refman/8.0/en/)
- [MariaDB Documentation](https://mariadb.org/documentation/)
- [MySQL Performance Blog](https://www.percona.com/blog/)
- [Percona Toolkit](https://www.percona.com/software/database-tools/percona-toolkit)
- [MySQL Security Guide](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [MySQL Community Forums](https://forums.mysql.com/)
- [MySQL Planet Blog Aggregator](https://planet.mysql.com/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.