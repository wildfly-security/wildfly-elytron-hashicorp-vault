# Vault Alias Format Specification

## Overview

The WildFly Elytron HashiCorp Vault credential store uses a structured alias format to reference secrets stored in HashiCorp Vault. This format supports multiple secret engines, custom mount paths, nested JSON traversal, and maintains backward compatibility with the legacy format.

## Syntax

```
[engine=TYPE][@mount-path][#]secret-path?key-path
```

### Components

- **`engine=TYPE`** (optional) - Specifies the Vault secret engine type
- **`@mount-path`** (optional) - Specifies a custom mount path
- **`#`** (optional/required) - Secret path marker (see rules below)
- **`secret-path`** (required) - Path to the secret in Vault
- **`?`** (required) - Key path delimiter
- **`key-path`** (required) - Path to the specific value within the secret

### Rules for `#` Delimiter

- **Optional** when alias starts with secret path: `myapp/database?password`
- **Required** when `engine=` is present: `engine=KVv1#secret?key`
- **Required** when `@` is present: `@custom#secret?key`

### Defaults

- **Engine:** `KVv2` (if `engine=` omitted)
- **Mount:** `secret` (if `@` omitted)
- **Key:** REQUIRED (no default)

## Delimiters Explained

### `engine=` - Engine Type Prefix
Specifies the Vault secret engine type. Supported values:
- `KVv2` - Key-Value version 2 (default, recommended)
- `KVv1` - Key-Value version 1 (for legacy Vault configurations)

### `@` - Mount Path Delimiter
Indicates a custom mount path. The mount path follows the `@` and ends at the `#`.

### `#` - Secret Path Marker
Separates the mount path from the secret path. Required when using `engine=` or `@` prefixes.

### `?` - Key Path Delimiter
Separates the secret path from the key path. Always required.

### `/` - JSON Path Traversal
Within the key path, `/` indicates nested JSON traversal.

## Key Path Syntax

Key paths support two modes:

### 1. Simple Key (Literal Match)
Use when the JSON key itself contains dots:
```
?db.host          → Look for key literally named "db.host"
?my.app.config    → Look for key literally named "my.app.config"
```

### 2. Nested Path (JSON Traversal)
Use `/` to traverse nested JSON objects:
```
?database/host    → Traverse: data["database"]["host"]
?app/config/key   → Traverse: data["app"]["config"]["key"]
```

### 3. Nested with Dots in Keys
Combine both approaches:
```
?my.app/config.key    → Traverse: data["my.app"]["config.key"]
?config/db.host       → Traverse: data["config"]["db.host"]
```

## Examples

### Simple Keys (Top-Level)

```
# Minimal format (# is optional)
myapp/database?password

# Key with dots (literal match)
myapp/database?db.host

# With # (also valid)
#myapp/config?api_key

# Key with multiple dots
services?my.app.config.value

# URL-encoded space in secret path
test%20path?password
```

### Nested JSON Paths

Given Vault secret: `{"database": {"host": "localhost", "port": 5432}}`

```
myapp/config?database/host     → "localhost"
myapp/config?database/port     → "5432"
```

Given Vault secret: `{"app": {"prod": {"key": "secret"}}}`

```
services?app/prod/key          → "secret"
```

### Mixed: Nested Path with Dots in Keys

Given Vault secret: `{"team": {"my.app": {"key": "value"}}}`

```
services?team/my.app/key       → "value"
# The dot in "my.app" is part of the key name, not a path separator
```

Given Vault secret: `{"db.config": {"host": "localhost"}}`

```
myapp?db.config/host           → "localhost"
# "db.config" is a literal key name, "/" traverses into it
```

### Real-World Examples

```
# Simple format (most common - no # needed)
myapp/database?password
myapp/config?database/connection/password
services/auth?jwt/signing/key

# With explicit engine type (# required)
engine=KVv2#myapp/database?password
engine=KVv1#old-app/config?api.key.v2

# With custom mount (# required)
@prod/vault#myapp/database?password
@team/backend#services/auth?jwt/signing/key

# Everything explicit
engine=KVv2@company/prod#division/team?app.config/db.settings/password

# URL-encoded characters in paths
test%20path?password                    # Space in path
test%23path?key                         # # in path
@mount%2Fname#secret%20path?db.host     # Multiple encoded chars
```

### Edge Cases

```
# If user has # in mount name (URL-encode it):
@test%23mount#secret?key

# If user has # in secret path without prefix (# becomes required):
#secret%23path?key

# If user has ? in secret path (URL-encode it):
secret%3Fpath?key

# URL-encoded characters work naturally:
path%20with%20spaces?password
path%2Fwith%2Fslash?key
```

## URL Encoding

### When to URL-Encode

You **MUST** URL-encode the following characters in mount paths and secret paths:

| Character | Encoding | When Required |
|-----------|----------|---------------|
| `#` | `%23` | Always in paths |
| `?` | `%3F` | Always in paths (rare) |
| Space | `%20` | Always |
| `/` | `%2F` | When `/` is part of path segment name (rare) |

### URL Encoding Examples

```bash
# Creating secrets in Vault with special characters:
vault kv put secret/test%23path key=value    # # encoded as %23
vault kv put secret/test%3Fpath key=value    # ? encoded as %3F
vault kv put secret/test%20path key=value    # space encoded as %20
```

```
# Using the same encoding in aliases:
#test%23path?key
#test%3Fpath?key
#test%20path?password
```

### Important: Decode After Splitting

The implementation decodes URL-encoded segments **after** splitting on delimiters. This prevents double-encoding issues:

```
User provides:  #test%20path?key
Split on ?:     secret="test%20path", key="key"
Decode each:    secret="test path", key="key"
Pass to Vault:  "test path"
Vault client:   Encodes to "test%20path" ✓ CORRECT
```

## Key Path Resolution Algorithm

The key path resolution follows these rules:

1. **No `/` in key path** → Direct lookup (supports dots in key name)
   ```
   keyPath = "db.host"
   → data.get("db.host")
   ```

2. **Contains `/`** → Split on `/` and traverse
   ```
   keyPath = "database/host"
   → data.get("database").get("host")
   ```

3. **Nested with dots** → Each segment can contain dots
   ```
   keyPath = "my.app/config.key"
   → data.get("my.app").get("config.key")
   ```

### Resolution Examples

Given Vault secret data:
```json
{
    "password": "secret123",
    "db.host": "localhost",
    "database": {
        "host": "prod.db.com",
        "port": 5432,
        "credentials": {
            "user": "admin",
            "pass": "secret"
        }
    },
    "my.app": {
        "config.key": "value123"
    }
}
```

Key path resolutions:
```
?password                    → "secret123"
?db.host                     → "localhost"
?database/host               → "prod.db.com"
?database/port               → "5432"
?database/credentials/pass   → "secret"
?my.app/config.key           → "value123"
```

## Validation Rules

### Required Validations

1. Secret path must not be empty
2. Key path must not be empty
3. Engine type must be valid (if specified)
4. Format must match: `[engine=TYPE][@mount][#]secret?key`

### Key Path Validation

1. **Simple keys:** Any characters except `/` and `?`
2. **Nested paths:** Segments separated by `/`, each segment can contain dots
3. **No empty segments:** `database//host` is invalid

## Migration from Legacy Format

### Legacy Format

The legacy format used a dot (`.`) to separate the secret path from the key:

```
secret-path.key
```

### Detection Strategy

The implementation automatically detects the format:

- **New format** if alias contains: `?`, `#`, `@`, or starts with `engine=`
- **Legacy format** if none of the above indicators are present AND the alias contains a dot (`.`)

**Important:** Legacy format support must be explicitly enabled via the `support-legacy-alias-format` configuration parameter. When disabled (default in stable releases), aliases without new format indicators will be rejected with an error message providing the correct new format.

### Migration Examples

| Legacy Format | New Format | Notes |
|---------------|------------|-------|
| `myapp/db.password` | `myapp/db?password` | Simple key |
| `app.config.key` | `app.config?key` | Dots in secret path |
| `my.app.db.pass` | `my.app.db?pass` | Multiple dots |
| `app/config.key` | `app?config/key` | Nested key path |

See [migration.md](migration.md) for detailed migration guidance.

## EBNF Grammar

```ebnf
alias          = [engine-spec] [mount-spec] [hash] secret-spec key-spec
engine-spec    = "engine=" engine-type
mount-spec     = "@" mount-path
hash           = "#"
secret-spec    = secret-path
key-spec       = "?" key-path

engine-type    = "KVv1" | "KVv2"
mount-path     = path-segment *("/" path-segment)
secret-path    = path-segment *("/" path-segment)
key-path       = key-segment *("/" key-segment)
path-segment   = 1*path-char
key-segment    = 1*key-char
path-char      = ALPHA / DIGIT / "-" / "_" / "." / ":" / <any char except "#" and "?">
key-char       = ALPHA / DIGIT / "-" / "_" / "." / ":" / <any char except "/" and "?">
```

## Advantages

### 1. Handles All Real-World Cases
- ✅ Paths with dots: `my.app.config?password`
- ✅ Keys with dots: `?db.host` (literal key name)
- ✅ Nested JSON: `?database/host` (traverse)
- ✅ Nested with dots: `?my.app/config.key` (both!)
- ✅ URL-encoded paths work perfectly
- ✅ Hierarchical paths: `@team/app#service/db?password`
- ✅ No restrictions on user naming conventions

### 2. Unambiguous Parsing
- `?` requires encoding as `%3F` in actual paths → safe delimiter
- `#` is fragment identifier → safe delimiter
- `@` is clear "at location" marker
- `/` in key path means JSON traversal
- No `/` in key path means literal key lookup
- No ambiguity with URL-encoded characters
- Decode-after-split prevents double-encoding

### 3. Flexible Key Resolution
- Simple keys work naturally (even with dots)
- Nested paths use intuitive `/` separator
- Dots in nested keys work automatically
- No escaping needed for common cases

### 4. Future-Proof
- Supports any Vault secret engine type
- Handles arbitrary path complexity
- Handles arbitrary JSON nesting
- Extensible format

### 5. Backward Compatible
- Legacy format still works via detection
- Gradual migration path
- No breaking changes required

### 6. User-Friendly
- No restrictions on dots in paths
- No restrictions on dots in keys
- URL-encoded paths work naturally
- Clear, readable format
- Single-character delimiters (concise)
- Minimal encoding requirements (only for rare `#` and `?`)
- Intuitive nested path syntax

## See Also

- [Configuration Guide](configuration.md) - Credential store configuration parameters
- [Migration Guide](migration.md) - Migrating from legacy format
- [WildFly Elytron Documentation](https://docs.wildfly.org/elytron/)