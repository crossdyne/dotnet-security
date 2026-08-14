# Crossdyne.Security (.NET)

> Cross-platform cryptographic library — [.NET](https://github.com/crossdyne/dotnet-security) | [TypeScript](https://github.com/crossdyne/typescript-security)
>
> [English](#english) | [Русский](#русский)

---

<a name="english"></a>
## English

.NET implementation of the Crossdyne.Security cryptographic library.

## Installation

```bash
dotnet add package Crossdyne.Security.Cryptography
dotnet add package Crossdyne.Security.Srp.Client
dotnet add package Crossdyne.Security.Srp.Server
dotnet add package Crossdyne.Security.Abstractions
dotnet add package Crossdyne.Security.Configuration
dotnet add package Crossdyne.Security.Utilities
dotnet add package Crossdyne.Security.Exceptions
dotnet add package Crossdyne.Security.Windows
```

### Features

- **AES-256-GCM** — authenticated symmetric encryption
- **PBKDF2 + HKDF** — secure key derivation from passwords
- **SRP-6a** — password-authenticated key exchange without sending the password to the server
- **Zero-memory** — sensitive buffers are cleared after use via `CryptographicOperations.ZeroMemory` / `Array.Clear`
- **Cross-platform** — compatible with the [TypeScript implementation](https://github.com/crossdyne/typescript-security). Encrypted payloads and SRP messages are interchangeable between .NET and TS.

### Project Structure

```
Crossdyne.Security.Cryptography/
├── CryptoService.cs                         # AES-GCM encrypt / decrypt
├── KeyDerivationService.cs                  # Derive KEK and AuthHash from password
└── CryptoServiceCollectionExtensions.cs     # DI registration

Crossdyne.Security.Srp.Client/
├── SrpClientService.cs                      # SRP client (proof, verifier)
├── SrpKeyDerivationService.cs               # Derive auth-hash for SRP
└── SrpClientServiceCollectionExtensions.cs  # DI registration

Crossdyne.Security.Srp.Server/
├── SrpServerService.cs                      # SRP server (challenge, verify)
└── SrpServerServiceCollectionExtensions.cs  # DI registration
```

### Requirements

- .NET 10.0+
- `System.Security.Cryptography`

### Dependency Injection Registration

```csharp
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Srp.Client;

var builder = WebApplication.CreateBuilder(args);

// Cryptography services (ICryptoService, IKeyDerivationService)
builder.Services.AddCrossdyneCryptography();

// SRP client services (ISrpClient, ISrpKeyDerivationService)
builder.Services.AddCrossdyneSrpClient();
```

### Quick Start

#### Encrypt / Decrypt

```csharp
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Configuration;

var crypto = new CryptoService();
var key = crypto.GenerateRandomBytes(32); // AES-256

string encrypted = crypto.EncryptData(
    data: new { Message = "Hello, World!" },
    key: key,
    version: CryptoVersion.V1);

var decrypted = crypto.DecryptData<MyData>(encrypted, key);
```

Encrypted payload format (Base64):

```
[Version (1 byte)][Nonce (N bytes)][Ciphertext][Tag]
```

#### Key Derivation from Password

```csharp
using Crossdyne.Security.Cryptography;

var kdf = new KeyDerivationService();
byte[] salt = /* 16+ random bytes */;

(byte[] kek, string authHash) = kdf.DeriveKeysFromPassword(
    identity: "user@example.com", // Or Login, or any other user ID (preferably one that either doesn't change or changes very rarely)
    password: "SuperSecret123!",
    salt: salt,
    version: CryptoVersion.V1);
```

- `kek` — key for AES-GCM
- `authHash` — hash for SRP authentication

#### SRP Authentication Flow

**Server — generate challenge**

```csharp
using Crossdyne.Security.Srp.Server;

var server = new SrpServerService();

SrpSessionState session = server.GetSrpChallenge(
    login: "user@example.com",
    verifierBytes: verifier,
    salt: salt,
    srpGroup: SrpGroup.Group2048);

// Send to client: salt + session.PublicKeyB (B)
```

**Client — generate proof**

```csharp
using Crossdyne.Security.Srp.Client;

var client = new SrpClientService();
var kdf = new SrpKeyDerivationService();

// 1. Derive auth-hash from password
byte[] authHash = kdf.DeriveAuthHashForSrp(
    identity, password, salt, SrpGroup.Group2048, CryptoVersion.V1);

// 2. Generate proof
(string A, string M1, byte[] sessionKeyK) = client.GenerateSrpProof(
    login: identity,
    authHashBytes: authHash,
    saltBase64: Convert.ToBase64String(salt),
    bBase64: Convert.ToBase64String(session.PublicKeyB),
    srpGroup: SrpGroup.Group2048);

// Send to server: A + M1
```

**Server — verify proof**

```csharp
string serverM2 = server.VerifySrpProof(
    sessionState: session,
    a: A,
    m1: M1,
    srpGroup: SrpGroup.Group2048);

// Send to client: serverM2
```

**Client — verify server proof**

```csharp
bool isValid = client.VerifyServerM2(
    publicA: A,
    m1: M1,
    sessionKeyK: sessionKeyK,
    serverM2: serverM2,
    srpGroup: SrpGroup.Group2048);
```

### Security Notes

- All sensitive buffers (passwords, keys, private SRP parameters) are cleared with `CryptographicOperations.ZeroMemory` / `Array.Clear`
- Salt must be **at least 16 bytes**
- AES-256 key must be **exactly 32 bytes**
- SRP groups are protected against small-subgroup attacks (checks `A % N != 0`, `B != 0`)

### License

MIT

---

<a name="русский"></a>
## Русский

.NET-реализация криптографической библиотеки Crossdyne.Security.

## Установка

```bash
dotnet add package Crossdyne.Security.Cryptography
dotnet add package Crossdyne.Security.Srp.Client
dotnet add package Crossdyne.Security.Srp.Server
dotnet add package Crossdyne.Security.Abstractions
dotnet add package Crossdyne.Security.Configuration
dotnet add package Crossdyne.Security.Utilities
dotnet add package Crossdyne.Security.Exceptions
dotnet add package Crossdyne.Security.Windows
```

### Возможности

- **AES-256-GCM** — симметричное шифрование с аутентификацией
- **PBKDF2 + HKDF** — надёжный вывод ключей из пароля
- **SRP-6a** — протокол аутентификации без передачи пароля на сервер
- **Zero-memory** — чувствительные буферы очищаются после использования через `CryptographicOperations.ZeroMemory` / `Array.Clear`
- **Кроссплатформенность** — совместима с [TypeScript-реализацией](https://github.com/crossdyne/typescript-security). Зашифрованные данные и SRP-сообщения взаимозаменяемы между .NET и TS.

### Структура проекта

```
Crossdyne.Security.Cryptography/
├── CryptoService.cs                         # AES-GCM шифрование / дешифрование
├── KeyDerivationService.cs                  # Вывод KEK и AuthHash из пароля
└── CryptoServiceCollectionExtensions.cs     # Регистрация в DI

Crossdyne.Security.Srp.Client/
├── SrpClientService.cs                      # SRP клиент (proof, верификатор)
├── SrpKeyDerivationService.cs               # Вывод auth-hash для SRP
└── SrpClientServiceCollectionExtensions.cs  # Регистрация в DI

Crossdyne.Security.Srp.Server/
├── SrpServerService.cs                      # SRP сервер (challenge, проверка)
└── SrpServerServiceCollectionExtensions.cs  # Регистрация в DI
```

### Требования

- .NET 10.0+
- `System.Security.Cryptography`

### Регистрация в Dependency Injection

```csharp
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Srp.Client;

var builder = WebApplication.CreateBuilder(args);

// Криптографические сервисы (ICryptoService, IKeyDerivationService)
builder.Services.AddCrossdyneCryptography();

// SRP-клиентские сервисы (ISrpClient, ISrpKeyDerivationService)
builder.Services.AddCrossdyneSrpClient();
```

### Быстрый старт

#### Шифрование / дешифрование

```csharp
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Configuration;

var crypto = new CryptoService();
var key = crypto.GenerateRandomBytes(32); // AES-256

string encrypted = crypto.EncryptData(
    data: new { Message = "Hello, World!" },
    key: key,
    version: CryptoVersion.V1);

var decrypted = crypto.DecryptData<MyData>(encrypted, key);
```

Формат зашифрованных данных (Base64):

```
[Version (1 byte)][Nonce (N bytes)][Ciphertext][Tag]
```

#### Вывод ключей из пароля

```csharp
using Crossdyne.Security.Cryptography;

var kdf = new KeyDerivationService();
byte[] salt = /* 16+ случайных байт */;

(byte[] kek, string authHash) = kdf.DeriveKeysFromPassword(
    identity: "user@example.com", // Или Login, либо любой иной идентификатор пользователя (желательно тот, который либо не меняется, либо меняется крайне редко)
    password: "SuperSecret123!",
    salt: salt,
    version: CryptoVersion.V1);
```

- `kek` — ключ для AES-GCM
- `authHash` — хеш для SRP-аутентификации

#### SRP-аутентификация

**Сервер — генерация challenge**

```csharp
using Crossdyne.Security.Srp.Server;

var server = new SrpServerService();

SrpSessionState session = server.GetSrpChallenge(
    login: "user@example.com",
    verifierBytes: verifier,
    salt: salt,
    srpGroup: SrpGroup.Group2048);

// Отправить клиенту: salt + session.PublicKeyB (B)
```

**Клиент — генерация proof**

```csharp
using Crossdyne.Security.Srp.Client;

var client = new SrpClientService();
var kdf = new SrpKeyDerivationService();

// 1. Вывести auth-hash из пароля
byte[] authHash = kdf.DeriveAuthHashForSrp(
    identity, password, salt, SrpGroup.Group2048, CryptoVersion.V1);

// 2. Сгенерировать proof
(string A, string M1, byte[] sessionKeyK) = client.GenerateSrpProof(
    login: identity,
    authHashBytes: authHash,
    saltBase64: Convert.ToBase64String(salt),
    bBase64: Convert.ToBase64String(session.PublicKeyB),
    srpGroup: SrpGroup.Group2048);

// Отправить серверу: A + M1
```

**Сервер — проверка proof**

```csharp
string serverM2 = server.VerifySrpProof(
    sessionState: session,
    a: A,
    m1: M1,
    srpGroup: SrpGroup.Group2048);

// Отправить клиенту: serverM2
```

**Клиент — проверка server proof**

```csharp
bool isValid = client.VerifyServerM2(
    publicA: A,
    m1: M1,
    sessionKeyK: sessionKeyK,
    serverM2: serverM2,
    srpGroup: SrpGroup.Group2048);
```

### Безопасность

- Все чувствительные буферы (пароли, ключи, приватные параметры SRP) очищаются через `CryptographicOperations.ZeroMemory` / `Array.Clear`
- Соль должна быть **минимум 16 байт**
- Ключ AES-256 — **строго 32 байта**
- SRP-группы защищены от атак на малые подгруппы (проверки `A % N != 0`, `B != 0`)

### Лицензия

MIT
