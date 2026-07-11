# session - довідник

`session` дає підписані cookie-сесії. Повний український довідник; англійською -
[DOC.md](DOC.md).

## Зміст

- [Модель](#модель)
- [Session](#session)
- [Manager і опції](#manager-і-опції)
- [Load, Save, Destroy](#load-save-destroy)
- [Middleware](#middleware)
- [Формат cookie й безпека](#формат-cookie-й-безпека)
- [Ротація ключів](#ротація-ключів)
- [Межі](#межі)

## Модель

MVP зберігає всю сесію в підписаній cookie (cookie-only): серверного сховища
немає. Cookie підписана HMAC-SHA256; нічого в ній не таємне (вона підписана, не
шифрована), тож не кладіть конфіденційні дані у значення сесії. Шифрований
payload - заплановане доповнення.

## Session

```go
type Session struct {
	ID        string
	Subject   string
	Values    map[string]string
	CreatedAt time.Time
	ExpiresAt time.Time
}
```

`Get`, `Set` і `Delete` керують `Values`. `Subject` - зручне поле для
автентифікованого принципала, може бути порожнім.

## Manager і опції

```go
m := session.New(secret, opts...)
```

| Опція | Ефект | Дефолт |
|-------|-------|--------|
| `WithName(s)` | ім'я cookie | "session" |
| `WithDomain(s)` | Domain cookie | "" |
| `WithPath(s)` | Path cookie | "/" |
| `WithSecure(b)` | атрибут Secure (лише HTTPS) | true |
| `WithSameSite(m)` | атрибут SameSite | Lax |
| `WithTTL(d)` | час життя сесії | 24h |
| `WithKey(k)` | додатковий ключ перевірки (ротація) | - |
| `WithClock(fn)` | джерело часу (тести) | time.Now |

`HttpOnly` встановлюється завжди.

## Load, Save, Destroy

```go
s := m.LoadOrNew(r)   // наявна сесія або свіжа при будь-якій невдачі
err := m.Save(w, s)   // призначає ID/час, оновлює expiry, ставить cookie
m.Destroy(w)          // очищає cookie
```

`Load` повертає `ErrNoSession`, `ErrInvalid` або `ErrExpired` при невдачі;
`LoadOrNew` зводить це до свіжої порожньої сесії - дискаверабельний спосіб
почати сесію в хендлері без `Middleware` (напр. login-ендпоінт). `Save`
призначає випадковий `ID` і `CreatedAt`, якщо їх немає, ставить `ExpiresAt` =
now+TTL і повертає `ErrTooLarge`, якщо закодована cookie з іменем та атрибутами
перевищить ~4 КБ ліміт браузера. Expiry виключний: cookie недійсна в момент
`ExpiresAt` і пізніше.

`Destroy` очищає cookie у відповіді, але **stateless підписану cookie не можна
відкликати на сервері**: копія, яку клієнт уже має, лишається дійсною до
`ExpiresAt`. Тримайте TTL коротким; для жорсткого відкликання додайте
серверний denylist ID сесій.

## Middleware

```go
http.Handle("/", m.Middleware(handler))
s, ok := session.From(r.Context())
```

`Middleware` завантажує сесію в контекст запиту, підставляючи свіжу порожню
сесію, коли її немає або вона невалідна. Оскільки cookie-only сесія пишеться в
заголовок відповіді, хендлери зберігають зміни явно через `Save`.

## Формат cookie й безпека

Значення cookie - `version.payload.signature`, кожен сегмент base64url. Префікс
версії дозволяє формату розвиватися; невідома версія відкидається. Підпис
перевіряється constant-time до декодування payload, тож підроблена cookie ніколи
не доходить до вашої сесії. Дефолти - `HttpOnly`, `SameSite=Lax` і `Secure=true`;
передавайте `WithSecure(false)` лише для локальної HTTP-розробки. `New` панікує,
якщо ключ коротший за 32 байти. Після успішного логіну викликайте
`Session.RegenerateID` перед `Save` для захисту від session fixation.

## Ротація ключів

`New` бере первинний (підписувальний) ключ; додавайте старіші через `WithKey`.
Усі налаштовані ключі пробуються при перевірці, тож можна ввести новий ключ і
вивести старий без інвалідації живих сесій:

```go
m := session.New(newKey, session.WithKey(oldKey))
```

## Межі

MVP не містить серверного сховища, шифрованого payload чи CSRF (заплановано), і
не робить керування користувачами, хешування паролів чи OAuth.
