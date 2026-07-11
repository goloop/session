[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/session) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/session/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# session

`session` дає безпечні, підписані cookie-сесії для браузерних застосунків. MVP -
cookie-only: уся сесія живе в підписаній HMAC-SHA256 cookie, тож серверного
сховища запускати не треба. Нуль залежностей, лише стандартна бібліотека.

Він доповнює токен-автентифікацію, а не замінює її: `session` володіє cookie й
станом браузера; auth-пакет володіє subject-ами, паролями й токенами.

## Встановлення

```bash
go get github.com/goloop/session
```

## Швидкий старт

```go
m := session.New(secret,
	session.WithName("sid"),
	session.WithSecure(true),                 // лише HTTPS у prod
	session.WithSameSite(http.SameSiteLaxMode),
	session.WithTTL(24*time.Hour),
)

// Читання, зміна, збереження.
s, err := m.Load(r)
s.Set("theme", "dark")
err = m.Save(w, s)

// Вихід.
m.Destroy(w)
```

З middleware:

```go
http.Handle("/", m.Middleware(handler))

// усередині handler:
s, _ := session.From(r.Context())
s.Set("seen", "1")
_ = m.Save(w, s)
```

## Безпека

- Cookie за замовчуванням `HttpOnly`, `SameSite=Lax` і `Secure`; передавайте
  `WithSecure(false)` лише для локальної HTTP-розробки.
- `New` панікує на ключі коротшому за 32 байти; викликайте `Session.RegenerateID`
  після логіну (тоді `Save`) для захисту від session fixation.
- Payload підписаний HMAC-SHA256 і версійований, тож формат може розвиватися, не
  ламаючи старі cookie.
- **Ротація ключів** вбудована: первинний ключ підписує, будь-який доданий через
  `WithKey` перевіряє, тож ключі можна змінювати без інвалідації живих сесій.

## Межі

MVP поки не містить серверного сховища, шифрованого payload чи CSRF (заплановано).
Не робить керування користувачами, хешування паролів чи OAuth.

## Документація

- Англійський довідник: [DOC.md](DOC.md)
- Український довідник: [DOC.UK.md](DOC.UK.md)

## Ліцензія

MIT - див. [LICENSE](LICENSE).
