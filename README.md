# 🐦 Chirpy — REST API

Chirpy — это Twitter-подобное API-приложение, написанное на Go. Поддерживает аутентификацию, публикацию чирпов, управление пользователями и подписку Chirpy Red через вебхук.

## 📦 Установка

### Требования
- Go 1.22+
- PostgreSQL
- Файл `.env` со значениями:
  ```
  DB_URL=postgres://<username>:<password>@localhost:5432/<dbname>?sslmode=disable
  JWT_SECRET=your_jwt_secret
  POLKA_KEY=your_polka_API_key
  PLATFORM=dev
  ```

### Запуск
```
go run main.go
```

## 🔐 Аутентификация

- Для защищённых маршрутов: `Authorization: Bearer <JWT>`
- Для вебхуков: `Authorization: ApiKey <POLKA_KEY>`

## 🔧 API Эндпоинты

### 👤 Пользователи

#### `POST /api/users`
Создание пользователя:
```json
{
  "email": "user@example.com",
  "password": "supersecret",
  "expires_in_seconds": 3600
}
```

#### `POST /api/login`
Логин:
```json
{
  "email": "user@example.com",
  "password": "supersecret"
}
```
Ответ:
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "token": "JWT",
  "refresh_token": "REFRESH_TOKEN",
  "is_chirpy_red": false
}
```

#### `POST /api/refresh`
Обновление access-токена  
Требует заголовок: `Authorization: Bearer <refresh_token>`

#### `POST /api/revoke`
Отзыв refresh-токена  
Требует заголовок: `Authorization: Bearer <refresh_token>`

#### `PUT /api/users`
Обновление email и пароля:
```json
{
  "email": "new@example.com",
  "password": "newpassword"
}
```

### 🐦 Чирпы

#### `POST /api/chirps`
Создание чирпа:
```json
{
  "body": "Hello, Chirpy!"
}
```
Максимум 140 символов. Запрещены слова: kerfuffle, sharbert, fornax.

### 📘 `GET /api/chirps`

**Описание:** Получает список всех чирпов.

**Параметры запроса (Query Parameters):**

| Параметр     | Тип             | Описание                                                                 |
|--------------|------------------|--------------------------------------------------------------------------|
| `author_id`  | `string` (UUID)  | (необязательно) Вернёт только чирпы, созданные этим пользователем       |
| `sort`       | `string`         | (необязательно) Сортировка по дате создания. <br>Допустимые значения: <br> - `asc` (по возрастанию, по умолчанию)<br> - `desc` (по убыванию) |

**Примеры:**

```http
GET /api/chirps
GET /api/chirps?sort=desc
GET /api/chirps?author_id=123e4567-e89b-12d3-a456-426614174000&sort=asc

#### `GET /api/chirps/{chirpID}`
Получить один чирп по ID.

#### `DELETE /api/chirps/{chirpID}`
Удалить чирп (только если пользователь — автор).

### 💳 Вебхуки Polka

#### `POST /api/polka/webhooks`

Заголовок:
```
Authorization: ApiKey f271c81ff7084ee5b99a5091b42d486e
```

Тело:
```json
{
  "event": "user.upgraded",
  "data": {
    "user_id": "uuid"
  }
}
```

Ответы:
- `204` — если успешно или событие неинтересное
- `401` — если API-ключ неверен
- `404` — если пользователь не найден

## 📁 Структура проекта

```
/chirpy
├── main.go
├── internal/
│   ├── auth/
│   └── database/
├── queries/
│   ├── chirps.sql
│   └── users.sql
├── .env
└── README.md
```
## ✅ Тесты

```
go test ./...
```
