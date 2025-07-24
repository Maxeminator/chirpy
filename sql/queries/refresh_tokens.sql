-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at)
VALUES ($1, $2, NOW(), NOW(), $3);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: GetUserFromRefreshToken :one
SELECT users.*, refresh_tokens.expires_at
FROM refresh_tokens
JOIN users ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1
  AND refresh_tokens.revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;