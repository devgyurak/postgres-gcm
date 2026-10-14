-- SPDX-License-Identifier: PostgreSQL
-- The distribution server image ships the extension, so create it in the default database on
-- first init and the image is ready to use. A deployment may drop and recreate it, create it
-- in other databases, or set pg_gcm.strict / pg_gcm.min_key_bytes itself.
CREATE EXTENSION IF NOT EXISTS pg_gcm;
