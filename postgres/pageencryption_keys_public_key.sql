ALTER TABLE pageencryption_keys
  ADD `public_key` BYTEA NOT NULL AFTER `protected_key`;
