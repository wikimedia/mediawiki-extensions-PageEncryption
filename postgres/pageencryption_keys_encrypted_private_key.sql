ALTER TABLE pageencryption_keys
  ADD  `encrypted_private_key` BYTEA NOT NULL AFTER `public_key`;
