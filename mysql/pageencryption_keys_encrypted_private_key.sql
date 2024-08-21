ALTER TABLE /*_*/pageencryption_keys
  ADD  `encrypted_private_key` BLOB NOT NULL AFTER `public_key`;
