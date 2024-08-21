ALTER TABLE /*_*/pageencryption_keys
  ADD `public_key` BLOB NOT NULL AFTER `protected_key`;
