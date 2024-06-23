
CREATE TABLE IF NOT EXISTS pageencryption_keys (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `protected_key` BYTEA NOT NULL,
  `public_key` BYTEA NOT NULL,
  `encrypted_private_key` BYTEA NOT NULL,
  `enabled` TINYINT(1) NOT NULL default 1,
  `updated_at` datetime NOT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


ALTER TABLE pageencryption_keys
  ADD PRIMARY KEY (`id`);

ALTER TABLE pageencryption_keys
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;


