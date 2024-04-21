
CREATE TABLE IF NOT EXISTS /*_*/pageencryption_keys (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `protected_key` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `enabled` TINYINT(1) NOT NULL default 1,
  `updated_at` datetime NOT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


ALTER TABLE /*_*/pageencryption_keys
  ADD PRIMARY KEY (`id`);

ALTER TABLE /*_*/pageencryption_keys
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;


