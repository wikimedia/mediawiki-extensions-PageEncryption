
CREATE TABLE IF NOT EXISTS pageencryption_permissions (
  `id` int(11) NOT NULL,
  `created_by` int(11) NOT NULL,
  `page_id` int(11) NULL,
  `revision_id` int(11) NULL,
  `access_type` enum('symmetric', 'asymmetric') NOT NULL,
  `protected_key` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `encrypted_password` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `encrypted_content` BLOB NOT NULL,
  `expiration_date` datetime NULL,
  `viewed` datetime NULL,
  `viewed_metadata` TEXT NULL,
  `updated_at` datetime NOT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


ALTER TABLE pageencryption_permissions
  ADD PRIMARY KEY (`id`);

ALTER TABLE pageencryption_permissions
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;


