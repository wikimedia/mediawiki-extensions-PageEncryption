CREATE TABLE IF NOT EXISTS pageencryption_asymmetric (
  `id` int(11) NOT NULL,
  `created_by` int(11) NOT NULL,
  `page_id` int(11) NULL,
  `revision_id` int(11) NULL,
  `recipient_id` int(11) NOT NULL,
  `nonce` BYTEA NOT NULL,
  `encrypted_content` BYTEA NOT NULL,
  `expiration_date` datetime NULL,
  `viewed` datetime NULL,
  `viewed_metadata` TEXT NULL,
  `updated_at` datetime NOT NULL,
  `created_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


ALTER TABLE pageencryption_asymmetric
  ADD PRIMARY KEY (`id`);

ALTER TABLE pageencryption_asymmetric
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

