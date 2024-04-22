<?php

/**
 * This file is part of the MediaWiki extension PageEncryption.
 *
 * PageEncryption is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * PageEncryption is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PageEncryption.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @file
 * @ingroup extensions
 * @author thomas-topway-it <support@topway.it>
 * @copyright Copyright ©2023, https://wikisphere.org
 */

class PageEncryptionApiSetEncryptionKey extends ApiBase {

	/**
	 * @inheritDoc
	 */
	public function isWriteMode() {
		return false;
	}

	/**
	 * @inheritDoc
	 */
	public function mustBePosted(): bool {
		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function execute() {
		$user = $this->getUser();

		if ( !$user->isAllowed( 'pageencryption-cancreateencryption' ) ) {
			$this->dieWithError( 'apierror-pageproperties-permissions-error' );
		}

		\PageEncryption::initialize( $user );

		$result = $this->getResult();

		$params = $this->extractRequestParams();

		$row = \PageEncryption::getEncryptionKeyRecord( $user->getId() );

		if ( $row ) {
			if ( !$params['reset-key'] ) {
				$message = null;
				$res = \PageEncryption::setUserKey( $row['protected_key'], $params['password'], $message );
				// close dialog or ask password again
				$result->addValue( [ $this->getModuleName() ], 'action', 'enter-password' );
				$result->addValue( [ $this->getModuleName() ], 'message', $message );
				return;
			}

			$result->addValue( [ $this->getModuleName() ], 'action', 'reset-key' );
			\PageEncryption::disableEncryptionKeyRecord( $row['id'] );
		}

		$message = null;
		$protected_key_encoded = null;
		$res = \PageEncryption::setEncryptionKey( $user->getId(), $params['password'], $message, $protected_key_encoded );

		$result->addValue( [ $this->getModuleName() ], 'action', 'new-record' );
		$result->addValue( [ $this->getModuleName() ], 'message', $message );

		// return the resulting protected key, for backup purpose,
		// since it is not password-deterministic
		$result->addValue( [ $this->getModuleName() ], 'protected-key', $protected_key_encoded );
	}

	/**
	 * @inheritDoc
	 */
	public function getAllowedParams() {
		return [
			'password' => [
				ApiBase::PARAM_TYPE => 'string',
				ApiBase::PARAM_REQUIRED => true
			],
			'reset-key' => [
				ApiBase::PARAM_TYPE => 'integer',
				ApiBase::PARAM_REQUIRED => true
			]
		];
	}

	/**
	 * @inheritDoc
	 */
	public function needsToken() {
		return 'csrf';
	}

	/**
	 * @inheritDoc
	 */
	protected function getExamplesMessages() {
		return [
			'action=pageencryption-set-encryption-key'
			=> 'apihelp-pageencryption-set-encryption-key-example-1'
		];
	}
}
