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
 * @copyright Copyright ©2023-2025, https://wikisphere.org
 */

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Defuse\Crypto\KeyProtectedByPassword;
use MediaWiki\Extension\PageEncryption\Aliases\Html as HtmlClass;
// use MediaWiki\Extension\PageEncryption\Aliases\Title as TitleClass;
use MediaWiki\MainConfigNames;
use MediaWiki\MediaWikiServices;
use MediaWiki\Revision\MutableRevisionSlots;
use MediaWiki\Revision\RevisionStore;
use MediaWiki\Revision\RevisionStoreRecord;
use MediaWiki\Revision\SlotRecord;

class PageEncryption {

	/** @var User */
	public static $User;

	/** @var userGroupManager */
	public static $userGroupManager;

	/** @var int */
	public static $encryptedNamespace = 2246;

	/** @var string */
	public static $cookieUserKey = 'pageencryption-userkey';

	/** @var array */
	public static $cachedMockUpRev = [];

	/** @const int */
	public const DecryptionFailed = 1;

	/** @const int */
	public const DecryptionFromAccessCode = 2;

	/** @const int */
	public const EncryptedPage = 3;

	/** @const int */
	public const DecryptionFromPublicKey = 4;

	/** @var int|null */
	public static $decryptionNotice = null;

	/**
	 * @param User|null $user
	 */
	public static function initialize( $user ) {
		self::$User = $user;
		self::$userGroupManager = MediaWikiServices::getInstance()->getUserGroupManager();
	}

	/**
	 * @return User|null
	 */
	public static function getUser() {
		if ( self::$User instanceof MediaWiki\User ) {
			return self::$User;
		}
		return RequestContext::getMain()->getUser();
	}

	/**
	 * @return array
	 */
	public static function getCookieOptions() {
		$context = RequestContext::getMain();
		$config = $context->getConfig();

		[
			$cookieSameSite,
			$cookiePrefix,
			$cookiePath,
			$cookieDomain,
			$cookieSecure,
			$forceHTTPS,
			$cookieHttpOnly,
		] = ( class_exists( 'MediaWiki\MainConfigNames' ) ?
			[
				MainConfigNames::CookieSameSite,
				MainConfigNames::CookiePrefix,
				MainConfigNames::CookiePath,
				MainConfigNames::CookieDomain,
				MainConfigNames::CookieSecure,
				MainConfigNames::ForceHTTPS,
				MainConfigNames::CookieHttpOnly
			] :
			[
				'CookieSameSite',
				'CookiePrefix',
				'CookiePath',
				'CookieDomain',
				'CookieSecure',
				'ForceHTTPS',
				'CookieHttpOnly'
			]
		);

		// @codeCoverageIgnoreStart
		return [
			'prefix' => $config->get( $cookiePrefix ),
			'path' => $config->get( $cookiePath ),
			'domain' => $config->get( $cookieDomain ),
			'secure' => $config->get( $cookieSecure )
				|| $config->get( $forceHTTPS ),
			'httpOnly' => $config->get( $cookieHttpOnly ),
			'sameSite' => $config->get( $cookieSameSite )
		];
	}

	/**
	 * @param string $cookieValue
	 * @return bool
	 */
	public static function setCookie( $cookieValue ) {
		// setcookie( 'pageencryption-passwordkey', $protected_key_encoded, array $options = []): bool
		$context = RequestContext::getMain();
		$request = $context->getRequest();
		$response = $request->response();
		// $session = SessionManager::getGlobalSession();
		// $expiration = $session->getProvider()->getRememberUserDuration();
		$cookieOptions = self::getCookieOptions();

		$session = $request->getSession();

		$sessionProvider = $session->getProvider();
		// !( $session->getProvider() instanceof CookieSessionProvider )
		// $info = $sessionProvider->provideSessionInfo( $request );
		// $provider = $info->getProvider();

		// @TODO subtract (current time - login time)
		$expiryValue = $sessionProvider->getRememberUserDuration() + time();
		$response->setCookie( self::$cookieUserKey, $cookieValue, $expiryValue, $cookieOptions );

		return true;
	}

	public static function deleteCookie() {
		$context = RequestContext::getMain();
		$request = $context->getRequest();
		$response = $request->response();

		// @see CookieSessionProvider unpersistSession
		$cookies = [
			self::$cookieUserKey => false,
		];
		$cookieOptions = self::getCookieOptions();

		foreach ( $cookies as $key => $value ) {
			$response->clearCookie( $key, $cookieOptions );
		}
	}

	/**
	 * @param int $pageId
	 * @param Key $user_key
	 * @return string|bool
	 */
	public static function decryptFromAccessCodeSession( $pageId, $user_key ) {
		$dbr = self::getDB( DB_REPLICA );
		$rows = $dbr->select( 'pageencryption_symmetric', '*', [ 'page_id' => $pageId ] );
		foreach ( $rows as $row ) {
			if ( empty( $row->viewed ) ) {
				continue;
			}
			$viewed_data = ( !empty( $row->viewed_data ) ? json_decode( $row->viewed_data ) : [] );
			$ip = ( !empty( $viewed_data['ip'] ) ? $viewed_data['ip'] : null );
			// the user might manually create a new cookie
			// to bypass the one-time use policy, for this
			// reason limit the access to the first 24 hours
			// and check that the IP is the same. For furher
			// access, encourage the user to register and to
			// use an asymmetric key
			// $ip !== self::getIPAddress() ||
			if ( strtotime( $row->viewed ) < time() - ( 60 * 60 * 24 )
				|| ( !empty( $row->expiration_date ) && time() > strtotime( $row->expiration_date ) ) ) {
				continue;
			}
			$text = $row->encrypted_content;
			try {
				$text = Crypto::decrypt( $text, $user_key );
			} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
				continue;
			}

			return $text;
		}
		return false;
	}

	/**
	 * @param int $pageId
	 * @param string $password
	 * @return string|bool
	 */
	public static function decryptFromAccessCode( $pageId, $password ) {
		$dbr = self::getDB( DB_PRIMARY );
		$rows = $dbr->select( 'pageencryption_symmetric', '*', [ 'page_id' => $pageId, 'viewed' => null ] );
		foreach ( $rows as $row ) {
			$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $row->protected_key );
			try {
				$user_key = $protected_key->unlockKey( $password );
			} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
				continue;
			}
			$user_key_encoded = $user_key->saveToAsciiSafeString();
			$context = RequestContext::getMain();
			$request = $context->getRequest();
			$response = $request->response();
			$cookieOptions = self::getCookieOptions();
			$cookieValue = $user_key_encoded;
			$expiryValue = 0;
			$cookieOptions = self::getCookieOptions();
			$cookieKey = self::$cookieUserKey . '-acode-' . $pageId;
			$response->setCookie( $cookieKey, $cookieValue, $expiryValue, $cookieOptions );

			// $ret = Key::loadFromAsciiSafeString( $user_key_encoded );
			$text = $row->encrypted_content;
			try {
				$text = Crypto::decrypt( $text, $user_key );
			} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
				continue;
			}
			$date = date( 'Y-m-d H:i:s' );

			// allow no-track
			$viewed_metadata = ( empty( $_GET['no_track'] ) ? json_encode( [
				'ip' => self::getIPAddress(),
				'user_agent' => $_SERVER['HTTP_USER_AGENT']
			] ) : null );
			$res = $dbr->update( 'pageencryption_symmetric', [
				'viewed' => $date,
				'viewed_metadata' => $viewed_metadata
				],
				[ 'id' => $row->id ], __METHOD__ );
			return $text;
		}
		return false;
	}

	/**
	 * @param int $pageId
	 * @param User $user
	 * @return string|null|bool
	 */
	public static function decryptFromPublicKey( $pageId, $user ) {
		$row_ = self::getEncryptionKeyRecord( $user->getId() );
		if ( !$row_ ) {
			return false;
		}

		$dbr = self::getDB( DB_PRIMARY );
		$rows = $dbr->select( 'pageencryption_asymmetric', '*', [ 'page_id' => $pageId, 'recipient_id' => $user->getId() ] );

		if ( !$rows->numRows() ) {
			return false;
		}

		// *** solution 1
		// $skpk = self::keyPairFromKey( $password );
		$errorMessage = null;
		$user_key = self::getUserKey( $errorMessage );

		if ( $user_key === false ) {
			return false;
		}

		$encrypted_private_key = $row_['encrypted_private_key'];
		$recipient_secret_key = self::decryptSymmetric( $encrypted_private_key, $user_key );

		$userFactory = MediaWikiServices::getInstance()->getUserFactory();
		foreach ( $rows as $row ) {
			if ( !empty( $row->expiration_date ) && time() > strtotime( $row->expiration_date ) ) {
				continue;
			}

			$user_ = $userFactory->newFromId( $row->created_by );
			$sender_public_key = self::getPublicKey( $user_ );
			$recipient_keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey( $recipient_secret_key, $sender_public_key );

			// Authenticate and decrypt message
			$ret = sodium_crypto_box_open( $row->encrypted_content, $row->nonce, $recipient_keypair );

			if ( $ret !== false ) {
				$date = date( 'Y-m-d H:i:s' );
				$res = $dbr->update( 'pageencryption_asymmetric', [
					'viewed' => $date,
					],
					[ 'id' => $row->id ], __METHOD__ );
				return $ret;
			}
		}

		return false;
	}

	/**
	 * @param RevisionStoreRecord $rev
	 * @return mixed
	 */
	public static function mockUpRevision( $rev ) {
		$cacheKey = $rev->getId();

		// *** prevents error "Sessions are disabled for load entry point"
		try {
			self::getUser()->getId();
		} catch ( Exception $e ) {
			// @phpcs:disable MediaWiki.Usage.AssignmentInReturn
			return self::$cachedMockUpRev[$cacheKey] = $rev;
		}

		if ( method_exists( RevisionStore::class, 'getPage' ) ) {
			$pageIdentity = $rev->getPage();
		} else {
			$pageIdentity = $rev->getPageAsLinkTarget();
		}

		$titleFactory = MediaWikiServices::getInstance()->getTitleFactory();
		$title = $titleFactory->newFromPageIdentity( $pageIdentity );

		if ( !self::isEncryptedNamespace( $title ) ) {
			return self::$cachedMockUpRev[$cacheKey] = $rev;
		}

		$isSamePage = ( RequestContext::getMain()->getTitle() === $title );
		if ( array_key_exists( $cacheKey, self::$cachedMockUpRev ) ) {
			return self::$cachedMockUpRev[$cacheKey];
		}

		$content = $rev->getSlot( SlotRecord::MAIN )->getContent();

		if ( !( $content instanceof TextContent ) ) {
			return self::$cachedMockUpRev[$cacheKey] = $rev;
		}

		$user = self::getUser();
		$text = $content->getText();
		$ret = false;
		$pageId = $title->getId();
		if ( $rev->getUser()->getId() !== $user->getId() ) {
			$cookieKey = self::$cookieUserKey . '-acode-' . $pageId;
			$context = RequestContext::getMain();
			$request = $context->getRequest();
			$user_key_encoded = $request->getCookie( $cookieKey );

			if ( !empty( $user_key_encoded ) ) {
				try {
					$user_key = Key::loadFromAsciiSafeString( $user_key_encoded );
				} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
				}
				$ret = self::decryptFromAccessCodeSession( $pageId, $user_key );
			}

			if ( $ret === false && isset( $_GET['acode'] ) ) {
				$ret = self::decryptFromAccessCode( $pageId, $_GET['acode'] );
			}

			if ( $ret !== false ) {
				if ( $isSamePage ) {
					self::$decryptionNotice = self::DecryptionFromAccessCode;
				}
			}

			if ( $ret === false ) {
				$ret = self::decryptFromPublicKey( $pageId, $user );

				if ( $ret !== false ) {
					if ( $isSamePage ) {
						self::$decryptionNotice = self::DecryptionFromPublicKey;
					}
				}
			}

			if ( $ret === false ) {
				if ( $isSamePage ) {
					self::$decryptionNotice = self::EncryptedPage;
				}

				return self::$cachedMockUpRev[$cacheKey] = $rev;
			}

		} else {
			$errorMessage = null;
			$user_key = self::getUserKey( $errorMessage );
			if ( $user_key !== false ) {
				$ret = self::decryptSymmetric( $text, $user_key );
			} else {
				// throw new MWException( 'user-key not set' );
				$ret = false;
			}
		}

		if ( $ret === false ) {
			if ( $isSamePage ) {
				self::$decryptionNotice = self::DecryptionFailed;
			}
			return self::$cachedMockUpRev[$cacheKey] = $rev;
		}
		// should be instance of text
		$contentHandler = $content->getContentHandler();
		$modelId = $contentHandler->getModelID();

		$slotContent = ContentHandler::makeContent( $ret, $title, $modelId );

		// >>>>>>>>>>>>>>>>>>>>>
		// *** we cannot use simply the following:

		// $revisionRecord = MutableRevisionRecord::newFromParentRevision( $rev );
		// $slots = $revisionRecord->getSlots();
		// $slots->setContent( MediaWiki\Revision\SlotRecord::MAIN, $slotContent );

		// since slot_revision_id is not inherited, and
		// when the slot is inherited twice (namely on
		// doContentModelChange) it will trigger an error

		$slotsArr =	$rev->getSlots()->getSlots();
		$slot = $slotsArr[SlotRecord::MAIN];

		$row = [
			'slot_id' => null,
			'slot_revision_id' => $slot->getRevision(),
			'slot_origin' => $slot->getOrigin(),
			'content_size' => $slot->getSize(),
			'content_sha1' => $slot->getSha1(),
			'slot_content_id' => $slot->getContentId(),
			'content_address' => $slot->getAddress(),
			'role_name' => SlotRecord::MAIN,
			'model_name' => $slot->getModel(),
		];

		$slot = new SlotRecord( (object)$row, $slotContent, $slot->isDerived() );

		$slots = new MutableRevisionSlots( $slotsArr );
		$slots->setSlot( $slot );

		// <<<<<<<<<<<<<<<<<<<<<<<

		$user = $rev->getUser();
		$comment = $rev->getComment();
		$row = [
			'rev_id' => $rev->getId(),
			'rev_page' => $title->getId(),
			'rev_timestamp' => $rev->getTimestamp(),
			'rev_minor_edit' => $rev->isMinor(),
			'rev_deleted' => $rev->getVisibility(),
			'rev_parent_id' => $rev->getParentId(),
			'rev_len' => $rev->getSize(),
			'rev_sha1' => $rev->getSha1(),
			'page_latest' => $rev->getId(),
		];

		return self::$cachedMockUpRev[$cacheKey] = new RevisionStoreRecord( $title, $user, $comment, (object)$row, $slots );
		// @phpcs:enable
	}

	/**
	 * @param string &$errorMessage
	 * @return Key|false
	 */
	public static function getUserKey( &$errorMessage ) {
		if ( !class_exists( 'Defuse\Crypto\Key' ) ) {
			$errorMessage = wfMessage( 'pageencryption-error-defuse-lib-not-found' )->parse();
			return false;
		}
		$context = RequestContext::getMain();
		$request = $context->getRequest();
		$user_key_encoded = $request->getCookie( self::$cookieUserKey );
		if ( !$user_key_encoded ) {
			return false;
		}
		try {
			return Key::loadFromAsciiSafeString( $user_key_encoded );

		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
			$errorMessage = $ex->getMessage();
		}
		return false;
	}

	/**
	 * @param string $text
	 * @param Key $user_key
	 * @return false|string
	 */
	public static function decryptSymmetric( $text, $user_key ) {
		try {
			$text = Crypto::decrypt( $text, $user_key );
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
			return false;
		}
		return $text;
	}

	/**
	 * @param string $text
	 * @param Key $user_key
	 * @return false|string
	 */
	public static function encryptSymmetric( $text, $user_key ) {
		try {
			$text = Crypto::encrypt( $text, $user_key );
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
			return false;
		}
		return $text;
	}

	/**
	 * @return MediaWiki\User\UserGroupManager|null
	 */
	public static function getUserGroupManager() {
		if ( self::$userGroupManager instanceof MediaWiki\User\UserGroupManager ) {
			return self::$userGroupManager;
		}
		return MediaWikiServices::getInstance()->getUserGroupManager();
	}

	/**
	 * @param User $user
	 * @param Title|MediaWiki\Title\Title $title
	 * @param string $expiration_date
	 * @param int|null $id
	 * @return bool
	 */
	public static function setPermissionsSymmetric( $user, $title, $expiration_date, $id = null ) {
		$table = 'pageencryption_symmetric';
		$row = [ 'expiration_date' => $expiration_date ];
		$dbr = self::getDB( DB_PRIMARY );

		if ( empty( $row['expiration_date'] ) ) {
			$row['expiration_date'] = null;
		}
		$date = date( 'Y-m-d H:i:s' );
		if ( !$id ) {
			$row['created_by'] = $user->getId();
			$row['page_id'] = $title->getArticleId();
			$wikiPage = self::getWikiPage( $title );
			$revisionRecord = $wikiPage->getRevisionRecord();
			$row['revision_id'] = $revisionRecord->getId();
			$errorMessage = null;
			$user_key = self::getUserKey( $errorMessage );

			if ( $user_key === false ) {
				throw new MWException( 'user-key not set' );
			}

			$contentHandler = $revisionRecord->getSlot( SlotRecord::MAIN )->getContent()->getContentHandler();
			$modelId = $contentHandler->getModelID();

			$content = $revisionRecord->getSlot( SlotRecord::MAIN )->getContent();

			// should be instance of text
			$contentHandler = $content->getContentHandler();
			$text = $content->getText();

			do {
				$password = self::randomStr( 5 );
				$row['encrypted_password'] = self::encryptSymmetric( $password, $user_key );

				$row_ = $dbr->selectRow(
					'pageencryption_symmetric',
					'*',
					[ 'page_id' => $row['page_id'], 'encrypted_password' => $row['encrypted_password'] ],
					__METHOD__
				);
			} while ( $row_ !== false );

			$protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey( $password );
			$protected_key_encoded = $protected_key->saveToAsciiSafeString();
			$user_key = $protected_key->unlockKey( $password );
			$text = self::encryptSymmetric( $text, $user_key );
			$row['protected_key'] = $protected_key_encoded;
			$row['encrypted_content'] = $text;

			$res = $dbr->insert( 'pageencryption_symmetric', $row + [ 'updated_at' => $date, 'created_at' => $date ] );
		} else {
			$res = $dbr->update( 'pageencryption_symmetric', $row, [ 'id' => $id ], __METHOD__ );
		}
		return $res;
	}

	/**
	 * @param User $user
	 * @param Title|MediaWiki\Title\Title $title
	 * @param User $recipient
	 * @param string $public_key
	 * @param string $expiration_date
	 * @param int|null $id
	 * @return bool
	 */
	public static function setPermissionsAsymmetric( $user, $title, $recipient, $public_key, $expiration_date, $id = null ) {
		$row = [ 'expiration_date' => $expiration_date ];
		$dbr = self::getDB( DB_PRIMARY );

		if ( empty( $row['expiration_date'] ) ) {
			$row['expiration_date'] = null;
		}
		$date = date( 'Y-m-d H:i:s' );
		$row['recipient_id'] = $recipient->getId();

		if ( !$id ) {
			$row['created_by'] = $user->getId();
			$row['page_id'] = $title->getArticleId();
			$wikiPage = self::getWikiPage( $title );
			$revisionRecord = $wikiPage->getRevisionRecord();
			$row['revision_id'] = $revisionRecord->getId();
			$errorMessage = null;
			$user_key = self::getUserKey( $errorMessage );

			if ( $user_key === false ) {
				throw new MWException( 'user-key not set' );
			}

			$contentHandler = $revisionRecord->getSlot( SlotRecord::MAIN )->getContent()->getContentHandler();
			$modelId = $contentHandler->getModelID();

			$content = $revisionRecord->getSlot( SlotRecord::MAIN )->getContent();

			// should be instance of text
			$contentHandler = $content->getContentHandler();
			$text = $content->getText();

			$nonce = \random_bytes( \SODIUM_CRYPTO_BOX_NONCEBYTES );
			$row['nonce'] = $nonce;

			$row_ = self::getEncryptionKeyRecord( $user->getId() );
			$encrypted_private_key = $row_['encrypted_private_key'];
			$sender_secret_key = self::decryptSymmetric( $encrypted_private_key, $user_key );

			// @see https://php.watch/articles/modern-php-encryption-decryption-sodium
			// Create enc/sign key pair
			$sender_keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey( $sender_secret_key, $public_key );

			// Encrypt and sign the message
			$text = sodium_crypto_box( $text, $nonce, $sender_keypair );
			$row['encrypted_content'] = $text;

			$res = $dbr->insert( 'pageencryption_asymmetric', $row + [ 'updated_at' => $date, 'created_at' => $date ] );
		} else {
			$res = $dbr->update( 'pageencryption_asymmetric', $row, [ 'id' => $id ], __METHOD__ );
		}
		return $res;
	}

	/**
	 * @param string $protected_key
	 * @param string $password
	 * @param string &$errorMessage
	 * @return bool
	 */
	public static function setUserKey( $protected_key, $password, &$errorMessage ) {
		if ( !class_exists( 'Defuse\Crypto\Key' ) ) {
			$errorMessage = wfMessage( 'pageencryption-error-defuse-lib-not-found' )->parse();
			return false;
		}
		$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $protected_key );

		// @see https://github.com/defuse/php-encryption/blob/master/docs/classes/Crypto.md
		try {
			$user_key = $protected_key->unlockKey( $password );
			$user_key_encoded = $user_key->saveToAsciiSafeString();
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
			$errorMessage = wfMessage( 'pageencryption-error-message-password-doesnotmatch' )->text();
			return false;
		}
		$res = self::setCookie( $user_key_encoded );
		if ( $res === false ) {
			$errorMessage = wfMessage( 'pageencryption-error-message-cannot-set-cookie' )->text();
		}

		return $res;
	}

	/**
	 * @param array $row
	 * @return bool
	 */
	public static function disableEncryptionKeyRecord( $row ) {
		$dbw = self::getDB( DB_PRIMARY );
		return $dbw->update(
			'pageencryption_keys',
			[ 'enabled' => 0 ],
			[ 'id' => $row['id'] ],
			__METHOD__
		);
	}

	/**
	 * @param int $user_id
	 * @param string $password
	 * @param string &$message
	 * @param string &$protected_key_encoded
	 * @return bool
	 */
	public static function setEncryptionKey( $user_id, $password, &$message, &$protected_key_encoded ) {
		$protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey( $password );
		$protected_key_encoded = $protected_key->saveToAsciiSafeString();

		// alternate solution: derive key-pair each time
		// $skpk = self::keyPairFromKey( $password );

		// https://php.watch/articles/modern-php-encryption-decryption-sodium
		$keypair = sodium_crypto_box_keypair();
		$secret_key = sodium_crypto_box_secretkey( $keypair );
		$public_key = sodium_crypto_box_publickey( $keypair );

		// $protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $protected_key_encoded );
		$user_key = $protected_key->unlockKey( $password );
		$encrypted_private_key = self::encryptSymmetric( $secret_key, $user_key );

		$row = [
			'user_id' => $user_id,
			'protected_key' => $protected_key_encoded,
			'public_key' => $public_key,
			'encrypted_private_key' => $encrypted_private_key,

			// alternate solution: derive key-pair each time
			// @see https://security.stackexchange.com/questions/268242/feedback-wanted-regarding-my-functions-to-encrypt-decrypt-data-using-php-openss
			// 'public_key' => sodium_crypto_box_publickey( $skpk )
		];

		$date = date( 'Y-m-d H:i:s' );

		$dbr = self::getDB( DB_PRIMARY );
		$res = $dbr->insert( 'pageencryption_keys', $row + [ 'updated_at' => $date, 'created_at' => $date ] );

		if ( !$res ) {
			$message = wfMessage( 'pageencryption-error-message-cannot-save-encryptionkey' )->text();
			return false;
		}

		$user_key_encoded = $user_key->saveToAsciiSafeString();
		$res = self::setCookie( $user_key_encoded );
		if ( $res === false ) {
			$message = wfMessage( 'pageencryption-error-message-cannot-set-cookie' )->text();
		}
		return $res;
	}

	/**
	 * *** currently unused
	 * @see https://security.stackexchange.com/questions/268242/feedback-wanted-regarding-my-functions-to-encrypt-decrypt-data-using-php-openss
	 * @see https://gist.github.com/bcremer/858e4a3c279b276751335dc38fc162c5
	 * @param string $secret_input
	 * @return string
	 */
	public static function keyPairFromKey( $secret_input ) {
		// the user's salt, unique per-user
		$a2id_salt = random_bytes( SODIUM_CRYPTO_PWHASH_SALTBYTES );

		// approx. 2-sec delay (~2020 cpu php7.4)
		$a2id_ops = 4;

		// 1gib
		$a2id_membytes = 1024 * 1024 * 1024;

		// if need be, adjust both downward until the delay is tolerable, but no faster than say ~250msec in 2023, ie.
		// echo SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE.PHP_EOL;  # 2
		// echo SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE.PHP_EOL;  # 67108864 (64mib)

		// note $length is set long enough for two separate keys
		// (you don't need to do this if not signing/ hashing anything)
		$sk_signk_seeds = sodium_crypto_pwhash(
			( SODIUM_CRYPTO_BOX_SEEDBYTES + SODIUM_CRYPTO_SIGN_SEEDBYTES ),

			// string $password,
			$secret_input,

			// string $salt,
			$a2id_salt,

			// int $opslimit,
			$a2id_ops,

			// int $memlimit,
			$a2id_membytes,

			// int $algo
			SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
		);

		return sodium_crypto_box_seed_keypair(
			substr( $sk_signk_seeds, 0, SODIUM_CRYPTO_BOX_SEEDBYTES )
		);
	}

	/**
	 * @param Title|MediaWiki\Title\Title $title
	 * @return bool
	 */
	public static function isEncryptedNamespace( $title ) {
		return $title->getNamespace() === self::$encryptedNamespace;
	}

	/**
	 * @see OutputPage addHelpLink
	 * @param OutputPage $outputPage
	 */
	public static function addIndicator( $outputPage ) {
		$to = 'Extension:PageEncryption';
		$toUrlencoded = wfUrlencode( str_replace( ' ', '_', $to ) );
		$helpUrl = "https://www.mediawiki.org/wiki/Special:MyLanguage/$toUrlencoded";
		$text = '';
		$link = HtmlClass::rawElement(
			'a',
			[
				'href' => $helpUrl,
				'target' => '_blank',
				'class' => 'pageencryption-indicator',
			],
			$text
		);

		$outputPage->setIndicators( [
			'pageencryption' => $link
		] );
	}

	/**
	 * @param User $user
	 * @return string|null
	 */
	public static function getPublicKey( $user ) {
		$dbr = self::getDB( DB_REPLICA );
		$ret = $dbr->selectField(
			'pageencryption_keys',
			'public_key',
			[ 'user_id' => $user->getId(), 'enabled' => 1 ],
			__METHOD__,
			[ 'LIMIT' => 1 ]
		);
		return !empty( $ret ) ? $ret : null;
	}

	/**
	 * @param OutputPage $outputPage
	 * @param Title|MediaWiki\Title\Title $title
	 * @param User $user
	 */
	public static function addJsConfigVars( $outputPage, $title, $user ) {
		// $wikiPage = \PageEncryption::getWikiPage( $title );
		// $revisionRecord = $wikiPage->getRevisionRecord();
		// if ( $revisionRecord && $user->getId() !== $revisionRecord->getUser()->getId() ) {
		// 	return;
		// }

		$isEditor = self::isEditor( $title, $user );
		$public_key = self::getPublicKey( $user );

		$isEncryptedNamespace = false;
		if ( $title->isSpecialPage() && $title->getText() === 'PageEncryptionPermissions' ) {
			$isEncryptedNamespace = true;

		} else {
			$isEncryptedNamespace = self::isEncryptedNamespace( $title );
		}

		$errorMessage = null;
		$userKey = self::getUserKey( $errorMessage );

		$outputPage->addJsConfigVars( [
			// httpOnly cookies cannot be accessed client-side, so we
			// set a specific variable
			'pageencryption-config' => [
				'isEncryptedNamespace' => $isEncryptedNamespace,
				'canHandleEncryption' => $user->isAllowed( 'pageencryption-can-handle-encryption' ),
				'canManageEncryption' => $user->isAllowed( 'pageencryption-can-manage-encryption' ),
				'isEditor' => $isEditor,
				'publicKeyIsSet' => $public_key !== null,
				'userkeyCookieIsSet' => ( $userKey !== false ),
				'protectedKeyIsSet' => is_array( self::getEncryptionKeyRecord( $user->getId() ) ),
			]
		] );
	}

	/**
	 * @param int $userId
	 * @return array|null
	 */
	public static function getEncryptionKeyRecord( $userId ) {
		$dbr = self::getDB( DB_REPLICA );
		$row = $dbr->selectRow(
			'pageencryption_keys',
			'*',
			[ 'user_id' => $userId, 'enabled' => 1 ],
			__METHOD__
		);
		return $row ? (array)$row : null;
	}

	/**
	 * @param array $conds
	 * @return void
	 */
	public static function deleteEncryptionKey( $conds ) {
		$dbw = self::getDB( DB_PRIMARY );
		$dbw->delete(
			'pageencrption_keys', $conds,
			__METHOD__
		);
	}

	/**
	 * @param string $type
	 * @param array $conds
	 * @return void
	 */
	public static function deletePermissions( $type, $conds ) {
		$dbw = self::getDB( DB_PRIMARY );
		$dbw->delete(
			"pageencryption_$type", $conds,
			__METHOD__
		);
	}

	/**
	 * @param OutputPage $outputPage
	 * @param array $items
	 * @return array
	 */
	public static function addHeaditem( $outputPage, $items ) {
		foreach ( $items as $key => $val ) {
			[ $type, $url ] = $val;
			switch ( $type ) {
				case 'stylesheet':
					$item = '<link rel="stylesheet" href="' . $url . '" />';
					break;
				case 'script':
					$item = '<script src="' . $url . '"></script>';
					break;
			}
			// @phan-suppress-next-line PhanTypeMismatchArgumentNullable
			$outputPage->addHeadItem( 'pageencryption_head_item' . $key, $item );
		}
	}

	/**
	 * @param Title|MediaWiki\Title\Title $title
	 * @return bool
	 */
	public static function isKnownArticle( $title ) {
		// *** unfortunately we cannot always rely on $title->isContentPage()
		// @see https://github.com/debtcompliance/EmailPage/pull/4#discussion_r1191646022
		// or use $title->exists()
		return ( $title && $title->canExist() && $title->getArticleID() > 0
			&& $title->isKnown() );
	}

	/**
	 * @param Title|MediaWiki\Title\Title $title
	 * @param User|null $user
	 * @return bool
	 */
	public static function isEditor( $title, $user = null ) {
		if ( !self::isKnownArticle( $title ) ) {
			return false;
		}
		if ( !$user ) {
			$user = self::getUser();
		}
		$page = self::getWikiPage( $title );
		return $page->getUser() === $user->getId();
	}

	/**
	 * @param User $user
	 * @return bool
	 */
	public static function isAuthorized( $user ) {
		$admins = self::getGlobalParameterAsArray( 'wgPageEncryptionAdmins' );
		$admins = array_unique( array_merge( $admins, [ 'sysop' ] ) );
		return self::matchUsernameOrGroup( $user, $admins );
	}

	/**
	 * @param User $user
	 * @param array $groups
	 * @return bool
	 */
	public static function matchUsernameOrGroup( $user, $groups ) {
		$userGroupManager = self::getUserGroupManager();
		// ***the following prevents that an user
		// impersonates a group through the username
		$all_groups = array_merge( $userGroupManager->listAllGroups(), $userGroupManager->listAllImplicitGroups() );
		$authorized_users = array_diff( $groups, $all_groups );
		$authorized_groups = array_intersect( $groups, $all_groups );
		$user_groups = self::getUserGroups( $userGroupManager, $user );
		$isAuthorized = count( array_intersect( $authorized_groups, $user_groups ) );
		if ( !$isAuthorized ) {
			$isAuthorized = in_array( $user->getName(), $authorized_users );
		}
		return $isAuthorized;
	}

	/**
	 * @param string $varName
	 * @return array
	 */
	public static function getGlobalParameterAsArray( $varName ) {
		$ret = ( array_key_exists( $varName, $GLOBALS ) ? $GLOBALS[ $varName ] : null );
		if ( empty( $ret ) ) {
			$ret = [];
		}
		if ( !is_array( $ret ) ) {
			$ret = preg_split( "/\s*,\s*/", $ret, -1, PREG_SPLIT_NO_EMPTY );
		}
		return $ret;
	}

	/**
	 * @param MediaWiki\User\UserGroupManager $userGroupManager
	 * @param User $user
	 * @param bool $replace_asterisk
	 * @return array
	 */
	public static function getUserGroups( $userGroupManager, $user, $replace_asterisk = false ) {
		$user_groups = $userGroupManager->getUserEffectiveGroups( $user );
		// $user_groups[] = $user->getName();
		if ( array_search( '*', $user_groups ) === false ) {
			$user_groups[] = '*';
		}
		if ( $replace_asterisk ) {
			$key = array_search( '*', $user_groups );
			$user_groups[ $key ] = 'all';
		}
		return $user_groups;
	}

	/**
	 * @param Title|MediaWiki\Title\Title $title
	 * @return void
	 */
	public static function getWikiPage( $title ) {
		// MW 1.36+
		if ( method_exists( MediaWikiServices::class, 'getWikiPageFactory' ) ) {
			return MediaWikiServices::getInstance()->getWikiPageFactory()->newFromTitle( $title );
		}
		return WikiPage::factory( $title );
	}

	/**
	 * @param int $db
	 * @return \Wikimedia\Rdbms\DBConnRef
	 */
	public static function getDB( $db ) {
		if ( !method_exists( MediaWikiServices::class, 'getConnectionProvider' ) ) {
			// @see https://gerrit.wikimedia.org/r/c/mediawiki/extensions/PageEncryption/+/1038754/comment/4ccfc553_58a41db8/
			return MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( $db );
		}
		$connectionProvider = MediaWikiServices::getInstance()->getConnectionProvider();
		switch ( $db ) {
			case DB_PRIMARY:
				return $connectionProvider->getPrimaryDatabase();
			case DB_REPLICA:
			default:
				return $connectionProvider->getReplicaDatabase();
		}
	}

	/**
	 * @see https://stackoverflow.com/questions/6101956/generating-a-random-password-in-php
	 * @param int $length
	 * @param string $keyspace to select from
	 * @return string
	 */
	private static function randomStr(
		int $length,
		string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	): string {
		$str = '';
		$max = mb_strlen( $keyspace, '8bit' ) - 1;
		if ( $max < 1 ) {
			throw new Exception( '$keyspace must be at least two characters long' );
		}
		for ( $i = 0; $i < $length; ++$i ) {
			$str .= $keyspace[random_int( 0, $max )];
		}
		return $str;
	}

	/**
	 * @return string
	 */
	public static function getIPAddress() {
		if ( !empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			return $_SERVER['HTTP_CLIENT_IP'];
		}
		if ( !empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			return $_SERVER['HTTP_X_FORWARDED_FOR'];
		}
		return $_SERVER['REMOTE_ADDR'];
	}
}
