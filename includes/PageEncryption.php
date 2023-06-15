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
use Defuse\Crypto\Crypto;
use Defuse\Crypto\KeyProtectedByPassword;
use Defuse\Crypto\Key;
use MediaWiki\MainConfigNames;
use MediaWiki\MediaWikiServices;
use MediaWiki\Revision\RevisionStore;
use MediaWiki\Revision\MutableRevisionRecord;
use MediaWiki\Revision\RevisionStoreRecord;
use MediaWiki\Session\SessionManager;
class PageEncryption {
	/** @var User */
	public static $User;
	/** @var userGroupManager */
	public static $userGroupManager;
	
	/** @var encryptedNamespace */
	public static $encryptedNamespace = 2246;
	
	/** @var cookieUserKey */
	public static $cookieUserKey = 'pageencryption-userkey';
	
	/** @var cachedMockUpRev */
	public static $cachedMockUpRev = [];
	/** @const DecryptionFailed */
	public const DecryptionFailed = 1;
	
	/** @const DecryptionFromAccessCode */
	public const DecryptionFromAccessCode = 2;
	/** @const EncryptedPage */
	public const EncryptedPage = 3;
	
	/** @var decryptionNotice */
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
	 * param string $password
	 * @return string
	 */
	public static function saveProtectedKey( $password ) {
		// @see https://github.com/defuse/php-encryption/blob/master/docs/Tutorial.md
		$protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey( $password );
		$protected_key_encoded = $protected_key->saveToAsciiSafeString();
   		$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $protected_key_encoded );
   		
   		// @todo save to database
   		
   		return $protected_key;
	}
	/**
	 * @return array
	 */
	public static function getCookieOptions() {
		$context = RequestContext::getMain();
		$config = $context->getConfig();
		
		list(
			$cookieSameSite,
			$cookiePrefix,
			$cookiePath,
			$cookieDomain,
			$cookieSecure,
			$forceHTTPS,
			$cookieHttpOnly,
		) = ( class_exists( 'MediaWiki\MainConfigNames' ) ?
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
	 * @return 
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
		return $response->setCookie( self::$cookieUserKey, $cookieValue, $expiryValue, $cookieOptions );
	}
	
	/**
	 * @return 
	 */
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
		$dbr = wfGetDB( DB_REPLICA );
		$rows = $dbr->select( 'pageencryption_permissions', '*', [ 'page_id' => $pageId ] );
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
		$dbr = wfGetDB( DB_MASTER );
		$rows = $dbr->select( 'pageencryption_permissions', '*', [ 'page_id' => $pageId, 'viewed' => null ] );
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
			$res = $dbr->update( 'pageencryption_permissions', [
				'viewed' => $date,
				'viewed_metadata' => $viewed_metadata
				],
				[ 'id' => $row->id ], __METHOD__ );
			return $text;
		}
		return false;
	}
	
	/**
	 * @param
	 * @return 
	 */
	public static function mockUpRevision( $rev ) {
		if ( method_exists( RevisionStore::class, 'getPage' ) ) {
			$title = $rev->getPage();
		} else {
			$title = $rev->getPageAsLinkTarget();
		}
		$isSamePage = ( RequestContext::getMain()->getTitle() === $title );
		$cacheKey = $rev->getId();
		if ( array_key_exists( $cacheKey, self::$cachedMockUpRev ) ) {
			return self::$cachedMockUpRev[$cacheKey];
		}
		
		$content = $rev->getSlot( MediaWiki\Revision\SlotRecord::MAIN )->getContent();    
		$text = $content->getText();
		$pageId = $title->getId();
		if ( $rev->getUser()->getId() !== self::getUser()->getId() ) {
			$cookieKey = self::$cookieUserKey . '-acode-' . $pageId;
			$context = RequestContext::getMain();
			$request = $context->getRequest();
			$user_key_encoded = $request->getCookie( $cookieKey );
			if ( !empty( $user_key_encoded ) ) {
				try {
					$user_key = Key::loadFromAsciiSafeString( $user_key_encoded );
				} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
    			}
				$text = self::decryptFromAccessCodeSession( $pageId, $user_key );
			} elseif ( !empty( $_GET['acode'] ) ) {
				$text = self::decryptFromAccessCode( $pageId, $_GET['acode'] );
			} else {
				if ( $isSamePage ) {
					self::$decryptionNotice = self::EncryptedPage;
				}
				return self::$cachedMockUpRev[$cacheKey] = $rev;
			}
			if ( $text !== false ) {
				if ( $isSamePage ) {
					self::$decryptionNotice = self::DecryptionFromAccessCode;
				}
			}
		} else {
			$text = self::decryptSymmetric( $text );
		}
		if ( $text === false ) {
			if ( $isSamePage ) {
				self::$decryptionNotice = self::DecryptionFailed;
			}
			return self::$cachedMockUpRev[$cacheKey] = $rev;
		}
		// should be instance of text
		$contentHandler = $content->getContentHandler();
		$modelId = $contentHandler->getModelID();
	
		$slotContent = ContentHandler::makeContent( $text, $title, $modelId );
		$revisionRecord = MutableRevisionRecord::newFromParentRevision( $rev );
		$slots = $revisionRecord->getSlots();
		$slots->setContent( MediaWiki\Revision\SlotRecord::MAIN, $slotContent );
       
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
	}
	/**
	 * @return string
	 */
	public static function getUserKey() {
	   	$context = RequestContext::getMain();
    	$request = $context->getRequest();
		if ( !$user_key_encoded = $request->getCookie( self::$cookieUserKey ) ) {
			return false;
		}
		try {
			$ret = Key::loadFromAsciiSafeString( $user_key_encoded );
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
    
		}
		return $ret;
	}
	/**
	 * @return false|string
	 */
	public static function decryptSymmetric( $text ) {
		if ( !$user_key = self::getUserKey() ) {
			return false;
		}
		try {
			$text = Crypto::decrypt( $text, $user_key );
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
    		return false;
		}
		return $text;
	}
	/**
	 * @param string $text
	 * @param string|null $user_key
	 * @return false|string
	 */
	public static function encryptSymmetric( $text, $user_key = null ) {
		if ( !$user_key && !$user_key = self::getUserKey() ) {
			return false;
		}
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
	 * @param Title $title
	 * @param array $row
	 * @param int|null $id
	 * @return bool
	 */
	public static function setPermissions( $user, $title, $row, $id = null ) {
		$dbr = wfGetDB( DB_MASTER );
		if ( empty( $row['expiration_date'] ) ) {
			$row['expiration_date'] = null;
		}
		$date = date( 'Y-m-d H:i:s' );
		if ( !$id ) {
			if ( empty( $row['access_type'] ) ) {
				$row['access_type'] = 'symmetric';
			}
			$row['created_by'] = $user->getId();
			$row['page_id'] = $title->getArticleId();
			$wikiPage = \PageEncryption::getWikiPage( $title );
			$revisionRecord = $wikiPage->getRevisionRecord();
			$row['revision_id'] = $revisionRecord->getId();
			do {
				$password = self::random_str( 5 );
				$row['encrypted_password'] = self::encryptSymmetric( $password );
			
				$row_ = $dbr->selectRow(
					'pageencryption_permissions',
					'*',
					[ 'page_id' => $row['page_id'], 'encrypted_password' => $row['encrypted_password'] ],
					__METHOD__
				);
			} while( $row_ !== false );
			$contentHandler = $revisionRecord->getSlot( MediaWiki\Revision\SlotRecord::MAIN )->getContent()->getContentHandler();
			$modelId = $contentHandler->getModelID();
        
			$content = $revisionRecord->getSlot( MediaWiki\Revision\SlotRecord::MAIN )->getContent();
          
			// should be instance of text
			$contentHandler = $content->getContentHandler();
			
			$text = $content->getText();
			$protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey( $password );
			$protected_key_encoded = $protected_key->saveToAsciiSafeString();
			$user_key = $protected_key->unlockKey( $password );
			$text = self::encryptSymmetric( $text, $user_key );
	
			$row['protected_key'] = $protected_key_encoded;
			$row['encrypted_content'] = $text;
			$row['expiration_date'] = null;
			
			$res = $dbr->insert( 'pageencryption_permissions', $row + [ 'updated_at' => $date, 'created_at' => $date ] );
		} else {
			unset( $row['access_type'] );
			$res = $dbr->update( 'pageencryption_permissions', $row, [ 'id' => $id ], __METHOD__ );
		}
		return $res;
	}
	/**
	 * @param string $protected_key
	 * @param string $password
	 * @param string &$message
	 * @return bool
	 */
	public static function setUserKey( $protected_key, $password, &$message ) {
		$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $protected_key );
		
		// @see https://github.com/defuse/php-encryption/blob/master/docs/classes/Crypto.md
		try {
			$user_key = $protected_key->unlockKey( $password );
			$user_key_encoded = $user_key->saveToAsciiSafeString();
		} catch ( Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex ) {
			$message = wfMessage( 'pageencryption-error-message-password-doesnotmatch' )->text();
			return false;
		}
		$res = self::setCookie( $user_key_encoded );
		if ( $res === false ) {
			$message = wfMessage( 'pageencryption-error-message-cannot-set-cookie' )->text();
		}
			
		return $res;
	}
	
	/**
	 * @param array $row
	 * @return bool
	 */
	public static function disableEncryptionKeyRecord( $row ) {
		return $dbr->update(
    		'pageencryption_keys',
    		[ 'enabled' => 0 ],
    		[ 'id' => $row['id'] ],
    		__METHOD__
    	);
	}
	/**
	 * @param string $user_id
	 * @param string $password
	 * @param string &$message
	 * @param string &$protected_key_encoded
	 * @return bool
	 */
	public static function setEncryptionKey( $user_id, $password, &$message, &$protected_key_encoded ) {
		$protected_key = KeyProtectedByPassword::createRandomPasswordProtectedKey( $password );
		$protected_key_encoded = $protected_key->saveToAsciiSafeString();
    
		$row = [
			'user_id' => $user_id,
			'protected_key' => $protected_key_encoded,
		];
		
		$date = date( 'Y-m-d H:i:s' );
		
		$dbr = wfGetDB( DB_MASTER );
		$res = $dbr->insert( 'pageencryption_keys', $row + [ 'updated_at' => $date, 'created_at' => $date ] );
		
		if ( !$res ) {
			$message = wfMessage( 'pageencryption-error-message-cannot-save-encryptionkey' )->text();
			return false;
		}
			
		$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString( $protected_key_encoded );
		$user_key = $protected_key->unlockKey( $password );
		$user_key_encoded = $user_key->saveToAsciiSafeString();
		$res = self::setCookie( $user_key_encoded );
		if ( $res === false ) {
			$message = wfMessage( 'pageencryption-error-message-cannot-set-cookie' )->text();
		}
		return $res;
	}
	/**
	 * @param Title $title
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
		$link = Html::rawElement(
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
	 * @param OutputPage $outputPage
	 * @param Title $title
	 * @param User $user
	 */
	public static function addJsConfigVars( $outputPage, $title, $user ) {
		// $wikiPage = \PageEncryption::getWikiPage( $title );
		// $revisionRecord = $wikiPage->getRevisionRecord();
		// if ( $revisionRecord && $user->getId() !== $revisionRecord->getUser()->getId() ) {
		// 	return;
		// }
		if ( $title->isKnown() && !self::isEditor( $title, $user ) ) {
			return;
		}
		$outputPage->addJsConfigVars( [
			// httpOnly cookies cannot be accessed client-side, so we
			// set a specific variable
			'pageencryption-user-is-editor' => true,
			'pageencryption-userkey-cookie-isSet' => \PageEncryption::getUserKey() !== false,
			'pageencryption-protected-key-isSet' => is_array( \PageEncryption::getEncryptionKeyRecord( $user->getId() ) ),
		] );
	}
	/**
	 * @param array $conds
	 * @return void
	 */
	public static function getEncryptionKeyRecord( $userId ) {
		$dbr = wfGetDB( DB_REPLICA );
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
		$dbw = wfGetDB( DB_PRIMARY );
		$dbw->delete(
			'pageencrption_keys',  $conds,
			__METHOD__
		);
	}
	
	/**
	 * @param array $conds
	 * @return void
	 */
	public static function deletePermissions( $conds ) {
		$dbw = wfGetDB( DB_PRIMARY );
		$dbw->delete(
			'pageencryption_permissions',  $conds,
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
			list( $type, $url ) = $val;
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
	 * @param Title $title
	 * @param User|null $user
	 * @return bool
	 */
	public static function isEditor( $title, $user = null ) {
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
	 * @param Title $title
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
 	 * @see https://stackoverflow.com/questions/6101956/generating-a-random-password-in-php
	 * @param int $length 
	 * @param string $keyspaceto select from
	 * @return string
	 */
	public static function random_str( $length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' ) {
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
