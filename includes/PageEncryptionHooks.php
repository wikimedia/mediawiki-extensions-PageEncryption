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
 * @copyright Copyright ©2023-2024, https://wikisphere.org
 */

if ( is_readable( __DIR__ . '/../vendor/autoload.php' ) ) {
	include_once __DIR__ . '/../vendor/autoload.php';
}

use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;

class PageEncryptionHooks {

	/** @var int */
	public static $encryptedNamespace = 2246;

	/** @var string[] */
	public static $admins = [ 'sysop', 'bureaucrat', 'interface-admin' ];

	/**
	 * @param DatabaseUpdater|null $updater
	 * @return void
	 */
	public static function onLoadExtensionSchemaUpdates( DatabaseUpdater $updater = null ) {
		$base = __DIR__;
		$dbType = $updater->getDB()->getType();
		$tables = [
			'pageencryption_symmetric',
			'pageencryption_asymmetric',
			'pageencryption_keys',
		];
		foreach ( $tables as $value ) {
			if ( file_exists( "$base/../$dbType/$value.sql" ) ) {
				$updater->addExtensionUpdate(
					[
						'addTable',
						$value,
						"$base/../$dbType/$value.sql",
						true
					]
				);
			}
		}

		$updater->addExtensionField(
			'pageencryption_keys',
			'public_key',
			"$base/../$dbType/pageencryption_keys_public_key.sql"
		);

		$updater->addExtensionField(
			'pageencryption_keys',
			'encrypted_private_key',
			"$base/../$dbType/pageencryption_keys_encrypted_private_key.sql"
		);
	}

	/**
	 * @param MediaWikiServices $services
	 * @return void
	 */
	public static function onMediaWikiServices( $services ) {
		// ignore on maintenance scripts
		if ( defined( 'MW_ENTRY_POINT' ) && MW_ENTRY_POINT === 'cli' ) {
			return;
		}

		if ( !empty( $_REQUEST['action'] )
				&& ( $_REQUEST['action'] === 'submit' || $_REQUEST['action'] === 'visualeditoredit' ) ) {
			return;
		}

		$dbLoadBalancerFactory = $services->getDBLoadBalancerFactory();
		$blobStoreFactory = $services->getBlobStoreFactory();
		$slotRoleRegistry = $services->getSlotRoleRegistry();
		$nameTables = $services->getNameTableStoreFactory();
		$cache = $services->getMainWANObjectCache();
		$commentStore = $services->getCommentStore();
		$actorMigration = $services->getActorMigration();
		$logger = LoggerFactory::getInstance( 'RevisionStore' );
		$contentHandlerFactory = $services->getContentHandlerFactory();
		$hookContainer = $services->getHookContainer();

		$dbDomain = false;
		// MW 1.35
		if ( version_compare( MW_VERSION, '1.36', '<' ) ) {
			$pageEncryptionRevisionLookup = new PageEncryptionRevisionLookup(
				$dbLoadBalancerFactory->getMainLB( $dbDomain ),
				$blobStoreFactory->newSqlBlobStore( $dbDomain ),
				$cache, // Pass cache local to wiki; Leave cache sharing to RevisionStore.
				$commentStore,
				$nameTables->getContentModels( $dbDomain ),
				$nameTables->getSlotRoles( $dbDomain ),
				$slotRoleRegistry,
				$actorMigration,
				$contentHandlerFactory,
				$hookContainer,
				$dbDomain
			);

		// MW 1.36 and MW 1.37 have the same interface
		} elseif ( version_compare( MW_VERSION, '1.38', '<' ) ) {
			$actorStoreFactory = $services->getActorStoreFactory();
			$pageStoreFactory = $services->getPageStoreFactory();
			$titleFactory = $services->getTitleFactory();

			$pageEncryptionRevisionLookup = new PageEncryptionRevisionLookup(
				$dbLoadBalancerFactory->getMainLB( $dbDomain ),
				$blobStoreFactory->newSqlBlobStore( $dbDomain ),
				$cache, // Pass cache local to wiki; Leave cache sharing to RevisionStore.
				$commentStore,
				$nameTables->getContentModels( $dbDomain ),
				$nameTables->getSlotRoles( $dbDomain ),
				$slotRoleRegistry,
				$actorMigration,
				$actorStoreFactory->getActorStore( $dbDomain ),
				$contentHandlerFactory,
				$pageStoreFactory->getPageStore( $dbDomain ),
				$titleFactory,
				$hookContainer,
				$dbDomain
			);

		// MW 1.38, 1.39 and 1.40 have the same interface
		} elseif ( version_compare( MW_VERSION, '1.42', '<' ) ) {
			$localCache = $services->getLocalServerObjectCache();
			$actorStoreFactory = $services->getActorStoreFactory();
			$pageStoreFactory = $services->getPageStoreFactory();
			$titleFactory = $services->getTitleFactory();

			$pageEncryptionRevisionLookup = new PageEncryptionRevisionLookup(
				$dbLoadBalancerFactory->getMainLB( $dbDomain ),
				$blobStoreFactory->newSqlBlobStore( $dbDomain ),
				$cache, // Pass cache local to wiki; Leave cache sharing to RevisionStore.
				$localCache,
				$commentStore,
				$nameTables->getContentModels( $dbDomain ),
				$nameTables->getSlotRoles( $dbDomain ),
				$slotRoleRegistry,

				$actorMigration,
				$actorStoreFactory->getActorStore( $dbDomain ),
				$contentHandlerFactory,
				$pageStoreFactory->getPageStore( $dbDomain ),
				$titleFactory,
				$hookContainer,
				$dbDomain, // $wikiId = WikiAwareEntity::LOCAL
			);

		} else {
			$localCache = $services->getLocalServerObjectCache();
			$actorStoreFactory = $services->getActorStoreFactory();
			$pageStoreFactory = $services->getPageStoreFactory();
			$titleFactory = $services->getTitleFactory();

			$pageEncryptionRevisionLookup = new PageEncryptionRevisionLookup(
				$dbLoadBalancerFactory->getMainLB( $dbDomain ),
				$blobStoreFactory->newSqlBlobStore( $dbDomain ),
				$cache, // Pass cache local to wiki; Leave cache sharing to RevisionStore.
				$localCache,
				$commentStore,
				$nameTables->getContentModels( $dbDomain ),
				$nameTables->getSlotRoles( $dbDomain ),
				$slotRoleRegistry,
				$actorStoreFactory->getActorStore( $dbDomain ),
				$contentHandlerFactory,
				$pageStoreFactory->getPageStore( $dbDomain ),
				$titleFactory,
				$hookContainer,
				$dbDomain, // $wikiId = WikiAwareEntity::LOCAL
			);
		}

		$services->redefineService( 'RevisionLookup', static function () use( $pageEncryptionRevisionLookup ) {
			return $pageEncryptionRevisionLookup;
		} );

		$services->redefineService( 'RevisionStore', static function () use( $pageEncryptionRevisionLookup ) {
			return $pageEncryptionRevisionLookup;
		} );
	}

	/**
	 * @param Title $title
	 * @param User $user
	 * @param string $action
	 * @param array|string|MessageSpecifier &$result
	 * @return bool
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/getUserPermissionsErrors
	 */
	public static function onGetUserPermissionsErrors( $title, $user, $action, &$result ) {
		// if ( \PageEncryption::isAuthorized( $user ) ) {
		// 	return true;
		// }

		if ( !\PageEncryption::isEncryptedNamespace( $title ) ) {
			return true;
		}

		if ( $action !== 'edit' && $action !== 'create' ) {
			return true;
		}

		if ( !$title->isKnown() && $user->isAllowed( 'pageencryption-can-manage-encryption' ) ) {
			return true;
		}

		if ( \PageEncryption::isEditor( $title, $user ) ) {
			return true;
		}

		$result = [ 'badaccess-group0' ];
		return false;
	}

	/**
	 * @param EditPage $editpage
	 */
	public static function onAlternateEdit( EditPage $editpage ) {
	}

	/**
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/MultiContentSave
	 * @param RenderedRevision $renderedRevision
	 * @param UserIdentity $user
	 * @param CommentStoreComment $summary
	 * @param int $flags
	 * @param Status $hookStatus
	 * @return void
	 */
	public static function onMultiContentSave( MediaWiki\Revision\RenderedRevision $renderedRevision, MediaWiki\User\UserIdentity $user, CommentStoreComment $summary, $flags, Status $hookStatus ) {
		$revisionRecord = $renderedRevision->getRevision();
		$title = $revisionRecord->getPageAsLinkTarget();

		if ( !\PageEncryption::isEncryptedNamespace( $title ) ) {
			return;
		}

		// @see PageUpdated, the following will disable makeAutoSummary
		// or @TODO extend content handler and provide encrypted auto summary
		$summary->data = [ 'encrypted' => true ];
		// or ...
		// $summary->text = 'edit encrypted content';

		$content = $revisionRecord->getContent( MediaWiki\Revision\SlotRecord::MAIN );

		// @TODO should be instance of text
		$contentHandler = $content->getContentHandler();
		$modelId = $contentHandler->getModelID();

		$text = $content->getText();
		$user_key = \PageEncryption::getUserKey();

		if ( $user_key === false ) {
			throw new MWException( 'User-key not set' );
		}

		$encryptedText = \PageEncryption::encryptSymmetric( $text, $user_key );

		if ( $encryptedText === false ) {
			throw new MWException( 'Cannot encrypt' );
		}

		// $modelId = $slotRoleRegistry->getRoleHandler( $slotName )->getDefaultModel( $title );
		$slotContent = ContentHandler::makeContent( $encryptedText, $title, $modelId );

		$slots = $revisionRecord->getSlots();
		$slots->setContent( MediaWiki\Revision\SlotRecord::MAIN, $slotContent );
	}

	/**
	 * @param OutputPage $out
	 * @param ParserOutput $parserOutput
	 * @return void
	 */
	public static function onOutputPageParserOutput( OutputPage $out, ParserOutput $parserOutput ) {
		$title = $out->getTitle();

		if ( \PageEncryption::isEncryptedNamespace( $title ) ) {
			if ( method_exists( $out, 'disableClientCache' ) ) {
				// MW 1.38+
				$out->disableClientCache();
			} else {
				$out->enableClientCache( false );
			}

			$parserOutput->addWrapperDivClass( 'pageencryption-encryption-namespace' );
		}
	}

	/**
	 * @param Content $content
	 * @param Title $title
	 * @param int $revId
	 * @param ParserOptions $options
	 * @param bool $generateHtml
	 * @param ParserOutput &$parserOutput
	 * @return void
	 */
	public static function onContentGetParserOutput( $content, $title, $revId, $options, $generateHtml, &$parserOutput ) {
		if ( \PageEncryption::isEncryptedNamespace( $title ) ) {
			// @see https://matrix.to/#/!NGZmJSwAAwbGRxhWwH:matrix.org/$_tv5PXROs5-J91qHYxA6dZT5mie5Tjx9-idKT_HCrzY?via=matrix.org&via=matrix.jembawan.com&via=gemeinsam.jetzt
			$parserOutput->updateCacheExpiry( 0 );
		}
	}

	/**
	 * @param ParserCache $parserCache
	 * @param ParserOutput $parserOutput
	 * @param Title $title
	 * @param ParserOptions $parserOptions
	 * @param int $revId
	 * @return void
	 */
	public static function onParserCacheSaveComplete( $parserCache, $parserOutput, $title, $parserOptions, $revId ) {
		// *** for debug purpose
		if ( \PageEncryption::isEncryptedNamespace( $title ) ) {
			// echo 'onParserCacheSaveComplete';
		}
	}

	/**
	 * *** ignore the cache if a page contains a transcluded page with stored permissions
	 * *** only for cache related to registered users
	 * @param ParserOutput $parserOutput
	 * @param WikiPage $wikiPage
	 * @param ParserOptions $parserOptions
	 * @return void
	 */
	public static function onRejectParserCacheValue( $parserOutput, $wikiPage, $parserOptions ) {
		$title = $wikiPage->getTitle();

		if ( \PageEncryption::isEncryptedNamespace( $title ) ) {
			return false;
		}
	}

	/**
	 * Initialise the 'VisualEditorAvailableNamespaces' setting
	 */
	public static function onRegistration() {
		$GLOBALS['wgVisualEditorAvailableNamespaces'][self::$encryptedNamespace] = true;
	}

	/**
	 * @param User &$user User after logout (won't have name, ID, etc.)
	 * @param string &$inject_html Any HTML to inject after the logout message.
	 * @param string $oldName The text of the username that just logged out.
	 */
	public static function onUserLogoutComplete( &$user, &$inject_html, $oldName ) {
		\PageEncryption::deleteCookie();
	}

	/**
	 * @param Title &$title
	 * @param null $unused
	 * @param OutputPage $output
	 * @param User $user
	 * @param WebRequest $request
	 * @param MediaWiki|MediaWiki\Actions\ActionEntryPoint $mediaWiki
	 * @return void
	 */
	public static function onBeforeInitialize( \Title &$title, $unused, \OutputPage $output, \User $user, \WebRequest $request, $mediaWiki ) {
		\PageEncryption::initialize( $user );
	}

	/**
	 * @param string &$siteNotice
	 * @param Skin $skin
	 * @return bool
	 */
	public static function onSiteNoticeBefore( &$siteNotice, $skin ) {
		$user = $skin->getUser();
		$userGroupManager = \PageEncryption::getUserGroupManager();
		$userGroups = \PageEncryption::getUserGroups( $userGroupManager, $user, true );

		if ( count( array_intersect( self::$admins, $userGroups ) ) ) {
			$dbr = \PageEncryption::getDB( DB_REPLICA );

			if ( !$dbr->tableExists( 'pageencryption_keys' ) ) {
				$siteNotice = '<div class="pageencryption-sitenotice">' . wfMessage( 'pageencryption-sitenotice-missing-table' )->plain() . '</div>';
				return false;
			}
		}

		// @todo move below the title
		if ( \PageEncryption::$decryptionNotice === \PageEncryption::DecryptionFromAccessCode ) {
			$siteNotice = '<div class="pageencryption-notice">' . wfMessage( 'pageencryption-sitenotice-decryption-from-access-code' )->plain() . '</div>';
			return false;
		}

		return true;
	}

	/**
	 * @param OutputPage $outputPage
	 * @param string &$text
	 * @return void
	 */
	public static function onOutputPageBeforeHTML( OutputPage $outputPage, &$text ) {
		$title = $outputPage->getTitle();
		if ( !\PageEncryption::isEncryptedNamespace( $title ) ) {
			return;
		}

		switch ( \PageEncryption::$decryptionNotice ) {
			case \PageEncryption::EncryptedPage:
				$text = '<div class="pageencryption-notice">' . wfMessage( 'pageencryption-sitenotice-encrypted-page' )->plain() . '</div>';
				break;

			case \PageEncryption::DecryptionFailed:
				$text = '<div class="pageencryption-notice">' . wfMessage( 'pageencryption-sitenotice-decryption-failed' )->plain() . '</div>';
				break;

		}
	}

	/**
	 * @param OutputPage $outputPage
	 * @param Skin $skin
	 * @return void
	 */
	public static function onBeforePageDisplay( OutputPage $outputPage, Skin $skin ) {
		global $wgResourceBasePath;

		$user = $skin->getUser();
		$title = $outputPage->getTitle();

		if ( $user->isAllowed( 'pageencryption-can-manage-encryption' )
			|| $user->isAllowed( 'pageencryption-can-handle-encryption' ) ) {
			$outputPage->addModules( [ 'ext.PageEncryptionPassword' ] );
			\PageEncryption::addJsConfigVars( $outputPage, $title, $user );
		}

		if ( !\PageEncryption::isEncryptedNamespace( $title ) ) {
			return;
		}

		\PageEncryption::addHeaditem( $outputPage, [
			[ 'stylesheet', $wgResourceBasePath . '/extensions/PageEncryption/resources/style.css' ],
		] );

		if ( $title->isKnown() ) {
			\PageEncryption::addIndicator( $outputPage );
		}
	}

	/**
	 * @param SkinTemplate $skinTemplate
	 * @param array &$links
	 * @return void
	 */
	public static function onSkinTemplateNavigation( SkinTemplate $skinTemplate, array &$links ) {
		$user = $skinTemplate->getUser();

		if ( !$user || !$user->isRegistered() ) {
			return;
		}

		$title = $skinTemplate->getTitle();

		if ( !$title->isKnown() || $title->isSpecialPage() ) {
			return;
		}

		if ( !\PageEncryption::isEncryptedNamespace( $title ) ) {
			return;
		}

		if ( !\PageEncryption::isEditor( $title, $user )
			|| !$user->isAllowed( 'pageencryption-can-manage-encryption' ) ) {
			return;
		}

		$url = SpecialPage::getTitleFor( 'PageEncryptionPermissions', $title )->getLocalURL();
		$links[ 'actions' ][] = [ 'text' => wfMessage( 'pageencryption-navigation' )->text(), 'href' => $url ];
	}

	/**
	 * *** Register any render callbacks with the parser
	 * @param Parser $parser
	 * @return bool|void
	 */
	public static function onParserFirstCallInit( Parser $parser ) {
		// $parser->setFunctionHook( 'pageencryption_userpages', [ \PageEncryption::class, 'pageencryption_userpages' ] );
	}

	/**
	 * @param Skin $skin
	 * @param array &$bar
	 * @return bool|void
	 */
	public static function onSkinBuildSidebar( $skin, &$bar ) {
		$user = $skin->getUser();

		if ( !$user || !$user->isRegistered() ) {
			return;
		}
	}
}
