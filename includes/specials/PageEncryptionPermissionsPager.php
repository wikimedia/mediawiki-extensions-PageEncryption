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

use MediaWiki\Extension\PageEncryption\Aliases\Html as HtmlClass;
use MediaWiki\Extension\PageEncryption\Aliases\Linker as LinkerClass;
use MediaWiki\Extension\PageEncryption\Aliases\Title as TitleClass;
use MediaWiki\Linker\LinkRenderer;
use MediaWiki\MediaWikiServices;

class PageEncryptionPermissionsPager extends TablePager {

	/** @var Title|MediaWiki\Title\Title */
	private $title;

	/** @var request */
	private $request;

	/** @var parentClass */
	private $parentClass;

	/** @var MediaWiki\User\UserFactory */
	private $userFactory;

	/**
	 * @param SpecialPageEncryption $parentClass
	 * @param Request $request
	 * @param LinkRenderer $linkRenderer
	 */
	public function __construct( $parentClass, $request, LinkRenderer $linkRenderer ) {
		$this->title = $parentClass->title;
		$this->request = $request;
		$this->parentClass = $parentClass;
		$this->userFactory = MediaWikiServices::getInstance()->getUserFactory();

		parent::__construct( $parentClass->getContext(), $linkRenderer );
	}

	/**
	 * @param IResultWrapper $result
	 */
	public function preprocessResults( $result ) {
	}

	/**
	 * @return array
	 */
	protected function getFieldNames() {
		// @TODO, this is called several times
		// by TablePager, so it could be cached
		$headers = [];

		if ( !$this->title && $this->parentClass->isAuthorized ) {
			$headers = [
				'created_by' => 'pageencryption-managepermissions-pager-header-created_by',
				'page_id' => 'pageencryption-managepermissions-pager-header-page',
			];
		}

		$headers = array_merge( $headers, [
		'revision' => 'pageencryption-managepermissions-pager-header-revision',
			'access_type' => 'pageencryption-managepermissions-pager-header-access_type',
			'recipient_id' => 'pageencryption-managepermissions-pager-header-recipient',
			'password' => 'pageencryption-managepermissions-pager-header-password',
			'expiration_date' => 'pageencryption-managepermissions-pager-header-expiration_date',
			'viewed' => 'pageencryption-managepermissions-pager-header-viewed',
		] );

		$headers = array_merge( $headers, [
			'actions' => 'pageencryption-managepermissions-pager-header-actions',
		] );

		foreach ( $headers as $key => $val ) {
			$headers[$key] = $this->msg( $val )->text();
		}

		return $headers;
	}

	/**
	 * @param string $field
	 * @param string $value
	 * @return string HTML
	 * @throws MWException
	 */
	public function formatValue( $field, $value ) {
		/** @var object $row */
		$row = $this->mCurrentRow;
		$linkRenderer = $this->getLinkRenderer();

		$formatted = '';
		switch ( $field ) {
			case 'created_by':
				$user = $this->userFactory->newFromId( $row->created_by );
				$formatted = $user->getName();
				break;

			case 'recipient_id':
				if ( $row->access_type === 'asymmetric' ) {
					$user = $this->userFactory->newFromId( $row->recipient_id );
					$formatted = $user->getName();
				} else {
					$formatted = 'n/a';
				}
				break;

			case 'page_id':
				$formatted = '';
				$title = TitleClass::newFromID( $row->page_id );
				$linkRenderer = $this->getLinkRenderer();
				$formatted = $linkRenderer->makeLink( $title );
				break;

			case 'revision':
				$title = TitleClass::newFromID( $row->page_id );
				$wikiPage = \PageEncryption::getWikiPage( $title );
				$revisionRecord = $wikiPage->getRevisionRecord();

				// @see HistoryPager
				$formatted = ChangesList::revDateLink( $revisionRecord, $this->parentClass->getUser(), $this->parentClass->getLanguage(),
					$this->title );
				break;

			case 'access_type':
				$formatted = $row->access_type;
				break;

			case 'password':
				if ( (int)$row->created_by === $this->parentClass->getUser()->getId() ) {
					$title = TitleClass::newFromID( $row->page_id );

					if ( $row->access_type === 'symmetric' ) {
						$errorMessage = null;
						$user_key = \PageEncryption::getUserKey( $errorMessage );
						if ( $user_key ) {
							$password = \PageEncryption::decryptSymmetric( $row->encrypted_password, $user_key );

							$formatted =
								// HtmlClass::rawElement(
								// 'span',
								// [
								// 	'data-password' => $password,
								// 	'class' => 'pageencryption-managepermissions-pager-button-show-password'
								// ],
								// $this->msg( 'pageencryption-managepermissions-pager-button-password-copytoclipboard' )->text()
							// ) .
							// . '&nbsp;' .
							 HtmlClass::rawElement(
								'span',
								[
									'data-url' => wfAppendQuery( $title->getFullURL(), 'acode=' . $password ),
									'class' => 'pageencryption-managepermissions-pager-button-show-url'
								],
								$this->msg( 'pageencryption-managepermissions-pager-button-url-copytoclipboard' )->text()
							);
						} else {
							$formatted = 'user-key not set';
						}
					} else {
						$formatted = HtmlClass::rawElement(
							'span',
							[
								'data-url' => $title->getFullURL(),
								'class' => 'pageencryption-managepermissions-pager-button-show-url'
							],
							$this->msg( 'pageencryption-managepermissions-pager-button-url-copytoclipboard' )->text()
						);
					}
				}
				break;

			case 'expiration_date':
				$date = ( (array)$row )[$field];
				if ( $date ) {
					$formatted = htmlspecialchars(
						$this->getLanguage()->userDate(
							wfTimestamp( TS_MW, $date ),
							$this->getUser()
						)
					);
				}
				break;

			case 'viewed':
				$date = ( (array)$row )[$field];
				if ( $date ) {
					$formatted = htmlspecialchars(
						$this->getLanguage()->userTimeAndDate(
							wfTimestamp( TS_RFC2822, $date ),
							$this->getUser()
						)
					);
				}
				break;

			case 'actions':
				$link = '<span class="mw-ui-button mw-ui-progressive">'
					. $this->msg( 'pageencryption-managepermissions-pager-button-edit' )->text() . '</span>';
				$title = SpecialPage::getTitleFor( 'PageEncryptionPermissions', $this->title );
				$query = [ 'edit' => $row->id, 'type' => $row->access_type ];
				$formatted = LinkerClass::link( $title, $link, [], $query );
				break;

			default:
				throw new MWException( "Unknown field '$field'" );
		}

		return $formatted;
	}

	/**
	 * @inheritDoc
	 */
	public function reallyDoQuery( $offset, $limit, $order ) {
		$fname = static::class . '::reallyDoQuery';
		// $dbr = $this->getRecacheDB();
		$dbr = \PageEncryption::getDB( DB_REPLICA );

		// @TODO use https://www.mediawiki.org/wiki/Manual:Database_access#UnionQueryBuilder
		// MW >= 1.41
		$table1 = $dbr->tableName( 'pageencryption_symmetric' );
		$table2 = $dbr->tableName( 'pageencryption_asymmetric' );

		$where = [];
		$pageId = null;
		if ( $this->title ) {
			$pageId = $this->title->getArticleID();

		} else {
			$page = $this->request->getVal( 'page' );

			if ( is_int( $page ) ) {
				$title_ = TitleClass::newFromText( $page );
				$pageId = $title_->getArticleId();
			}

			if ( !$this->parentClass->isAuthorized ) {
				$created_by = $this->parentClass->getUser()->getId();

			} else {
				$created_by_ = $this->request->getVal( 'created_by' );

				if ( !empty( $created_by_ ) ) {
					$user_ = $this->userFactory->newFromName( $created_by_ );
					$created_by = $user_->getId();
				}
			}
		}

		if ( $pageId !== null ) {
			$where[] = "page_id = $pageId";
		}

		if ( !empty( $created_by ) ) {
			$where[] = "created_by = $created_by";
		}

		$where = implode( ' AND ', $where );
		if ( $where ) {
			$where = "WHERE $where";
		}

		$query = "SELECT * FROM (
SELECT id, created_by, page_id, revision_id, null as recipient_id, encrypted_password, expiration_date, viewed, viewed_metadata, updated_at, created_at, 'symmetric' AS access_type FROM $table1 $where
UNION
SELECT id, created_by, page_id, revision_id, recipient_id, null as encrypted_password, expiration_date, viewed, viewed_metadata, updated_at, created_at, 'asymmetric' AS access_type FROM $table2 $where
) AS t ORDER BY t.created_at";

		$sql = $dbr->limitResult( $query, $limit, $offset );

		// phpcs:ignore MediaWiki.Usage.DbrQueryUsage.DbrQueryFound
		$res = $dbr->query( $sql, $fname );

		// return new Wikimedia\Rdbms\FakeResultWrapper( $ret );
		return $res;
	}

	/**
	 * *** currently unused
	 * @return array
	 */
	public function getQueryInfo() {
		$ret = [];

		$tables = [ 'pageencryption_permissions' ];
		$fields = [ '*' ];
		$join_conds = [];
		$conds = [];
		$options = [];

		$created_by = $this->request->getVal( 'created_by' );

		if ( !empty( $created_by ) ) {
			$conds[ 'created_by' ] = $created_by;
		}

		$page = $this->request->getVal( 'page' );

		if ( $this->title ) {
			$conds['page_id'] = $this->title->getArticleID();

		} else {
			if ( !$this->parentClass->isAuthorized ) {
				$conds['created_by'] = $this->parentClass->getUser()->getId();
			}

			if ( !empty( $page ) ) {
				$title = TitleClass::newFromText( $page );
				$conds[ 'page_id' ] = $title->getArticleId();
			}
		}

		array_unique( $tables );

		$ret['tables'] = $tables;
		$ret['fields'] = $fields;
		$ret['join_conds'] = $join_conds;
		$ret['conds'] = $conds;
		$ret['options'] = $options;

		return $ret;
	}

	/**
	 * @return string
	 */
	protected function getTableClass() {
		return parent::getTableClass() . ' pageencryption-managepermissions-pager-table';
	}

	/**
	 * @return string
	 */
	public function getIndexField() {
		return 'created_at';
	}

	/**
	 * @return string
	 */
	public function getDefaultSort() {
		return 'created_at';
	}

	/**
	 * @param string $field
	 * @return bool
	 */
	protected function isFieldSortable( $field ) {
		// no index for sorting exists
		return false;
	}
}
