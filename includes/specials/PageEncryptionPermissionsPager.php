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

use MediaWiki\Linker\LinkRenderer;

class PageEncryptionPermissionsPager extends TablePager {

	/** @var title */
	private $title;

	/** @var request */
	private $request;

	/** @var parentClass */
	private $parentClass;

	/**
	 * @param SpecialPageEncryption $parentClass
	 * @param Request $request
	 * @param LinkRenderer $linkRenderer
	 */
	public function __construct( $parentClass, $request, LinkRenderer $linkRenderer ) {
		$this->title = $parentClass->title;
		$this->request = $request;
		$this->parentClass = $parentClass;

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
			];
		}

		$headers = array_merge( $headers, [
			'page_id' => 'pageencryption-managepermissions-pager-header-page',
			'revision' => 'pageencryption-managepermissions-pager-header-revision',
			'access_type' => 'pageencryption-managepermissions-pager-header-access_type',
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
				$user = User::newFromId( $row->created_by );
				$formatted = $user->getName();
				break;

			case 'page_id':
				$formatted = '';
				$title = Title::newFromID( $row->page_id );
				$linkRenderer = $this->getLinkRenderer();
				$formatted = $linkRenderer->makeLink( $title );
				break;

			case 'revision':
				$title = Title::newFromID( $row->page_id );
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
					$title = Title::newFromID( $row->page_id );
					$user_key = \PageEncryption::getUserKey();
					if ( $user_key ) {
						$password = \PageEncryption::decryptSymmetric( $row->encrypted_password, $user_key );

						$formatted = Html::rawElement(
							'span',
							[
								'data-password' => $password,
								'class' => 'pageencryption-managepermissions-pager-button-show-password'
							],
							$this->msg( 'pageencryption-managepermissions-pager-button-password-copytoclipboard' )->text()
						)
						. '&nbsp;' . Html::rawElement(
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
				}
				break;

			case 'expiration_date':
				$formatted = $row->expiration_date;
				break;

			case 'viewed':
				$formatted = $row->viewed;
				break;

			case 'actions':
				$link = '<span class="mw-ui-button mw-ui-progressive">'
					. $this->msg( 'pageencryption-managepermissions-pager-button-edit' )->text() . '</span>';
				$title = SpecialPage::getTitleFor( 'PageEncryptionPermissions', $this->title );
				$query = [ 'edit' => $row->id ];
				$formatted = Linker::link( $title, $link, [], $query );
				break;

			default:
				throw new MWException( "Unknown field '$field'" );
		}

		return $formatted;
	}

	/**
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
				$title = Title::newFromText( $page );
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
