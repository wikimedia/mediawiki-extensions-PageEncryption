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

require_once __DIR__ . '/PageEncryptionPermissionsPager.php';

/**
 * A special page that lists protected pages
 *
 * @ingroup SpecialPage
 */
class SpecialPageEncryptionPermissions extends SpecialPage {

	/** @var title */
	public $title;

	/** @var localTitle */
	public $localTitle;

	/** @var isAuthorized */
	public $isAuthorized;

	/** @var user */
	private $user;

	/** @var request */
	private $request;

	/** @var latest_id */
	private $latest_id;

	/**
	 * @inheritDoc
	 */
	public function __construct() {
		$listed = true;
		parent::__construct( 'PageEncryptionPermissions', '', $listed );
	}

	/**
	 * @inheritDoc
	 */
	public function execute( $par ) {
		$this->requireLogin();

		$this->setHeaders();
		$this->outputHeader();

		$title = Title::newFromText( $par );

		// !$title->isContentPage()
		if ( $title && ( !$title->isKnown() || $title->isSpecialPage() ) ) {
			$title = null;
		}

		$user = $this->getUser();

		$this->isAuthorized = \PageEncryption::isAuthorized( $user );

		if ( !$user->isAllowed( 'pageencryption-cancreateencryption' ) ) {
			$this->displayRestrictionError();
			return;
		}

		$this->localTitle = SpecialPage::getTitleFor( 'PageEncryptionPermissions', $title );

		$this->title = $title;

		$out = $this->getOutput();

		$out->addModuleStyles( 'mediawiki.special' );

		$out->addModules( [ 'ext.PageEncryptionPermissions' ] );

		$out->setPageTitle( $this->msg( "pageencryptionpermissions" )->text() . ( $title ? ' (' . $title->getFullText() . ')' : '' ) );

		$this->addHelpLink( 'Extension:PageEncryption' );

		$request = $this->getRequest();

		$this->request = $request;

		$this->user = $user;

		$id = $request->getVal( 'edit' );

		if ( $id ) {
			$this->editPermission( $request, $out );
			return;
		}

		if ( $title ) {
			$out->addWikiMsg(
				'pageencryption-managepermissions-return',
				$title->getFullText(),
				$title->getFullText()
			);
		}

		$pager = new PageEncryptionPermissionsPager(
			$this,
			$request,
			$this->getLinkRenderer()
		);

		$out->enableOOUI();

		// $out->addWikiMsg( 'pageencryption-managepermissions-description-' . ( $this->title ? 'specific' : 'generic' ),
		// 	!$this->title || !$user->isAllowed( 'pageencryption-canmanagepermissions' ) ? '' : $this->msg( 'pageencryption-managepermissions-description-manage-all-permissions' )->text() );

		$out->addWikiMsg( 'pageencryption-managepermissions-form-preamble' );

		$out->addHTML( '<br />' );

		$layout = new OOUI\PanelLayout( [ 'id' => 'pageencryption-panel-layout', 'expanded' => false, 'padded' => false, 'framed' => false ] );

		$layout->appendContent(
			new OOUI\FieldsetLayout(
				[
					'label' => $this->msg( 'pageencryption-managepermissions-form-button-addpermission-legend' )->text(), 'items' => [
						new OOUI\ButtonWidget(
							[
								'href' => wfAppendQuery( $this->localTitle->getLocalURL(), 'edit=new' ),
								'label' => $this->msg( 'pageencryption-managepermissions-form-button-addpermission' )->text(),
								'infusable' => true,
								'flags' => [ 'progressive', 'primary' ],
							]
						)
					],
				]
			)
		);

		$out->addHTML( $layout );

		$out->addHTML( '<br />' );

		if ( empty( $par ) ) {
			$out->addHTML( $this->showOptions( $request ) );
			$out->addHTML( '<br />' );
		}

		if ( $pager->getNumRows() ) {
			$out->addParserOutputContent( $pager->getFullOutput() );

		} else {
			$out->addWikiMsg( 'pageencryption-managepermissions-table-empty' );
		}
	}

	/**
	 * @inheritDoc
	 */
	public function doesWrites() {
		return true;
	}

	/**
	 * @inheritDoc
	 */
	protected function editPermission( $request, $out ) {
		$id = $request->getVal( 'edit' );
		$action = $request->getVal( 'action' );
		$new = ( $id && $id === 'new' );

		$dbr = \PageEncryption::wfGetDB( DB_MASTER );

		if ( !empty( $action ) ) {

			switch ( $action ) {
				case 'delete':
					\PageEncryption::deletePermissions( [ 'id' => $id ] );
					header( 'Location: ' . $this->localTitle->getLocalURL() );
					return;

				case 'cancel':
					header( 'Location: ' . $this->localTitle->getLocalURL() );
					return;
			}
		}

		$row = [];

		if ( !$new ) {
			$dbr = \PageEncryption::wfGetDB( DB_REPLICA );
			$row = $dbr->selectRow( 'pageencryption_permissions', '*', [ 'id' => $id ], __METHOD__ );
		}

		if ( !$row ) {
			if ( !$new ) {
				$out->addWikiMsg( 'pageencryption-managepermissions-form-missing-item' );
				$out->addHTML( '<br />' );
				return;
			}

			$row = [
				'created_by' => null,
				'page_id' => null,
				'access_type' => null,
				'add_permissions' => null,
				'protected_key' => null,
				'encrypted_content' => null,
				'expiration_date' => null,
				'viewed' => null,
			];

		} else {
			$row = (array)$row;
		}

		$formDescriptor = $this->getFormDescriptor( $row, $out );

		$messagePrefix = 'pageencryption-managepermissions';
		$htmlForm = new OOUIHTMLForm( $formDescriptor, $this->getContext(), $messagePrefix );

		$htmlForm->setId( 'pageencryption-form-permissions' );

		$htmlForm->setMethod( 'post' );

		$htmlForm->setSubmitCallback( [ $this, 'onSubmit' ] );

		$htmlForm->showCancel();

		$htmlForm->setCancelTarget( $this->localTitle->getLocalURL() );

		$htmlForm->setSubmitTextMsg( 'pageencryption-managepermissions-form-button-submit' );

		$out->addWikiMsg(
			'pageencryption-managepermissions-form-returnlink',
			$this->localTitle->getFullText()
		);

		$out->addWikiMsg( 'pageencryption-managepermissions-form-preamble' );

		$htmlForm->prepareForm();

		$result = $htmlForm->tryAuthorizedSubmit();

		$htmlForm->setAction(
			wfAppendQuery( $this->localTitle->getLocalURL(),
				'edit=' . ( !empty( $this->latest_id ) ? $this->latest_id : $id ) )
		);

		if ( !$new || $this->latest_id ) {
			$htmlForm->addButton(
				[
				'type' => 'button',
				'name' => 'action',
				'value' => 'delete',
				'href' => $this->localTitle->getLocalURL(),
				'label-message' => 'pageencryption-managepermissions-form-button-delete',
				'flags' => [ 'destructive' ]
				]
			);
		}

		$htmlForm->displayForm( $result );
	}

	/**
	 * @param array $row
	 * @param Output $out
	 * @return array
	 */
	protected function getFormDescriptor( $row, $out ) {
		$formDescriptor = [];

		$section_prefix = '';

		$options = [
			$this->msg( "pageencryption-managepermissions-form-access_type-options-symmetric_key" )->text() => 'symmetric_key',
			$this->msg( "pageencryption-managepermissions-form-access_type-options-asymmetric_key" )->text() => 'asymmetric_key',
		];

/*
		$formDescriptor['access_type'] = [
			'label-message' => 'pageencryption-managepermissions-form-scope-label',
			'type' => 'select',
			'name' => 'access_type',
			'required' => true,
			'disabled' => true,
			'section' => $section_prefix . 'form-fieldset-permissions-main',
			'help-message' => 'pageencryption-managepermissions-form-scope-help',
			'default' => $row['access_type'],
			'options' => $options,
		];
*/

		$expiration_date = explode( ' ', (string)$row['expiration_date'] );

		$formDescriptor['expiration_date'] = [
			'label-message' => 'pageencryption-managepermissions-form-expiration_date-label',
			'type' => 'date',
			'min' => date( 'Y-m-d' ),
			'name' => 'expiration_date',
			'required' => false,
			'section' => $section_prefix . 'form-fieldset-permissions-main',
			'help-message' => 'pageencryption-managepermissions-form-expiration_date-help',
			'default' => $expiration_date[0]
		];

/*
$this->username = '';

		$formDescriptor['username'] = [
			'label-message' => 'pageencryption-managepermissions-form-usernames-label',
			'type' => 'user',
			'name' => 'username',
			'required' => true,
			'section' => $section_prefix . 'form-fieldset-permissions-main',
			'help-message' => 'pageencryption-managepermissions-form-usernames-help',
			'default' => $row['username'],
			// 'options' => array_flip( $this->usernames ),
		];
*/

		return $formDescriptor;
	}

	/**
	 * @param array $data
	 * @param HTMLForm $htmlForm
	 * @return bool
	 */
	public function onSubmit( $data, $htmlForm ) {
		$request = $this->getRequest();

		$id = $request->getVal( 'edit' );

		$new = ( $id && $id === 'new' );

		$row = [
			'access_type' => $data['access_type'],
			'expiration_date' => $data['expiration_date']
		];

		\PageEncryption::setPermissions( $this->user, $this->title, $row, ( !$new ? $id : null ) );

		if ( $new ) {
			$dbr = \PageEncryption::wfGetDB( DB_MASTER );

			$this->latest_id = $dbr->selectField(
				'pageencryption_permissions',
				'id',
				[],
				__METHOD__,
				[ 'ORDER BY' => 'id DESC' ]
			);
		}

		header( 'Location: ' . $this->localTitle->getLocalURL() );

		// return true;
	}

	public function onSuccess() {
	}

	/**
	 * @param Request $request
	 * @return string
	 */
	protected function showOptions( $request ) {
		$formDescriptor = [];

		if ( $this->isAuthorized ) {
			$created_by = $request->getVal( 'created_by' );

			$formDescriptor['created_by'] = [
				'label-message' => 'pageencryption-managepermissions-form-search-created_by-label',
				'type' => 'user',
				'name' => 'created_by',
				'required' => false,
				'help-message' => 'pageencryption-managepermissions-form-search-created_by-help',
				'default' => ( !empty( $created_by ) ? $created_by : null ),
			];
		}

		// @TODO, add other fields ...

		$page = $request->getVal( 'page' );

		$formDescriptor['page'] = [
			'label-message' => 'pageencryption-managepermissions-form-search-page-label',
			'type' => 'title',
			'name' => 'page',
			'required' => false,
			'default' => ( !empty( $page ) ? $page : null ),
		];

		$htmlForm = HTMLForm::factory( 'ooui', $formDescriptor, $this->getContext() );

		$htmlForm
			->setMethod( 'get' )
			->setWrapperLegendMsg( 'pageencryption-managepermissions-form-search-legend' )
			->setSubmitText( $this->msg( 'pageencryption-managepermissions-form-search-submit' )->text() );

		return $htmlForm->prepareForm()->getHTML( false );
	}

	/**
	 * @return string
	 */
	protected function getGroupName() {
		return 'pageencryption';
	}
}
