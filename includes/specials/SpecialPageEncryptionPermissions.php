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

require_once __DIR__ . '/PageEncryptionPermissionsPager.php';

use MediaWiki\MediaWikiServices;
use MediaWiki\Title\Title;

/**
 * A special page that lists protected pages
 *
 * @ingroup SpecialPage
 */
class SpecialPageEncryptionPermissions extends SpecialPage {

	/** @var Title */
	public $title;

	/** @var Title */
	public $localTitle;

	/** @var bool */
	public $isAuthorized;

	/** @var User */
	private $user;

	/** @var Request */
	private $request;

	/** @var int */
	private $latest_id;

	/** @var bool */
	private $missingPublicKey;

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

		if ( !$user->isAllowed( 'pageencryption-can-manage-encryption' ) ) {
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

		$out->addWikiMsg( 'pageencryption-managepermissions-form-preamble' . ( !$par ? '-site' : '' ) );

		$out->addHTML( '<br />' );
		$layout = new OOUI\PanelLayout( [ 'id' => 'pageencryption-panel-layout', 'expanded' => false, 'padded' => false, 'framed' => false ] );

		$layout->appendContent(
			new OOUI\FieldsetLayout(
				[
					'label' => $this->msg( 'pageencryption-managepermissions-form-button-addpermission-legend' )->text(), 'items' => [
						new OOUI\ButtonWidget(
							[
								'href' => wfAppendQuery( $this->localTitle->getLocalURL(), 'edit=new&type=symmetric' ),
								'label' => $this->msg( 'pageencryption-managepermissions-form-button-addpermission' )->text(),
								'infusable' => true,
								'flags' => [ 'progressive', 'primary' ],
							]
						),
						new OOUI\ButtonWidget(
							[
								'href' => wfAppendQuery( $this->localTitle->getLocalURL(), 'edit=new&type=asymmetric' ),
								'label' => $this->msg( 'pageencryption-managepermissions-form-button-addpermission-asymmetric' )->text(),
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
		$type = $request->getVal( 'type' );
		$new = ( $id && $id === 'new' );

		$dbr = \PageEncryption::getDB( DB_PRIMARY );

		if ( !empty( $action ) ) {

			switch ( $action ) {
				case 'delete':
					\PageEncryption::deletePermissions( $type, [ 'id' => $id ] );
					header( 'Location: ' . $this->localTitle->getLocalURL() );
					return;

				case 'cancel':
					header( 'Location: ' . $this->localTitle->getLocalURL() );
					return;
			}
		}

		$row = [];
		if ( !$new ) {
			$dbr = \PageEncryption::getDB( DB_REPLICA );
			$row = $dbr->selectRow( "pageencryption_$type", '*', [ 'id' => $id ], __METHOD__ );
		}

		if ( !$row ) {
			if ( !$new ) {
				$out->addWikiMsg( 'pageencryption-managepermissions-form-missing-item' );
				$out->addHTML( '<br />' );
				return;
			}

			$row = [
				'expiration_date' => null,
				'recipient_id' => null
			];

		} else {
			$row = (array)$row;
		}

		$type = $request->getVal( 'type' );
		$formDescriptor = $type === 'symmetric' ?
			$this->formDescriptorSymmetric( $row, $out )
			: $this->formDescriptorPublicKey( $row, $out );

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

		$htmlForm->prepareForm();

		$result = $htmlForm->tryAuthorizedSubmit();

		$htmlForm->setAction(
			wfAppendQuery( $this->localTitle->getLocalURL(),
				'type=' . $type
				. '&edit=' . ( !empty( $this->latest_id ) ? $this->latest_id : $id )
			)
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
	protected function formDescriptorSymmetric( $row, $out ) {
		$formDescriptor = [];
		$section_prefix = '';

/*
		$options = [
			$this->msg( "pageencryption-managepermissions-form-access_type-options-symmetric_key" )->text() => 'symmetric_key',
			$this->msg( "pageencryption-managepermissions-form-access_type-options-asymmetric_key" )->text() => 'asymmetric_key',
		];

		$formDescriptor['access_type'] = [
			'label-message' => 'pageencryption-managepermissions-form-scope-label',
			'type' => 'select',
			'name' => 'access_type',
			'required' => true,
			'disabled' => true,
			'section' => $section_prefix . 'form-fieldset-permissions-main-symmetric',
			'help-message' => 'pageencryption-managepermissions-form-scope-help',
			'default' => $row['access_type'],
			'options' => $options,
		];
*/

		if ( !$this->title ) {
			$formDescriptor['page'] = [
				'label-message' => 'pageencryption-managepermissions-form-page-label',
				'type' => 'title',
				'name' => 'page',
				'exists' => true,
				'namespace' => NS_PAGEENCRYPTION,
				'required' => true,
				'section' => $section_prefix . 'form-fieldset-permissions-main-symmetric',
				'help-message' => 'pageencryption-managepermissions-form-page-help'
			];
		}

		$expiration_date = explode( ' ', (string)$row['expiration_date'] );

		$formDescriptor['expiration_date'] = [
			'label-message' => 'pageencryption-managepermissions-form-expiration_date-label',
			'type' => 'date',
			'min' => date( 'Y-m-d' ),
			'name' => 'expiration_date',
			'required' => false,
			'section' => $section_prefix . 'form-fieldset-permissions-main-symmetric',
			'help-message' => 'pageencryption-managepermissions-form-expiration_date-help',
			'default' => $expiration_date[0]
		];

		return $formDescriptor;
	}

	/**
	 * @param array $row
	 * @param Output $out
	 * @return array
	 */
	protected function formDescriptorPublicKey( $row, $out ) {
		$formDescriptor = [];
		$section_prefix = '';

		if ( !$this->title ) {
			$formDescriptor['page'] = [
				'label-message' => 'pageencryption-managepermissions-form-page-label',
				'type' => 'title',
				'name' => 'page',
				'namespace' => NS_PAGEENCRYPTION,
				'required' => true,
				'section' => $section_prefix . 'form-fieldset-permissions-main-public-key',
				'help-message' => 'pageencryption-managepermissions-form-page-help'
			];
		}

		if ( !empty( $row['recipient_id'] ) ) {
			$user_ = MediaWikiServices::getInstance()->getUserFactory()->newFromId( $row['recipient_id'] );
			$username = $user_->getName();
		} else {
			$username = null;
		}

		$formDescriptor['username'] = [
			'label-message' => 'pageencryption-managepermissions-form-user-label',
			'type' => 'user',
			'name' => 'username',
			'required' => true,
			'section' => $section_prefix . 'form-fieldset-permissions-main-public-key',
			'help-message' => 'pageencryption-managepermissions-form-user-help',
			'validation-callback' => function () {
				if ( $this->missingPublicKey ) {
					// @see includes/htmlform/OOUIHTMLForm.php
					return $this->msg( 'pageencryption-managepermissions-form-user-missing-public-key' )->text();
				}
				return true;
			},
			'default' => $username
		];

		$expiration_date = explode( ' ', (string)$row['expiration_date'] );

		$formDescriptor['expiration_date'] = [
			'label-message' => 'pageencryption-managepermissions-form-expiration_date-label',
			'type' => 'date',
			'min' => date( 'Y-m-d' ),
			'name' => 'expiration_date',
			'required' => false,
			'section' => $section_prefix . 'form-fieldset-permissions-main-public-key',
			'help-message' => 'pageencryption-managepermissions-form-expiration_date-help',
			'default' => $expiration_date[0]
		];

		return $formDescriptor;
	}

	/**
	 * @param array $data
	 * @param HTMLForm $htmlForm
	 * @return bool
	 */
	public function onSubmit( $data, $htmlForm ) {
		$request = $this->getRequest();
		$dbr = \PageEncryption::getDB( DB_PRIMARY );
		$id = $request->getVal( 'edit' );
		$new = ( $id && $id === 'new' );
		$title = ( array_key_exists( 'page', $data ) ? $title = Title::newFromText( $data['page'] )
			: $this->title );

		if ( array_key_exists( 'username', $data ) ) {
			$type = 'asymmetric';
			$this->missingPublicKey = false;

			$recipient = MediaWikiServices::getInstance()->getUserFactory()
				->newFromName( $data['username'] );

			$public_key = \PageEncryption::getPublicKey( $recipient );

			if ( empty( $public_key ) ) {
				$this->missingPublicKey = true;
				return Status::newFatal( 'formerror' );
			}

			\PageEncryption::setPermissionsAsymmetric(
				$this->user,
				$title,
				$recipient,
				$public_key,
				$data['expiration_date'],
				( !$new ? $id : null )
			);

		} else {
			$type = 'symmetric';
			\PageEncryption::setPermissionsSymmetric(
				$this->user,
				$title,
				$data['expiration_date'],
				( !$new ? $id : null )
			);
		}

		if ( $new ) {
			$this->latest_id = $dbr->selectField(
				"pageencryption_$type",
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
			'namespace' => NS_PAGEENCRYPTION,
			'exists' => true,
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
