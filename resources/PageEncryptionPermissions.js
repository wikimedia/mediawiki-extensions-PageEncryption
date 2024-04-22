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
 * @author thomas-topway-it <support@topway.it>
 * @copyright Copyright ©2023, https://wikisphere.org
 */

$( function () {
	$( '.pageencryption-managepermissions-pager-button-show-url' ).on(
		'click',

		function () {
			navigator.clipboard.writeText( $( this ).data( 'url' ) ).then( () => {
				alert(
					mw.msg(
						'pageencryption-jsmodule-managepermissions-copied-to-clipboard'
					)
				);
			} );
		}
	);

	$( '.pageencryption-managepermissions-pager-button-show-password' ).on(
		'click',

		function () {
			navigator.clipboard.writeText( $( this ).data( 'password' ) ).then( () => {
				alert(
					mw.msg(
						'pageencryption-jsmodule-managepermissions-copied-to-clipboard'
					)
				);
			} );
		}
	);

	// eslint-disable-next-line no-jquery/no-global-selector
	$( '#pageencryption-form-permissions button[type="submit"]' ).on(
		'click',
		// eslint-disable-next-line no-unused-vars
		function ( val ) {
			if ( $( this ).val() === 'delete' ) {
				// eslint-disable-next-line no-alert
				if ( !confirm( mw.msg( 'pageencryption-jsmodule-deleteitemconfirm' ) ) ) {
					return false;
				}

				// eslint-disable-next-line no-jquery/no-sizzle
				$( this )
					.closest( 'form' )
					.find( ':input' )
					.each( function ( i, el ) {
						$( el ).removeAttr( 'required' );
					} );
			}
		}
	);

	// display every 3 days
	if (
		canManagePermissions &&
		!mw.cookie.get( 'pageencryption-check-latest-version' )
	) {
		mw.loader.using( 'mediawiki.api', function () {
			new mw.Api()
				.postWithToken( 'csrf', {
					action: 'pageencryption-check-latest-version'
				} )
				.done( function ( res ) {
					if ( 'pageencryption-check-latest-version' in res ) {
						if ( res[ 'pageencryption-check-latest-version' ].result === 2 ) {
							var messageWidget = new OO.ui.MessageWidget( {
								type: 'warning',
								label: new OO.ui.HtmlSnippet(
									mw.msg(
										'pageencryption-jsmodule-managepermissions-outdated-version'
									)
								),
								// *** this does not work before ooui v0.43.0
								showClose: true
							} );
							var closeFunction = function () {
								var three_days = 3 * 86400;
								mw.cookie.set( 'pageencryption-check-latest-version', true, {
									path: '/',
									expires: three_days
								} );
								$( messageWidget.$element ).parent().remove();
							};
							messageWidget.on( 'close', closeFunction );
							$( '#pageencryption-panel-layout' ).first().prepend(
								// eslint-disable-next-line no-jquery/no-parse-html-literal
								$( '<div><br/></div>' ).prepend( messageWidget.$element )
							);
							if (
								// eslint-disable-next-line no-jquery/no-class-state
								!messageWidget.$element.hasClass(
									'oo-ui-messageWidget-showClose'
								)
							) {
								messageWidget.$element.addClass(
									'oo-ui-messageWidget-showClose'
								);
								var closeButton = new OO.ui.ButtonWidget( {
									classes: [ 'oo-ui-messageWidget-close' ],
									framed: false,
									icon: 'close',
									label: OO.ui.msg( 'ooui-popup-widget-close-button-aria-label' ),
									invisibleLabel: true
								} );
								closeButton.on( 'click', closeFunction );
								messageWidget.$element.append( closeButton.$element );
							}
						}
					}
				} );
		} );
	}
} );
