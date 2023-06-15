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

$(function () {
	var WindowManager;
	var DialogName = "Dialog";
	var CookieName = "pageencryption-userkey";
	var Model = {};
	var EncryptedNamespace = 2246;
	var PasswordInputField;
	var PasswordConfirmationInputField;
	var MessageWidget;
	var KeyRecordIsSet = mw.config.get("pageencryption-protected-key-isSet");
	var UserkeyCookieIsSet = mw.config.get("pageencryption-userkey-cookie-isSet");
	var Booklet;

	// console.log(mw.config);

	function ProcessDialog(config) {
		ProcessDialog.super.call(this, config);
	}
	OO.inheritClass(ProcessDialog, OO.ui.ProcessDialog);

	ProcessDialog.static.name = DialogName;
	ProcessDialog.static.title = "PageEncryption";

	ProcessDialog.static.actions = [
		{
			action: "save",
			modes: "edit",
			label: mw.msg("pageencryption-jsmodule-dialog-save"),
			flags: ["primary", "progressive"],
		},
		{
			modes: "edit",
			label: mw.msg("pageencryption-jsmodule-dialog-cancel"),
			flags: ["safe", "close"],
		},
	];

	function PageOneLayout(name, config) {
		PageOneLayout.super.call(this, name, config);

		var fieldset = new OO.ui.FieldsetLayout({
			label: "",
		});

		var passwordInput = new OO.ui.TextInputWidget({
			label: mw.msg("pageencryption-jsmodule-dialog-password"),
			value: "",
			required: true,
			type: "password",
		});

		PasswordInputField = new OO.ui.FieldLayout(passwordInput, {
			label: "",
			align: "top",
		});

		Model.passwordInput = passwordInput;

		var passwordConfirmationInput = new OO.ui.TextInputWidget({
			label: mw.msg("pageencryption-jsmodule-dialog-password-confirmation"),
			value: "",
			required: true,
			type: "password",
		});

		Model.passwordConfirmationInput = passwordConfirmationInput;

		(PasswordConfirmationInputField = new OO.ui.FieldLayout(
			passwordConfirmationInput,
			{
				label: "",
				align: "top",
			}
		)),
			(MessageWidget = new OO.ui.MessageWidget({
				type: "info",
				// inline: true,
				label: mw.msg("pageencryption-jsmodule-dialog-field-password"),
			}));

		// MessageWidget.toggle(false)
		fieldset.addItems([
			MessageWidget,

			PasswordInputField,
			PasswordConfirmationInputField,
		]);

		this.$element.append(fieldset.$element);
	}
	OO.inheritClass(PageOneLayout, OO.ui.PageLayout);
	PageOneLayout.prototype.setupOutlineItem = function () {
		this.outlineItem.setLabel("Page One");
	};

	function messageButton() {
		var buttonGoBack = new OO.ui.ButtonWidget({
			framed: false,
			label: mw.msg("pageencryption-jsmodule-dialog-goback"),
			classes: ["pageencryption-button-goback"],
		});

		buttonGoBack.on("click", function () {
			Booklet.setPage("two");

			// MessageWidget resides on page one
			MessageWidget.setType("info");
			MessageWidget.setLabel(
				mw.msg("pageencryption-jsmodule-dialog-field-password")
			);
		});

		return new OO.ui.HtmlSnippet(
			$("<span>").append(
				mw.msg("pageencryption-jsmodule-dialog-field-password-reset") + " ",
				buttonGoBack.$element
			)
		);
	}

	function PageTwoLayout(name, config) {
		PageTwoLayout.super.call(this, name, config);

		var fieldset = new OO.ui.FieldsetLayout({
			label: "",
		});

		var enterPasswordInput = new OO.ui.TextInputWidget({
			label: mw.msg("pageencryption-jsmodule-dialog-password"),
			value: "",
			required: true,
			type: "password",
		});

		var buttonLostPassword = new OO.ui.ButtonWidget({
			framed: false,
			label: mw.msg("pageencryption-jsmodule-lost-password"),
			classes: ["pageencryption-button-lost-password"],
		});

		buttonLostPassword.on("click", function () {
			Booklet.setPage("one");
			MessageWidget.setType("error");
			MessageWidget.setLabel(messageButton());
		});

		var enterPasswordInputField = new OO.ui.FieldLayout(enterPasswordInput, {
			label: "",
			align: "top",
			helpInline: true,
			classes: ["pageencryption-field-password"],
			help: new OO.ui.HtmlSnippet(buttonLostPassword.$element),
		});

		Model.enterPasswordInput = enterPasswordInput;

		var messageWidget = new OO.ui.MessageWidget({
			type: "info",
			label: mw.msg("pageencryption-jsmodule-dialog-field-password-reenter"),
		});

		// MessageWidget.toggle(false)
		fieldset.addItems([messageWidget, enterPasswordInputField]);

		this.$element.append(fieldset.$element);
	}
	OO.inheritClass(PageTwoLayout, OO.ui.PageLayout);
	PageTwoLayout.prototype.setupOutlineItem = function () {
		this.outlineItem.setLabel("Page Two");
	};

	ProcessDialog.prototype.initialize = function () {
		ProcessDialog.super.prototype.initialize.apply(this, arguments);

		var page1 = new PageOneLayout("one"),
			page2 = new PageTwoLayout("two");

		Booklet = new OO.ui.BookletLayout({
			outlined: false,
			expanded: true,
			showMenu: false,
		});

		Booklet.addPages([page1, page2]);

		Booklet.setPage(!KeyRecordIsSet ? "one" : "two");

		var content = new OO.ui.PanelLayout({
			$content: Booklet.$element,
			padded: true,
			expanded: true,
		});

		this.$body.append(content.$element);
	};

	ProcessDialog.prototype.getBodyHeight = function () {
		return 300;
	};

	ProcessDialog.prototype.getActionProcess = function (action) {
		var dialog = this;

		if (!action || action === "delete") {
			return ProcessDialog.super.prototype.getActionProcess.call(this, action);
		}

		// or use Booklet.getCurrentPage().name
		if (!KeyRecordIsSet) {
			var password = Model.passwordInput.getValue();
			var passwordConfirm = Model.passwordConfirmationInput.getValue();

			if (password !== passwordConfirm) {
				console.log(password + "," + passwordConfirm);

				PasswordInputField.setErrors([]);

				PasswordConfirmationInputField.setErrors([
					mw.msg("pageencryption-jsmodule-dialog-password-error-nomatch"),
				]);

				return ProcessDialog.super.prototype.getActionProcess.call(
					this,
					action
				);
			}

			var validator = new PageEncryptionPasswordValidator();
			var errors = validator.checkPassword(password);
			var conf = validator.getConf();

			if (errors.length) {
				var errorsMessages = [];

				for (var error of errors) {
					var args = ["pageencryption-jsmodule-dialog-password-error-" + error];
					switch (error) {
						case "length":
							args.push(conf.minSize);
							args.push(conf.maxSize);
							break;

							break;
						case "special":
							args.push(conf.specialCharacters);

							break;
						case "prohibited":
							args.push(conf.prohibitedCharacters);
							break;
					}

					errorsMessages.push(mw.msg.apply(null, args));
				}
				PasswordInputField.setErrors(errorsMessages);
				return ProcessDialog.super.prototype.getActionProcess.call(
					this,
					action
				);
			}

			PasswordInputField.setErrors([]);
			PasswordConfirmationInputField.setErrors([]);
		} else {
			var password = Model.enterPasswordInput.getValue();
		}

		var payload = {
			action: "pageencryption-set-encryption-key",
			password: password,
			"reset-key": Booklet.getCurrentPage().name === "one" ? 1 : 0,
		};

		// https://www.mediawiki.org/wiki/OOUI/Windows/Process_Dialogs#Action_sets
		return ProcessDialog.super.prototype.getActionProcess
			.call(this, action)
			.first(function () {
				switch (action) {
					case "save":

					// eslint-disable no-fallthrough
					case "delete":
						var callApi = function (postData, resolve, reject) {
							// console.log("postData", postData);

							new mw.Api()
								.postWithToken("csrf", postData)
								.done(function (res) {
									// console.log("res", res);
									if (!("pageencryption-set-encryption-key" in res)) {
										reject(
											new OO.ui.Error(res, {
												recoverable: true,
												warning: false,
											})
										);
									} else {
										var value = res["pageencryption-set-encryption-key"];
										if (value["message"] !== null) {
											reject(
												new OO.ui.Error(value["message"], {
													recoverable: true,
													warning: false,
												})
											);
										} else {
											if (value["action"] === "new-record") {
												// @TODO show popup
												console.log(value["protected-key"]);
											}

											WindowManager.removeWindows([DialogName]);
										}
									}

									// resolve();
								})
								.fail(function (res) {
									console.log("res", res);
									var msg = res;
									// https://doc.wikimedia.org/oojs-ui/master/js/source/Error.html#OO-ui-Error-method-constructor
									reject(
										new OO.ui.Error(msg, { recoverable: true, warning: false })
									);
								});
						};
						// eslint-disable-next-line compat/compat
						return new Promise((resolve, reject) => {
							mw.loader.using("mediawiki.api", function () {
								callApi(payload, resolve, reject);
							});
						}); // promise
				}
				//return false;
			}, this); // .next

		return new OO.ui.Process(function () {
			dialog.close({ action: action });
		});

		// return ProcessDialog.super.prototype.getActionProcess.call( this, action );
	};

	/*
	ProcessDialog.prototype.getTeardownProcess = function (data) {
		return ProcessDialog.super.prototype.getTeardownProcess
			.call(this, data)
			.first(function () {
				console.log("ProcessDialog");
				removeActiveWindow();
			}, this);
	};
*/

	/**
	 * Override getBodyHeight to create a tall dialog relative to the screen.
	 *
	 * @return {number} Body height
	 */
	// ProcessDialog.prototype.getBodyHeight = function () {
	// 	// see here https://www.mediawiki.org/wiki/OOUI/Windows/Process_Dialogs
	// 	// this.page1.content.$element.outerHeight( true );
	// 	return window.innerHeight - 100;
	// };

	function createWindowManager() {
		var windowManager = new OO.ui.WindowManager({
			classes: ["pageencryption-ooui-window"],
		});
		$(document.body).append(windowManager.$element);

		return windowManager;
	}

	function openDialog() {
		var processDialog = new ProcessDialog({
			size: "medium",
			classes: [],
		});

		WindowManager = createWindowManager();

		WindowManager.addWindows([processDialog]);

		WindowManager.openWindow(processDialog);
	}

	//  *** httpOnly cookies cannot be accessed client-side
	// function userKeyIsSet() {
	// 	return mw.cookie.get(CookieName, mw.config.get("pageencryption-wgCookiePrefix"));
	// }

	function isEncryptedNamespace() {
		return mw.config.get("wgNamespaceNumber") === EncryptedNamespace;
	}

	if (
		mw.config.get("pageencryption-user-is-editor") &&
		(!KeyRecordIsSet || !UserkeyCookieIsSet)
	) {
		openDialog();
	}
});
