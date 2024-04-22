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

// @credits https://github.com/briannippert/Password-Validator/blob/master/PasswordValidatorv2.js
const PageEncryptionPasswordValidator = function ( conf ) {
	var conf = $.extend(
		{
			minSize: 5,
			maxSize: 15,
			lengthConfigured: true,
			uppercaseConfigured: true,
			digitConfigured: true,
			specialConfigured: true,
			prohibitedConfigured: true,
			specialCharacters: [ '_', '#', '%', '*', '@' ],
			prohibitedCharacters: [ '$', '&', '=', '!' ]
		},
		conf || {}
	);

	function checkPassword( value ) {
		var length = conf.lengthConfigured ? checkLength( value ) : true;
		var upper = conf.uppercaseConfigured ? checkUpperCase( value ) : true;
		var digit = conf.digitConfigured ? checkDigit( value ) : true;
		var special = conf.specialConfigured ? checkSpecialCharacters( value ) : true;
		var prohibited = conf.prohibitedConfigured ?
			checkProhibitedCharacter( value ) :
			true;

		var errors = [];
		if ( !length ) {
			errors.push( 'length' );
		}
		if ( !upper ) {
			errors.push( 'uppercase' );
		}
		if ( !digit ) {
			errors.push( 'digit' );
		}
		if ( !special ) {
			errors.push( 'special' );
		}
		if ( prohibited ) {
			errors.push( 'prohibited' );
		}

		return errors;
	}

	function checkSpecialCharacters( str ) {
		// var specialChar = new RegExp("[_\\-#%*\\+]");
		var specialChar = new RegExp( '[' + conf.specialCharacters.join( '' ) + ']' );

		return specialChar.test( str );
	}

	function checkProhibitedCharacter( str ) {
		// var specialChar = new RegExp("[$&=!@]");//= /[$&=!@]/;
		var specialChar = new RegExp(
			'[' + conf.prohibitedCharacters.join( '' ) + ']'
		);

		return specialChar.test( str );
	}

	function checkDigit( str ) {
		return /\d/.test( str );
	}

	function checkUpperCase( str ) {
		return /[^A-Z]/.test( str );
	}

	function checkLength( str ) {
		return str.length >= conf.minSize && str.length <= conf.maxSize;
	}

	function getConf( str ) {
		return conf;
	}

	return {
		checkPassword,
		getConf
	};
};
