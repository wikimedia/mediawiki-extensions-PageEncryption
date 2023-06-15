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
 
use MediaWiki\Revision\RevisionStore;
use MediaWiki\Page\PageIdentity;

class PageEncryptionRevisionLookup extends RevisionStore {

	/**
	 * @inheritDoc
	 */
	public function newRevisionFromRow(
		$row,
		$queryFlags = 0,
		// *** keep commented, since the class between MW 1.35
		// and above is different
		/* PageIdentity */ $page = null,
		$fromCache = false
	) {
		$rev = $this->newRevisionFromRowAndSlots( $row, null, $queryFlags, $page, $fromCache );
		return \PageEncryption::mockUpRevision( $rev );
	}

}

