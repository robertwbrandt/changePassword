<?php
/*
 *    eDirectory Password Changer
 *
 *    Created by: Bob Brandt (http://brandt.ie)
 *    Created on: 2013-05-26
 *
 *    This script was originally modified from both Matt Rude's LDAP PHP 
 *    Change Password Webpage (http://mattrude.com) and Jeff Todnem's Password 
 *    Strength Checker(http://www.passwordmeter.com/)
 *
 *                             GNU GENERAL PUBLIC LICENSE
 *                                Version 2, June 1991
 *    -------------------------------------------------------------------------
 *    Copyright (C) 2013 Bob Brandt
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License as published by the
 *    Free Software Foundation; either version 2 of the License, or (at your
 *    option) any later version.
 *    
 *    This program is distributed in the hope that it will be useful, but
 *    WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *    General Public License for more details.
 *    
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * In order to work with Active Directory, the userPassword attribute has to be enabled:
 * http://msdn.microsoft.com/en-us/library/cc223249.aspx
 * Active Directory supports modifying passwords on objects via the userPassword attribute, provided that 
 * (1) either the DC is running as AD LDS, or the DC is running as AD DS and the domain functional level is DS_BEHAVIOR_WIN2003 or greater, and 
 * (2) the fUserPwdSupport heuristic is true in the dSHeuristics attribute (section 6.1.1.2.4.1.2). 
 * If fUserPwdSupport is false, the userPassword attribute is treated as an ordinary attribute and has no special semantics associated with it. 
 * If fUserPwdSupport is true but the DC is running as AD DS and the domain functional level is less than DS_BEHAVIOR_WIN2003, the DC fails the operation with the error constraintViolation / ERROR_NOT_SUPPORTED.
 *
 * http://msdn.microsoft.com/en-us/library/cc223560.aspx
 * This article states that the 9th character of the dSHeuristics is neither "0" nor "2", then the fUserPwdSupport heuristic is true. 
 * If this character is "2", then the fUserPwdSupport heuristic is false. 
 * If this character is "0", then the fUserPwdSupport heuristic is false for AD DS and true for AD LDS.
 *
 * You can change this value by using the ADSI Edit utility and modifying the following object:
 *  CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,Root domain in forest
 *
 * test:> ldapsearch -b "ou=opw,dc-i,dc=opw,dc=ie" -s sub -D 'cn=passwordAdmin,ou=web,ou=opw,dc=i,dc=opw,dc=ie' -w 'P@ssw0rdAdm1n' -H 'ldaps://10.201.200.12/' "(objectClass=brandtb)" mail
*/


// LDAP Connection Details
$ldapDetails[0] = array( 'name' => 'Production Tree', 'server' => 'ldaps://10.201.200.1/', 'base' => 'o=opw', 'user' => 'cn=passwordAdmin,ou=web,o=opw', 'pass' => 'P@ssw0rdAdm1n' );
$ldapDetails[1] = array( 'name' => 'Identity Tree', 'server' => 'ldaps://10.200.199.10/', 'base' => 'ou=org,o=opw', 'user' => 'cn=passwordAdmin,ou=web,ou=org,o=opw', 'pass' => 'P@ssw0rdAdm1n' );
$ldapDetails[2] = array( 'name' => 'Legacy Active Directory', 'server' => 'ldaps://10.201.200.10/', 'base' => 'ou=opw,dc=opw,dc=ad', 'user' => 'cn=passwordAdmin,ou=web,ou=opw,dc=opw,dc=ad', 'pass' => 'P@ssw0rdAdm1n' );
$ldapDetails[3] = array( 'name' => 'Active Directory', 'server' => 'ldaps://10.201.200.12/', 'base' => 'ou=opw,dc=i,dc=opw,dc=ie', 'user' => 'cn=passwordAdmin,ou=web,ou=opw,dc=i,dc=opw,dc=ie', 'pass' => 'P@ssw0rdAdm1n' );

// LDAP Schema names
$ldapSchema[0] = array( 'class' => 'person', 'uid' => 'cn', 'fullname' => 'fullname', 'email' => 'mail', 'telephone' => 'telephonenumber', 'grade' => 'title', 'section' => 'ou', 'location' => 'l', 'expire' => 'passwordexpirationtime', 'gracelimit' => 'logingracelimit', 'graceremain' => 'logingraceremaining', 'group' => 'groupmembership' );
$ldapSchema[1] = array( 'class' => 'person', 'uid' => 'cn', 'fullname' => 'fullname', 'email' => 'mail', 'telephone' => 'telephonenumber', 'grade' => 'title', 'section' => 'ou', 'location' => 'l', 'expire' => 'passwordexpirationtime', 'gracelimit' => 'logingracelimit', 'graceremain' => 'logingraceremaining', 'group' => 'groupmembership' );
$ldapSchema[2] = array( 'class' => 'person', 'uid' => 'samAccountName' );
$ldapSchema[3] = array( 'class' => 'person', 'uid' => 'samAccountName' );
$ldapSchemaDisplayOrder = array( 'fullname', 'email', 'telephone', 'grade', 'section', 'location' );

// Admin Groups are case sensitive.
$admingroups = array( 1 => 'cn=helpdeskgroup,o=OPW', 2 => 'cn=ServerAdmins,o=OPW', 3 => 'cn=admingroup,o=OPW' );

$minimumPasswordLen = 10;
$mustHaveCapital = true;
$mustHaveLower = true;
$mustHaveNumber = true;
$minimumScore = 50;
$differentPass = true;
$corporateLogo = 'http://changepassword/opw.jpg';

$monthNames = array("","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec");

require 'class.phpmailer.php';
$mail = new PHPMailer;
$mail->IsSMTP();
$mail->Host = 'smtp.opw.ie';
$mail->SMTPAuth = false;
$mail->From = 'changepassword@opw.ie';
$mail->FromName = 'Change Password';
$mail->AddBCC('bob.brandt@opw.ie');
$mail->WordWrap = 50;                                 // Set word wrap to 50 characters
$mail->IsHTML(false);                                  // Set email format to HTML

// Turn off all error reporting
error_reporting(0);
// Report all PHP errors
//error_reporting(-1);

function getLDAPInfo($ldapNumber, &$userInfo) {
	global $ldapDetails, $ldapSchema, $admingroups, $monthNames;
	$ldapDS = ldap_connect($ldapDetails[$ldapNumber]['server']);
	#if (ldap_start_tls($ldapDS)) 
	if ($ldapDS) $ldapBind = ldap_bind($ldapDS, $ldapDetails[$ldapNumber]['user'], $ldapDetails[$ldapNumber]['pass']);
	if ($ldapBind) { 
		$ldapFilter = '(&(objectClass='. $ldapSchema[$ldapNumber]['class'] . ')(' . $ldapSchema[$ldapNumber]['uid'] . '=' . $userInfo['uid'] . '))';
		$results = ldap_search($ldapDS, $ldapDetails[$ldapNumber]['base'], $ldapFilter, array_values($ldapSchema[$ldapNumber]), 0, 1);
		$entries = ldap_get_entries($ldapDS, $results);
		$userInfo['count'] = $entries['count'];
		$userInfo['dn'] = $entries[0]['dn'];
		ldap_close($ldapDS);
		$userInfo['admin'] = 0;
		for ($j = 1; $j <= count($admingroups); $j++) if (in_array($admingroups[$j], $entries[0][$ldapSchema[$ldapNumber]['group']])) $userInfo['admin'] = $j;	
		$ldapSchemaKeys = array_keys($ldapSchema[$ldapNumber]);
		for ($j = 0; $j < count($ldapSchemaKeys); $j++) $userInfo[$ldapSchemaKeys[$j]] = $entries[0][$ldapSchema[$ldapNumber][$ldapSchemaKeys[$j]]][0];
		if (isset($userInfo['expire'])) $userInfo['expire'] = substr($userInfo['expire'],6,2) . ' ' . $monthNames[intval(substr($userInfo['expire'],4,2))] . ' ' . substr($userInfo['expire'],0,4) . ' at ' . substr($userInfo['expire'],8,2) . ":" . substr($userInfo['expire'],10,2);
		return $entries;
	}
}

function changePassword() {
	global $ldapDetails, $ldapSchema, $loginInfo;
	for ($j = 0; $j < count($ldapDetails); $j++) {
		$ldapDetails[$j]['return'] = false;	
		$ldapDS = ldap_connect($ldapDetails[$j]['server']);
		if ($ldapDS) { 
			$ldapBind = ldap_bind($ldapDS, $ldapDetails[$j]['user'], $ldapDetails[$j]['pass']);
			if ($ldapBind) {   			 
				$ldapFilter = '(&(objectClass='. $ldapSchema[$j]['class'] . ')(' . $ldapSchema[$j]['uid'] . '=' . $loginInfo['username'] . '))';		
				$results = ldap_search($ldapDS, $ldapDetails[$j]['base'], $ldapFilter, array_values($ldapSchema[$j]), 0, 1);
				$entries = ldap_get_entries($ldapDS, $results);
				$dn = $entries[0]['dn'];
				$entry['userPassword'] = $loginInfo['password'];
				ldap_modify($ldapDS, $dn, $entry);
				$ldapDetails[$j]['return'] = ldap_error($ldapDS) . " (code " . ldap_errno($ldapDS) . ")";
				ldap_close($ldapDS);
			} else { $ldapDetails[$j]['return'] = 'Unable to bind to server.'; }
		} else { $ldapDetails[$j]['return'] = 'Unable to connect to server.'; }
	}
	return $ldapDetails;
}

function stringAdd($sOne,$sTwo) { $sep = ($sOne != '' and $sTwo != '') ? '<br/>' : ''; return $sOne . $sep . $sTwo; }

function buildUserDetails() {
	global $ldapSchemaDisplayOrder, $ldapSchema, $userInfo; $sDetails = '';
	for ($j = 0; $j < count($ldapSchemaDisplayOrder); $j++) $sDetails = stringAdd($sDetails , $userInfo[$ldapSchemaDisplayOrder[$j]]);
	return $sDetails;
}

function hashCode($string) {
	$hash = 0; if (strlen($string) == 0) return $hash;
	for ($i = 0; $i < strlen($string); $i++) {
		$char = ord(substr($string, $i, 1));
		$hash = (($hash<<5) - $hash) + $char;
		$hash = $hash & $hash; }
	return $hash;
}

function writeJavascript() {
	global $minimumPasswordLen, $mustHaveCapital, $mustHaveLower, $mustHaveNumber, $minimumScore, $differentPass, $admingroups, $loginInfo;
	$return = "\n" . 'function setFocus() { document.getElementById("passwordPwd").focus(); }' . "\n";
	if ($minimumPasswordLen) $return .= 'function chkPassLen() { return (document.getElementById("passwordPwd").value.length >= ' . $minimumPasswordLen . "); }\n";
	if ($mustHaveLower) $return .= 'function chkPassLower() { return (document.getElementById("passwordPwd").value.match(/[a-z]/) != null); }' . "\n";
	if ($mustHaveCapital) $return .= 'function chkPassUpper() { return (oPwd = document.getElementById("passwordPwd").value.match(/[A-Z]/) != null); }' . "\n";
	if ($mustHaveNumber) $return .= 'function chkPassNum() { return (document.getElementById("passwordPwd").value.match(/[0-9]/) != null); }' . "\n";
	if ($minimumScore) $return .= 'function chkPassScore() { return (document.getElementById("score").value >= ' . $minimumScore . "); }\n";
	if ($differentPass) $return .= 'function chkPassDiff() { return ( document.getElementById("passwordPwd").value.replace(/\s+/g, "").replace(/[0-9]+/g, "").toLowerCase() != "' . strtolower(trim(preg_replace('/\s+/', '',str_replace(range(0,9),'',$loginInfo['loginpass'])))) . '" );}' . "\n";
	$return .= 'String.prototype.strReverse = function() { var newstring = ""; for (var s=0; s < this.length; s++) newstring = this.charAt(s) + newstring; return newstring; }' . "\n";
		
	$return .= "\nfunction chkPass(pwd) {\n";
	$return .= "	// Simultaneous variable declaration and value assignment aren't supported in IE apparently\n";
	$return .= "	// so I'm forced to assign the same value individually per var to support a crappy browser *sigh*\n"; 
	$return .= '	var nScore=0, nLength=0, nAlphaUC=0, nAlphaLC=0, nNumber=0, nSymbol=0, nMidChar=0, nRequirements=0, nAlphasOnly=0, nNumbersOnly=0, nUnqChar=0, nRepChar=0, nRepInc=0, nConsecAlphaUC=0, nConsecAlphaLC=0, nConsecNumber=0, nConsecSymbol=0, nConsecCharType=0, nSeqAlpha=0, nSeqNumber=0, nSeqSymbol=0, nSeqChar=0, nReqChar=0, nMultConsecCharType=0;' . "\n";
	$return .= "	var nMultRepChar=1, nMultConsecSymbol=1;\n";
	$return .= "	var nMultMidChar=2, nMultRequirements=2, nMultConsecAlphaUC=2, nMultConsecAlphaLC=2, nMultConsecNumber=2;\n";
	$return .= '	var nReqCharType=3, nMultAlphaUC=3, nMultAlphaLC=3, nMultSeqAlpha=3, nMultSeqNumber=3, nMultSeqSymbol=3;' . "\n";
	$return .= '	var nMultLength=4, nMultNumber=4, nMultSymbol=6;' . "\n";
	$return .= '	var nTmpAlphaUC="", nTmpAlphaLC="", nTmpNumber="", nTmpSymbol="";' . "\n";
	$return .= '	var sAlphas = "abcdefghijklmnopqrstuvwxyz";' . "\n";
	$return .= '	var sNumerics = "01234567890";' . "\n";
	$return .= '	var sSymbols = ")!@#$%^&*()";' . "\n";
	$return .= '	var sComplexity = "Too Short";' . "\n";
	$return .= '	if (document.all) { var nd = 0; } else { var nd = 1; }' . "\n";
	$return .= '	if (pwd) {' . "\n";
	$return .= '		nScore = parseInt(pwd.length * nMultLength);' . "\n";
	$return .= '		nLength = pwd.length;' . "\n";
	$return .= '		var arrPwd = pwd.replace(/\s+/g,"").split(/\s*/);' . "\n";
	$return .= '		var arrPwdLen = arrPwd.length;' . "\n";
	$return .= '		/* Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */' . "\n";
	$return .= '		for (var a=0; a < arrPwdLen; a++) {' . "\n";
	$return .= '			if (arrPwd[a].match(/[A-Z]/g)) {' . "\n";
	$return .= '				if (nTmpAlphaUC !== "") { if ((nTmpAlphaUC + 1) == a) { nConsecAlphaUC++; nConsecCharType++; } }' . "\n";
	$return .= '				nTmpAlphaUC = a;' . "\n";
	$return .= '				nAlphaUC++;' . "\n";
	$return .= '			}' . "\n";
	$return .= '			else if (arrPwd[a].match(/[a-z]/g)) {' . "\n"; 
	$return .= '				if (nTmpAlphaLC !== "") { if ((nTmpAlphaLC + 1) == a) { nConsecAlphaLC++; nConsecCharType++; } }' . "\n";
	$return .= '				nTmpAlphaLC = a;' . "\n";
	$return .= '				nAlphaLC++;' . "\n";
	$return .= '			}' . "\n";
	$return .= '			else if (arrPwd[a].match(/[0-9]/g)) {' . "\n"; 
	$return .= '				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }' . "\n";
	$return .= '				if (nTmpNumber !== "") { if ((nTmpNumber + 1) == a) { nConsecNumber++; nConsecCharType++; } }' . "\n";
	$return .= '				nTmpNumber = a;' . "\n";
	$return .= '				nNumber++;' . "\n";
	$return .= '			}' . "\n";
	$return .= '			else if (arrPwd[a].match(/[^a-zA-Z0-9_]/g)) {' . "\n"; 
	$return .= '				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }' . "\n";
	$return .= '				if (nTmpSymbol !== "") { if ((nTmpSymbol + 1) == a) { nConsecSymbol++; nConsecCharType++; } }' . "\n";
	$return .= '				nTmpSymbol = a;' . "\n";
	$return .= '				nSymbol++;' . "\n";
	$return .= '			}' . "\n";
	$return .= '			/* Internal loop through password to check for repeat characters */' . "\n";
	$return .= '			var bCharExists = false;' . "\n";
	$return .= '			for (var b=0; b < arrPwdLen; b++) {' . "\n";
	$return .= '				if (arrPwd[a] == arrPwd[b] && a != b) { /* repeat character exists */' . "\n";
	$return .= '					bCharExists = true;' . "\n";
	$return .= '					/* ' . "\n";
	$return .= '					Calculate increment deduction based on proximity to identical characters' . "\n";
	$return .= '					Deduction is incremented each time a new match is discovered' . "\n";
	$return .= '					Deduction amount is based on total password length divided by the' . "\n";
	$return .= '					difference of distance between currently selected match' . "\n";
	$return .= '					*/' . "\n";
	$return .= '					nRepInc += Math.abs(arrPwdLen/(b-a));' . "\n";
	$return .= '				}' . "\n";
	$return .= '			}' . "\n";
	$return .= '			if (bCharExists) {' . "\n"; 
	$return .= '				nRepChar++; ' . "\n";
	$return .= '				nUnqChar = arrPwdLen-nRepChar;' . "\n";
	$return .= '				nRepInc = (nUnqChar) ? Math.ceil(nRepInc/nUnqChar) : Math.ceil(nRepInc);' . "\n"; 
	$return .= '			}' . "\n";
	$return .= '		}' . "\n";
	$return .= '		/* Check for sequential alpha string patterns (forward and reverse) */' . "\n";
	$return .= '		for (var s=0; s < 23; s++) {' . "\n";
	$return .= '			var sFwd = sAlphas.substring(s,parseInt(s+3));' . "\n";
	$return .= '			var sRev = sFwd.strReverse();' . "\n";
	$return .= '			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqAlpha++; nSeqChar++;}' . "\n";
	$return .= '		}' . "\n";
	$return .= '		/* Check for sequential numeric string patterns (forward and reverse) */' . "\n";
	$return .= '		for (var s=0; s < 8; s++) {' . "\n";
	$return .= '			var sFwd = sNumerics.substring(s,parseInt(s+3));' . "\n";
	$return .= '			var sRev = sFwd.strReverse();' . "\n";
	$return .= '			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqNumber++; nSeqChar++;}' . "\n";
	$return .= '		}' . "\n";
	$return .= '		/* Check for sequential symbol string patterns (forward and reverse) */' . "\n";
	$return .= '		for (var s=0; s < 8; s++) {' . "\n";
	$return .= '			var sFwd = sSymbols.substring(s,parseInt(s+3));' . "\n";
	$return .= '			var sRev = sFwd.strReverse();' . "\n";
	$return .= '			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqSymbol++; nSeqChar++;}' . "\n";
	$return .= '		}' . "\n";
	$return .= '	/* Modify overall score value based on usage vs requirements */' . "\n";
	$return .= '		/* General point assignment */' . "\n";
	$return .= '		if (nAlphaUC > 0 && nAlphaUC < nLength) nScore = parseInt(nScore + ((nLength - nAlphaUC) * 2));' . "\n";
	$return .= '		if (nAlphaLC > 0 && nAlphaLC < nLength) nScore = parseInt(nScore + ((nLength - nAlphaLC) * 2));' . "\n";
	$return .= '		if (nNumber > 0 && nNumber < nLength) nScore = parseInt(nScore + (nNumber * nMultNumber));' . "\n";
	$return .= '		if (nSymbol > 0) nScore = parseInt(nScore + (nSymbol * nMultSymbol));' . "\n";
	$return .= '		if (nMidChar > 0) nScore = parseInt(nScore + (nMidChar * nMultMidChar));' . "\n";
	$return .= '		/* Point deductions for poor practices */' . "\n";
	$return .= '		// Only Letters' . "\n";
	$return .= '		if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol === 0 && nNumber === 0) nScore = parseInt(nScore - nLength);' . "\n";
	$return .= '		// Only Numbers' . "\n";
	$return .= '		if (nAlphaLC === 0 && nAlphaUC === 0 && nSymbol === 0 && nNumber > 0) nScore = parseInt(nScore - nLength);' . "\n";
	$return .= '		// Same character exists more than once' . "\n";
	$return .= '		if (nRepChar > 0) nScore = parseInt(nScore - nRepInc);' . "\n";
	$return .= '		// Consecutive Uppercase Letters exist' . "\n";
	$return .= '		if (nConsecAlphaUC > 0) nScore = parseInt(nScore - (nConsecAlphaUC * nMultConsecAlphaUC));' . "\n";
	$return .= '		// Consecutive Lowercase Letters exist ' . "\n";
	$return .= '		if (nConsecAlphaLC > 0) nScore = parseInt(nScore - (nConsecAlphaLC * nMultConsecAlphaLC));' . "\n";
	$return .= '		// Consecutive Numbers exist' . "\n";
	$return .= '		if (nConsecNumber > 0) nScore = parseInt(nScore - (nConsecNumber * nMultConsecNumber));  ' . "\n";
	$return .= '		// Sequential alpha strings exist (3 characters or more)' . "\n";
	$return .= '		if (nSeqAlpha > 0) nScore = parseInt(nScore - (nSeqAlpha * nMultSeqAlpha));' . "\n"; 
	$return .= '		// Sequential numeric strings exist (3 characters or more)' . "\n";
	$return .= '		if (nSeqNumber > 0) nScore = parseInt(nScore - (nSeqNumber * nMultSeqNumber));' . "\n";
	$return .= '		// Sequential symbol strings exist (3 characters or more)' . "\n";
	$return .= '		if (nSeqSymbol > 0) nScore = parseInt(nScore - (nSeqSymbol * nMultSeqSymbol));' . "\n";
	$return .= '		/* Determine if mandatory requirements have been met and set image indicators accordingly */' . "\n";
	$return .= '		nRequirements = nReqChar;' . "\n";
	$return .= '		if (pwd.length >= ' . $minimumPasswordLen . ") { var nMinReqChars = 3; } else { var nMinReqChars = 4; }\n";
	$return .= '		if (nRequirements > nMinReqChars) nScore = parseInt(nScore + (nRequirements * 2));' . "\n";
	$return .= '		/* Determine complexity based on overall score */' . "\n";
	$return .= '		if (nScore > 100) { nScore = 100; } else if (nScore < 0) { nScore = 0; }' . "\n";
	$return .= '		if (nScore >= 0 && nScore < 20) { sComplexity = "Very Weak"; }' . "\n";
	$return .= '		else if (nScore >= 20 && nScore < 40) { sComplexity = "Weak"; }' . "\n";
	$return .= '		else if (nScore >= 40 && nScore < 60) { sComplexity = "Good"; }' . "\n";
	$return .= '		else if (nScore >= 60 && nScore < 80) { sComplexity = "Strong"; }' . "\n";
	$return .= '		else if (nScore >= 80 && nScore <= 100) { sComplexity = "Very Strong"; }' . "\n";
	$return .= '	}' . "\n";
	$return .= '	/* Display updated score criteria to client */' . "\n";
	$return .= '	var oScorebar = document.getElementById("scorebar");' . "\n";
	$return .= '	var oScore = document.getElementById("score");' . "\n";
	$return .= '	if (nScore < 50) {red = 255; green = 255 * (nScore/50); blue = 0;} else {red = 255 - 255 * ((nScore-50)/50); green = 255 - 128 * ((nScore-50)/50); blue = 50 - 50 * Math.abs((nScore-75)/25);}' . "\n";
	$return .= '	oScorebar.innerHTML = nScore + "%&nbsp;&nbsp;" + sComplexity;' . "\n";
	$return .= '	oScorebar.style.backgroundColor = "rgb(" + parseInt(red) + " ," + parseInt(green) + " ," + parseInt(blue) + ")";' . "\n";
	$return .= '	oScore.value = nScore' . "\n";
	$return .= '' . "\n";
	if ($minimumPasswordLen) $return .= '	if (document.getElementById("pwlength")) document.getElementById("pwlength").className = chkPassLen() ? "good" : "warning";' . "\n";
	if ($mustHaveLower) $return .= '	if (document.getElementById("pwlower")) document.getElementById("pwlower").className = chkPassLower() ? "good" : "warning";' . "\n";
	if ($mustHaveCapital) $return .= '	if (document.getElementById("pwcapital")) document.getElementById("pwcapital").className = chkPassUpper() ? "good" : "warning";' . "\n";
	if ($mustHaveNumber) $return .= '	if (document.getElementById("pwnumber")) document.getElementById("pwnumber").className = chkPassNum() ? "good" : "warning";' . "\n";
	if ($minimumScore) $return .= '	if (document.getElementById("pwscore")) document.getElementById("pwscore").className = chkPassScore() ? "good" : "warning";' . "\n";
	if ($differentPass) $return .= '	if (document.getElementById("pwsame")) document.getElementById("pwsame").className = chkPassDiff() ? "good" : "warning";' . "\n";
	$return .= '}' . "\n";

	$return .= "\nfunction togPwdMask() {\n";
	$return .= '	var oPwd = document.getElementById("passwordPwd");' . "\n";
	$return .= '	var oTxt = document.getElementById("passwordTxt");' . "\n";
	$return .= '	var oPwd2 = document.getElementById("passwordPwd2");' . "\n";
	$return .= '	var oTxt2 = document.getElementById("passwordTxt2");' . "\n";
//	$return .= '	var oMask = document.getElementById("mask");' . "\n";
	$return .= '	if (document.getElementById("mask").checked) { ' . "\n";
	$return .= '		oPwd.value = oTxt.value;' . "\n";
	$return .= '		oPwd.className = ""; ' . "\n";
	$return .= '		oTxt.className = "hide";' . "\n"; 
	$return .= '		oPwd2.value = oTxt2.value;' . "\n";
	$return .= '		oPwd2.className = ""; ' . "\n";
	$return .= '		oTxt2.className = "hide"; ' . "\n";
	$return .= '	} ' . "\n";
	$return .= '	else { ' . "\n";
	$return .= '		oTxt.value = oPwd.value;' . "\n";
	$return .= '		oPwd.className = "hide"; ' . "\n";
	$return .= '		oTxt.className = "";' . "\n";
	$return .= '		oTxt2.value = oPwd2.value;' . "\n";
	$return .= '		oPwd2.className = "hide"; ' . "\n";
	$return .= '		oTxt2.className = "";' . "\n";
	$return .= '	}' . "\n";
	$return .= '}' . "\n";

	$return .= "\nfunction togUserInfo() {\n";
	$return .= '	var oBtn = document.getElementById("submitted");' . "\n";
	$return .= '	var oSubmitted = document.getElementById("submitteduser");' . "\n";
	$return .= '	var oEntered = document.getElementById("username");' . "\n";
	$return .= '	sBtn = "Verify Username"; sDiv = "hide";' . "\n";
	$return .= '	if (oSubmitted.value.toLowerCase() == oEntered.value.toLowerCase()) { sBtn = "Change Passphrase"; }' . "\n";
	$return .= '	if (oSubmitted.value.toLowerCase() == oEntered.value.toLowerCase()) { sDiv = ""; }	 ' . "\n";
	$return .= '	oBtn.value = sBtn;' . "\n";
	$return .= '	if (document.getElementById("uidetails")) document.getElementById("uidetails").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("uiexpire")) document.getElementById("uiexpire").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("uigracelogin")) document.getElementById("uigracelogin").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("newpassword")) document.getElementById("newpassword").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("complexity")) document.getElementById("complexity").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("rules")) document.getElementById("rules").className = sDiv;' . "\n";
	$return .= '	if (document.getElementById("newpassword2")) document.getElementById("newpassword2").className = sDiv;' . "\n";
	$return .= '}' . "\n";

	$return .= "\nfunction validateForm() {\n";
	$return .= '	if ( document.getElementById("submitted").value != "Change Passphrase" ) return true;' . "\n"; 
	$return .= '	var oPwd = document.getElementById("passwordPwd");' . "\n";
	$return .= '	if ( oPwd.value != document.getElementById("passwordPwd2").value ) { alert("Your PassPhrases must match!"); return false; }' . "\n";
	$return .= '	if ( oPwd.value == "" ) { alert("Your PassPhrase must not be empty!"); return false; }' . "\n";
	if (count($admingroups) != $loginInfo['admin']) {
		$return .= '	if ( document.getElementById("username").value.toLowerCase() == document.getElementById("loginname").value.toLowerCase() ) {' . "\n";
		if ($minimumPasswordLen) $return .= '		if (! chkPassLen()) { alert("Your Passphrase must be at least ' . $minimumPasswordLen . ' characters long!"); return false; }' . "\n";
		if ($mustHaveLower) $return .= '		if (! chkPassLower() ) { alert("Your Passphrase must contain at least one lowercase letter!"); return false; }' . "\n";
		if ($mustHaveCapital) $return .= '		if (! chkPassUpper()) { alert("Your Passphrase must contain at least one uppercase letter!"); return false; }' . "\n";
		if ($mustHaveNumber) $return .= '		if (! chkPassNum()) { alert("Your Passphrase must contain at least one number letter!"); return false; }' . "\n";
		if ($minimumScore) $return .= '		if (! chkPassScore()) {	alert("Your Passphrase must be more complex!");return false;}' . "\n";
		if ($differentPass) $return .= '		if (! chkPassDiff()) { alert("Your Passphrase must not be a variation of your old Passphrase!"); return false; }' . "\n";
		$return .= '	}' . "\n";
	}
	$return .= '	alert(oPwd.value.hashCode()); return false;' . "\n";
	$return .= '}' . "\n";
	return $return;
}

function getHeadHTML() {
	global $loginInfo;
	$initial = ($loginInfo['submitted'] != 'Change Passphrase');
	$return = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">' . "\n";
	$return .= '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en"><head><title>Passphrase Change Page</title>' . "\n";
	
	$return .= '<style type="text/css">' . "\n";
	$return .= 'body { font-family: Verdana,Arial,Courier New; font-size: 0.7em;}' . "\n";
	$return .= 'img { height: 150px; border: none;}' . "\n";
	$return .= 'table { width: 500px; margin: 0 auto;}' . "\n";
	if ($initial) $return .= 'form {text-align: center; width: 500px; margin: 5% auto;}' . "\n";
	if ($initial) $return .= 'input {width: 155px;}' . "\n";	
	if ($initial) $return .= 'hr { width: 155px;}' . "\n";
	if ($initial) $return .= 'th { text-align: right; vertical-align:text-top; width: 180px;}' . "\n";
	if ($initial) $return .= 'td { text-align: left; vertical-align:text-top;}' . "\n";
	if (! $initial) $return .= 'th { text-align: right; width: 50%; font-size:1em;}' . "\n";
	if (! $initial) $return .= 'td { text-align: left; width: 50%; font-size:1em;}' . "\n";
	if ($initial) $return .= '.hide { display: none;}' . "\n";
	$return .= '.warning { color:#FF0000; font-weight: bold;}' . "\n";
	$return .= '.good { color:#007700; font-weight: bold;}' . "\n";
	if ($initial) $return .= '.userdetails { text-align: center; width:155px;}' . "\n";
	if ($initial) $return .= '#scorebar {font-size: 85%; font-weight: bold; text-align: center; vertical-align: middle; border: 1px #000 solid; line-height: 18px; height: 18px; width: 155px;}' . "\n";
	$return .= '</style>' . "\n";
	if ($initial) $return .= '<script language="javascript">' . "\n" . writeJavascript() . "</script>\n";
	if ($initial) $return .= '<meta http-equiv="Pragma" content="no-cache"/>' . "\n";
	$return .= '<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head>' . "\n";	
	
	return $return;
}

function getBodyHTML($title) {
	global $corporateLogo, $userInfo, $loginInfo, $ldapDetails;
	$return = '<body><table>' . "\n";
	if ($corporateLogo) $return .= '<tr><td colspan="2" style="text-align: center;" ><img src="' . $corporateLogo . '"/></t1></tr>' . "\n";				
	$return .= '<tr><td colspan="2" style="text-align: center;" ><h1>' . $title . '</h1></t1></tr>' . "\n";
	for ($j = 0; $j < count($ldapDetails); $j++) {
		$return .= '<tr><th>' . $ldapDetails[$j]['name'] . ':</th><td>';
		if ($ldapDetails[$j]['return'] == 'Success (code 0)') $return .= '<div class="good">Success</div>';
		else $return .= '<div class="warning">' . $ldapDetails[$j]['return'] . '</div>';			
		$return .= '</td></tr>' . "\n";
	}
	return $return;
}


// Get all the environment variables.
$loginInfo = array();
// First retrieve all the GET variables.
//$loginInfo['loginname'] = $_GET['loginname'];
//$loginInfo['loginpass'] = $_GET['loginpass'];
//$loginInfo['username'] = $_GET['username'];
//$loginInfo['password'] = $_GET['password'];
//$loginInfo['submitted'] = $_GET['submitted'];

// Second retrieve all the POST variables if not already defined..
//if (isset($_POST['loginname'])) $loginInfo['loginname'] = $_POST['loginname'];
//if (isset($_POST['loginpass'])) $loginInfo['loginpass'] = $_POST['loginpass'];
if (isset($_POST['username'])) $loginInfo['username'] = $_POST['username'];
if (isset($_POST['password'])) $loginInfo['password'] = $_POST['password'];
if (isset($_POST['submitted'])) $loginInfo['submitted'] = $_POST['submitted'];

// Third retrieve the environment variables if not already defined.
if (empty($loginInfo['loginname'])) $loginInfo['loginname'] = $_SERVER['PHP_AUTH_USER'];
if (empty($loginInfo['loginpass'])) $loginInfo['loginpass'] = $_SERVER['PHP_AUTH_PW'];
if (empty($loginInfo['username'])) $loginInfo['username'] = $loginInfo['loginname'];

$loginInfo['uid'] = $loginInfo['loginname'];
$userInfo['uid'] = $loginInfo['username'];


if ($loginInfo['submitted'] != 'Change Passphrase') {
	session_start();		
	getLDAPInfo(0,$loginInfo);

	if ($loginInfo['count'] > 1) {
		echo '<body><h1>More than one login user found</h1></body>';
	} else {
		getLDAPInfo(0,$userInfo);

		if ($userInfo['admin'] > $loginInfo['admin'] or $userInfo['count'] != 1) {
			if ($userInfo['admin'] > $loginInfo['admin']) $warning = "You do not have rights to modify " . $userInfo['uid'] . "'s Passphrase.";
			if ($userInfo['count'] > 1) $warning = "More than one user(" . $userInfo['uid'] . ") was found.";
			if ($userInfo['count'] < 1) $warning = "Sorry, the user(" . $userInfo['uid'] . ") was not found.";
			$loginInfo['username'] = $loginInfo['loginname'];
			$userInfo['uid'] = $loginInfo['loginname'];							
			getLDAPInfo(0,$userInfo);
		}			

		echo "<!--",$loginInfo['loginname'],' is '; if ($warning != '') echo 'not '; echo 'allowed to modify ',$loginInfo['username'],"-->\n";
		
		echo getHeadHTML();
		echo '<body onload="togUserInfo();chkPass();setFocus();">',"\n";
		echo '<form action="',$_SERVER['PHP_SELF'],'" id="passwordChange" method="post" onsubmit="return validateForm();" ><table>',"\n";
		if ($corporateLogo) echo '<tr><td colspan="2" style="text-align: center;" ><img src="',$corporateLogo,'"/></t1></tr>',"\n";
		echo '<tr><td colspan="2" style="text-align: center;" ><h1>Passphrase Change Page</h1></t1></tr></div></td></tr>',"\n";
		echo '<tr><th>Username:</th><td>';
		echo '<input id="loginname" type="hidden" value="',$loginInfo['loginname'],'"/><input id="loginpass" type="hidden" value="',hashCode($loginInfo['loginpass']),'"/><input id="submitteduser" type="hidden" value="',$loginInfo['username'],'"/>';
		echo '<input name="username" id="username" type="text" size="20px" autocomplete="off" value="',$loginInfo['username'],'"';
		if ($loginInfo['admin'] = 0) echo ' readonly=""'; else echo ' onkeyup="togUserInfo();"';
		echo ' tabindex="1"/></td></tr>',"\n";
		if (isset($warning)) echo '<tr><td colspan="2" class="warning" style="text-align: center;" >',$warning,'</td></tr>',"\n";
		$userDetails = buildUserDetails();
		echo '<tr id="uidetails" class=""><th></th><td><div class="userdetails">',$userDetails,'</div>';
		if ($userDetails != '' and (isset($userInfo['expire']) or isset($userInfo['gracelogin']))) echo '<div class="userdetails"><hr/></div>';
		echo '</td></tr>',"\n";
		if (isset($userInfo['expire'])) echo '<tr id="uiexpire" class=""><th>Passphrase Expires:</th><td><div class="userdetails">', $userInfo['expire'], '</div></td></tr>',"\n";
		if (isset($userInfo['gracelimit']) and isset($userInfo['graceremain'])) echo '<tr id="uigracelogin" class=""><th>Grace Logins:</th><td><div class="userdetails">', $userInfo['graceremain'] , ' out of ' , $userInfo['gracelimit'], ' remaining</div></td></tr>',"\n";
		echo '<tr id="newpassword"><th>New Passphrase:</th><td>',"\n";
		echo '  <input id="passwordPwd" name="password" size="20px" autocomplete="off" onkeyup="chkPass(this.value);passwordTxt.value=this.value;" class="" type="password" value="" tabindex="2"/>',"\n";
		echo '  <input id="passwordTxt" size="20px" autocomplete="off" onkeyup="chkPass(this.value);passwordPwd.value=this.value;" class="hide" type="text" value="" tabindex="3"/>',"\n";
		echo '&nbsp;Hide:<input id="mask" type="checkbox" value="1" checked="checked" onclick="togPwdMask();" tabindex="-1" style="width: 15px;"/></td></tr>',"\n";
		echo '<tr id="complexity"><th>Complexity:</th><td><input name="score" id="score" type="hidden" value=""><div id="scorebar">0%&nbsp;&nbsp;Too Short</div></td></tr>',"\n";
//		echo '<tr id="rules"><th></th><td><div style="text-align: left; width:200px;">',"\n";
		echo '<tr id="rules"><th></th><td><div style="text-align: left;">',"\n";		
		if ( $minimumPasswordLen ) echo '<li id="pwlength" class="">At least ', $minimumPasswordLen, ' characters long</li>',"\n";
		if ( $mustHaveCapital ) echo '<li id="pwcapital" class="">Have one capital letter</li>',"\n";
		if ( $mustHaveLower ) echo '<li id="pwlower" class="">Have one lowercase letter</li>',"\n";
		if ( $mustHaveNumber ) echo '<li id="pwnumber" class="">Have one number</li>',"\n";
		if ( $minimumScore ) echo '<li id="pwscore" class="">Have a score greater than ',$minimumScore,'</li>',"\n";
		if ($loginInfo['username'] == $loginInfo['loginname']) echo '<li id="pwsame" class="">Must not be the same as your old<br/>Passphrase.</li>';
		echo '</div></td></tr>',"\n";	
		echo '<tr id="newpassword2"><th>Retype Passphrase:</th><td>',"\n";
		echo '  <input id="passwordPwd2" size="20px" autocomplete="off" onkeyup="passwordTxt2.value=this.value;" class="" type="password" value="" tabindex="4"/>',"\n";
		echo '  <input id="passwordTxt2" size="20px" autocomplete="off" onkeyup="passwordPwd2.value=this.value;"class="hide" type="text" value="" tabindex="5"/>',"\n";
		echo '</td></tr>',"\n";
		echo '<tr><td style="text-align: center;" colspan="2"><input id="submitted" name="submitted" type="submit" value="Change Passphrase" tabindex="6"/></td></tr>',"\n";
		echo '</table></form></body>',"\n";
		echo '</html>';
	}
} elseif ($loginInfo['submitted'] == 'Change Passphrase') {
	getLDAPInfo(0,$loginInfo);
	getLDAPInfo(0,$userInfo);

	changePassword();

	$headHTML = getHeadHTML();
	echo $headHTML;

	echo '<body><table>', "\n";
	if ($corporateLogo) echo '<tr><td colspan="2" style="text-align: center;" ><img src="', $corporateLogo, '"/></t1></tr>', "\n";			
	echo '<tr><td colspan="2" style="text-align: center;" ><h1>Changing Passphrase for<br/>', $loginInfo['username'], ' (', $userInfo['fullname'], ')</h1></t1></tr>', "\n";
	for ($j = 0; $j < count($ldapDetails); $j++) {
		echo '<tr><th>', $ldapDetails[$j]['name'], ':</th><td>';
		if ($ldapDetails[$j]['return'] == 'Success (code 0)') echo '<div class="good">Success</div>';
		else echo '<div class="warning">', $ldapDetails[$j]['return'], '</div>';		
		echo '</td></tr>', "\n";
	}

	if ($userInfo['email']) {
		echo '<tr><th>Email Sent:</th>';
		$mail->AddAddress($userInfo['email'], $userInfo['fullname']);
		
		if (strtolower($loginInfo['loginname']) == strtolower($loginInfo['username'])) $mail->Subject = "Your (" . $loginInfo['username'] . ") Network Passphrase has been changed.";
		else $mail->Subject = "Your (" . $loginInfo['username'] . ") Network Passphrase has been changed by " . $loginInfo['loginname'] . '(' . $loginInfo['fullname'] . ')';
			
		$htmlmsg = $headHTML . '<!--   Username = ' . $loginInfo['username'] . " -->\n";
		$htmlmsg .= '<!--   Password = ' . $loginInfo['password'] . " -->\n";
		if (strtolower($loginInfo['loginname']) != strtolower($loginInfo['username'])) $htmlmsg .= '<!-- Changed By = ' . $loginInfo['uid'] . '(' . $loginInfo['fullname'] . ") -->\n";
		$htmlmsg .= '<body style="font-family: Verdana,Arial,Courier New; font-size: 0.7em;"><div width="100% align="center"><table style="width: 500px; margin: 0 auto;">';
		$htmlmsg .= '<tr><td colspan="2" style="text-align: center;" ><img src="' . $corporateLogo . '" style="height: 150px;"/></t1></tr>';
		$htmlmsg .= '<tr><td colspan="2" style="text-align: center; font-size:1em;" >Your (' . $loginInfo['username'] . ') Network Passphrase have been changed on the following systems:</t1></tr>';
		$msg = "Network Passphrase Change Notice\nYour(" . $loginInfo['username'] . ") Network Passphrase has been changed by " . $loginInfo['loginname'] . "\n";
		for ($j = 0; $j < count($ldapDetails); $j++) {
			if ($ldapDetails[$j]['return'] == 'Success (code 0)') {
				$htmlmsg .= '<tr><th style="text-align: right; width: 50%; font-size:1em;">' . $ldapDetails[$j]['name'] . ':</th><td>' . '<div style="color:green; font-weight: bold;">Success</div>' . "</td></tr>\n";
				$msg .= $ldapDetails[$j]['name'] . ": Success\n";
			} else {
				$htmlmsg .= '<tr><th style="text-align: right; width: 50%; font-size:1em;">' . $ldapDetails[$j]['name'] . ':</th><td>' . '<div style="color:red; font-weight: bold;">' . $ldapDetails[$j]['return'] . '</div>' . "</td></tr>\n";
				$msg .= $ldapDetails[$j]['name'] . ": " . $ldapDetails[$j]['return'] . "\n";
			}			
		}
		$htmlmsg .= '</table></div></body></html>';
	
		$mail->Body    = $htmlmsg;
		$mail->AltBody = $msg;

		if ($mail->Send()) echo '<td><div class="good">',$userInfo['email'],'</div></td></tr>',"\n";
		else echo '<td><div class="warning">',$mail->ErrorInfo,'</div></td></tr>',"\n";
	}
	
	if (strtolower($loginInfo['username']) != strtolower($loginInfo['loginname'])) {
		echo '<tr><th>&nbsp;</th><td>&nbsp;</td></tr>',"\n";
		echo '<tr><td style="text-align: center;" colspan="2"><input id="continue" type="submit" value="Change Another Passphrase" onclick="location.href=',"'",$_SERVER['PHP_SELF'],"'",'"/></td></tr>',"\n";
	}
	echo '</table></body>',"\n";
	echo '</html>';
}
?>
