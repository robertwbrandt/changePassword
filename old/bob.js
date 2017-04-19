function chkPassLen() { minLength = 10; var oPwd = document.getElementById("passwordPwd"); return (oPwd.value.length >= minLength); }
function chkPassLower() { var oPwd = document.getElementById("passwordPwd");	return (oPwd.value.match(/[a-z]/) != null); }
function chkPassUpper() { var oPwd = document.getElementById("passwordPwd");	return (oPwd.value.match(/[A-Z]/) != null); }
function chkPassNum() { var oPwd = document.getElementById("passwordPwd");	return (oPwd.value.match(/[0-9]/) != null); }
function chkPassScore() { minScore = 50; var oScore = document.getElementById("score"); return (oScore.value >= minScore); }
function chkPassDiff() {
	var oPwd = document.getElementById("passwordPwd");
	var oOrig = document.getElementById("loginpass");	
	sPwd = oPwd.value.replace(/\s+/g, '').replace(/[0-9]+/g, '').toLowerCase();
	sOrig = oOrig.value.replace(/\s+/g, '').replace(/[0-9]+/g, '').toLowerCase();
	return ( sPwd != sOrig );
}

String.prototype.strReverse = function() {
	var newstring = "";
	for (var s=0; s < this.length; s++) newstring = this.charAt(s) + newstring;
	return newstring;
};

function chkPass(pwd) {
	// Simultaneous variable declaration and value assignment aren't supported in IE apparently
	// so I'm forced to assign the same value individually per var to support a crappy browser *sigh* 
	var nScore=0, nLength=0, nAlphaUC=0, nAlphaLC=0, nNumber=0, nSymbol=0, nMidChar=0, nRequirements=0, nAlphasOnly=0, nNumbersOnly=0, nUnqChar=0, nRepChar=0, nRepInc=0, nConsecAlphaUC=0, nConsecAlphaLC=0, nConsecNumber=0, nConsecSymbol=0, nConsecCharType=0, nSeqAlpha=0, nSeqNumber=0, nSeqSymbol=0, nSeqChar=0, nReqChar=0, nMultConsecCharType=0;
	var nMultRepChar=1, nMultConsecSymbol=1;
	var nMultMidChar=2, nMultRequirements=2, nMultConsecAlphaUC=2, nMultConsecAlphaLC=2, nMultConsecNumber=2;
	var nReqCharType=3, nMultAlphaUC=3, nMultAlphaLC=3, nMultSeqAlpha=3, nMultSeqNumber=3, nMultSeqSymbol=3;
	var nMultLength=4, nMultNumber=4, nMultSymbol=6;
	var nTmpAlphaUC="", nTmpAlphaLC="", nTmpNumber="", nTmpSymbol="";
	var sAlphas = "abcdefghijklmnopqrstuvwxyz";
	var sNumerics = "01234567890";
	var sSymbols = ")!@#$%^&*()";
	var sComplexity = "Too Short";
	var nMinPwdLen = 10;
	if (document.all) { var nd = 0; } else { var nd = 1; }
	if (pwd) {
		nScore = parseInt(pwd.length * nMultLength);
		nLength = pwd.length;
		var arrPwd = pwd.replace(/\s+/g,"").split(/\s*/);
		var arrPwdLen = arrPwd.length;
		
		/* Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */
		for (var a=0; a < arrPwdLen; a++) {
			if (arrPwd[a].match(/[A-Z]/g)) {
				if (nTmpAlphaUC !== "") { if ((nTmpAlphaUC + 1) == a) { nConsecAlphaUC++; nConsecCharType++; } }
				nTmpAlphaUC = a;
				nAlphaUC++;
			}
			else if (arrPwd[a].match(/[a-z]/g)) { 
				if (nTmpAlphaLC !== "") { if ((nTmpAlphaLC + 1) == a) { nConsecAlphaLC++; nConsecCharType++; } }
				nTmpAlphaLC = a;
				nAlphaLC++;
			}
			else if (arrPwd[a].match(/[0-9]/g)) { 
				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
				if (nTmpNumber !== "") { if ((nTmpNumber + 1) == a) { nConsecNumber++; nConsecCharType++; } }
				nTmpNumber = a;
				nNumber++;
			}
			else if (arrPwd[a].match(/[^a-zA-Z0-9_]/g)) { 
				if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
				if (nTmpSymbol !== "") { if ((nTmpSymbol + 1) == a) { nConsecSymbol++; nConsecCharType++; } }
				nTmpSymbol = a;
				nSymbol++;
			}
			/* Internal loop through password to check for repeat characters */
			var bCharExists = false;
			for (var b=0; b < arrPwdLen; b++) {
				if (arrPwd[a] == arrPwd[b] && a != b) { /* repeat character exists */
					bCharExists = true;
					/* 
					Calculate increment deduction based on proximity to identical characters
					Deduction is incremented each time a new match is discovered
					Deduction amount is based on total password length divided by the
					difference of distance between currently selected match
					*/
					nRepInc += Math.abs(arrPwdLen/(b-a));
				}
			}
			if (bCharExists) { 
				nRepChar++; 
				nUnqChar = arrPwdLen-nRepChar;
				nRepInc = (nUnqChar) ? Math.ceil(nRepInc/nUnqChar) : Math.ceil(nRepInc); 
			}
		}
		
		/* Check for sequential alpha string patterns (forward and reverse) */
		for (var s=0; s < 23; s++) {
			var sFwd = sAlphas.substring(s,parseInt(s+3));
			var sRev = sFwd.strReverse();
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqAlpha++; nSeqChar++;}
		}
		
		/* Check for sequential numeric string patterns (forward and reverse) */
		for (var s=0; s < 8; s++) {
			var sFwd = sNumerics.substring(s,parseInt(s+3));
			var sRev = sFwd.strReverse();
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqNumber++; nSeqChar++;}
		}

		/* Check for sequential symbol string patterns (forward and reverse) */
		for (var s=0; s < 8; s++) {
			var sFwd = sSymbols.substring(s,parseInt(s+3));
			var sRev = sFwd.strReverse();
			if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqSymbol++; nSeqChar++;}
		}
		
	/* Modify overall score value based on usage vs requirements */

		/* General point assignment */
		if (nAlphaUC > 0 && nAlphaUC < nLength) nScore = parseInt(nScore + ((nLength - nAlphaUC) * 2));
		if (nAlphaLC > 0 && nAlphaLC < nLength) nScore = parseInt(nScore + ((nLength - nAlphaLC) * 2));
		if (nNumber > 0 && nNumber < nLength) nScore = parseInt(nScore + (nNumber * nMultNumber));
		if (nSymbol > 0) nScore = parseInt(nScore + (nSymbol * nMultSymbol));
		if (nMidChar > 0) nScore = parseInt(nScore + (nMidChar * nMultMidChar));
		
		/* Point deductions for poor practices */
		// Only Letters
		if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol === 0 && nNumber === 0) nScore = parseInt(nScore - nLength);
		// Only Numbers
		if (nAlphaLC === 0 && nAlphaUC === 0 && nSymbol === 0 && nNumber > 0) nScore = parseInt(nScore - nLength);
		// Same character exists more than once
		if (nRepChar > 0) nScore = parseInt(nScore - nRepInc);
		// Consecutive Uppercase Letters exist
		if (nConsecAlphaUC > 0) nScore = parseInt(nScore - (nConsecAlphaUC * nMultConsecAlphaUC));
		// Consecutive Lowercase Letters exist 
		if (nConsecAlphaLC > 0) nScore = parseInt(nScore - (nConsecAlphaLC * nMultConsecAlphaLC));
		// Consecutive Numbers exist
		if (nConsecNumber > 0) nScore = parseInt(nScore - (nConsecNumber * nMultConsecNumber));  
		// Sequential alpha strings exist (3 characters or more)		
		if (nSeqAlpha > 0) nScore = parseInt(nScore - (nSeqAlpha * nMultSeqAlpha)); 
		// Sequential numeric strings exist (3 characters or more)		
		if (nSeqNumber > 0) nScore = parseInt(nScore - (nSeqNumber * nMultSeqNumber));
		// Sequential symbol strings exist (3 characters or more)		
		if (nSeqSymbol > 0) nScore = parseInt(nScore - (nSeqSymbol * nMultSeqSymbol));

		/* Determine if mandatory requirements have been met and set image indicators accordingly */
		nRequirements = nReqChar;
		if (pwd.length >= nMinPwdLen) { var nMinReqChars = 3; } else { var nMinReqChars = 4; }
		if (nRequirements > nMinReqChars) nScore = parseInt(nScore + (nRequirements * 2));

		/* Determine complexity based on overall score */
		if (nScore > 100) { nScore = 100; } else if (nScore < 0) { nScore = 0; }
		if (nScore >= 0 && nScore < 20) { sComplexity = "Very Weak"; }
		else if (nScore >= 20 && nScore < 40) { sComplexity = "Weak"; }
		else if (nScore >= 40 && nScore < 60) { sComplexity = "Good"; }
		else if (nScore >= 60 && nScore < 80) { sComplexity = "Strong"; }
		else if (nScore >= 80 && nScore <= 100) { sComplexity = "Very Strong"; }
	}

	/* Display updated score criteria to client */
	var oScorebar = document.getElementById("scorebar");
	var oScore = document.getElementById("score");
	if (nScore < 50) {
		red = 255;
		blue = 0;
		green = 255 * (nScore/50);
	} else {
		red = 255 - 255 * ((nScore-50)/50);
		green = 255 - 128 * ((nScore-50)/50);
		blue = 50 - 50 * Math.abs((nScore-75)/25);
	}
	oScorebar.innerHTML = nScore + "%&nbsp;&nbsp;" + sComplexity;
	oScorebar.style.backgroundColor = "rgb(" + parseInt(red) + " ," + parseInt(green) + " ," + parseInt(blue) + ")";
	oScore.value = nScore

	if (document.getElementById("pwlength")) document.getElementById("pwlength").className = chkPassLen() ? "good" : "warning";
	if (document.getElementById("pwlower")) document.getElementById("pwlower").className = chkPassLower() ? "good" : "warning";
	if (document.getElementById("pwcapital")) document.getElementById("pwcapital").className = chkPassUpper() ? "good" : "warning";		
	if (document.getElementById("pwnumber")) document.getElementById("pwnumber").className = chkPassNum() ? "good" : "warning";
	if (document.getElementById("pwscore")) document.getElementById("pwscore").className = chkPassScore() ? "good" : "warning";
	if (document.getElementById("pwsame")) document.getElementById("pwsame").className = chkPassDiff() ? "good" : "warning";
}

function togPwdMask() {
	var oPwd = document.getElementById("passwordPwd");
	var oTxt = document.getElementById("passwordTxt");
	var oPwd2 = document.getElementById("passwordPwd2");
	var oTxt2 = document.getElementById("passwordTxt2");
	var oMask = document.getElementById("mask");
	if (oMask.checked) { 
		oPwd.value = oTxt.value;
		oPwd.className = ""; 
		oTxt.className = "hide"; 
		oPwd2.value = oTxt2.value;
		oPwd2.className = ""; 
		oTxt2.className = "hide"; 
	} 
	else { 
		oTxt.value = oPwd.value;
		oPwd.className = "hide"; 
		oTxt.className = "";
		oTxt2.value = oPwd2.value;
		oPwd2.className = "hide"; 
		oTxt2.className = "";
	}
}

function togUserInfo() {
	var oBtn = document.getElementById("submitted");
	var oSubmitted = document.getElementById("submitteduser");
	var oEntered = document.getElementById("username");
	sBtn = "Verify Username";
	sDiv = "hide";

	if (oSubmitted.value.toLowerCase() == oEntered.value.toLowerCase()) { sBtn = "Change Passphrase"; }
	if (oSubmitted.value.toLowerCase() == oEntered.value.toLowerCase()) { sDiv = ""; }	 

	oBtn.value = sBtn;
	if (document.getElementById("uidetails")) document.getElementById("uidetails").className = sDiv;	
	if (document.getElementById("uiexpire")) document.getElementById("uiexpire").className = sDiv;
	if (document.getElementById("uigracelogin")) document.getElementById("uigracelogin").className = sDiv;
	if (document.getElementById("newpassword")) document.getElementById("newpassword").className = sDiv;
	if (document.getElementById("complexity")) document.getElementById("complexity").className = sDiv;
	if (document.getElementById("rules")) document.getElementById("rules").className = sDiv;
	if (document.getElementById("newpassword2")) document.getElementById("newpassword2").className = sDiv;					
}

function setFocus(){
	document.getElementById("passwordPwd").focus();
}

function validateForm() {
	var oSubmitted = document.getElementById("submitted");
	if ( oSubmitted.value != "Change Passphrase" ) return true; 

	var oLoginAdmin = document.getElementById("loginadmin");
	var oLogin = document.getElementById("loginname");
	var oEntered = document.getElementById("username");
	var oPwd = document.getElementById("passwordPwd");
	var oPwd2 = document.getElementById("passwordPwd2");
		
	if ( oPwd.value != oPwd2.value ) { alert("Your PassPhrases must match!"); return false; }
	if ( oPwd.value == "" ) { alert("Your PassPhrase must not be empty!"); return false; }	
	//Check this in the final.
	if ( !(oLoginAdmin.checked) || oLogin.value == oEntered.value ) {
		if (! chkPassLen()) { alert("Your Passphrase must be at least 10 characters long!"); return false; }
		if (! chkPassLower() ) { alert("Your Passphrase must contain at least one lowercase letter!"); return false; }
		if (! chkPassUpper()) { alert("Your Passphrase must contain at least one uppercase letter!"); return false; }
		if (! chkPassNum()) { alert("Your Passphrase must contain at least one number letter!"); return false; }
		if (! chkPassScore()) {	alert("Your Passphrase must be more complex!");	return false;	}
		if (! chkPassDiff()) { alert("Your Passphrase must not be a variation of your old Passphrase!"); return false; }
	}

	alert("Form Verification Passed!");
	return false;
}