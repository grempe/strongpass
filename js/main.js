function computePassword(basePassPhrase, username, siteUri, extraSalt) {
  var zxcvbnResult, pbkdf2Rounds, pbkdf2KeyLen, hostname,
      hostnameValid, salt, pbkdf2Key, pbkdf2KeyBase64,
      pbkdf2KeyBase64Len, password, passwordEntropy;

  pbkdf2Rounds = 25000;    // number of PBKDF2 rounds
  pbkdf2KeyLen = 32;       // output key length in bytes
  pbkdf2KeyBase64Len = 24; // the generated password is the first n chars of pbkdf2Key Base64 output

  // Estimate base password entropy with ZXCVBN
  // https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/
  // https://dl.dropboxusercontent.com/u/209/zxcvbn/test/index.html
  zxcvbnResult = zxcvbn(basePassPhrase);

  host = extractHostFromUri(siteUri);

  if (zxcvbnResult.score >= 4 && username.length >= 1 && host) {
    // Compose a consistent salt and convert it to a Uint8Array of Bytes
    if (extraSalt.length >= 1) {
        salt = nacl.util.decodeUTF8(username + '@' + host + ':' + extraSalt);
    } else {
        salt = nacl.util.decodeUTF8(username + '@' + host);
    }

    // Derive a cryptographically strong PBKDF2 key (password) as a Uint8Array of Bytes
    pbkdf2Key = sha256.pbkdf2(nacl.util.decodeUTF8(basePassPhrase), salt, pbkdf2Rounds, pbkdf2KeyLen);

    // Base64 encode the PBKDF2 key.
    pbkdf2KeyBase64 = nacl.util.encodeBase64(pbkdf2Key);

    // Take only the first N bytes of the generated password.
    password = pbkdf2KeyBase64.substring(0, pbkdf2KeyBase64Len);

    // calc the estimated entropy of the generated password.
    zxcvbnForPassword = zxcvbn(password);

    return {username: username, host: host, password: password, passwordEntropy: zxcvbnForPassword.entropy};
  } else {
    return null;
  }
}

function extractHostFromUri(uri) {
    var domainMatcher = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    var ipMatcher = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    // Extract the domain portion of the site URI
    // URI Parser : https://github.com/derek-watson/jsUri
    host = new Uri(uri).host();

    if (host && domainMatcher.test(host)) {
      return host;
    } else if (host && ipMatcher.test(host)) {
      return host;
    } else {
      return null;
    }
}

function computeSaltInWords(username, domain, extraSalt) {
  if (username && domain && extraSalt.length >= 1) {
    return username + '@' + domain + ':*****';
  } else if (username && domain && extraSalt === '') {
    return username + '@' + domain;
  } else {
    return null;
  }
}

// https://stackoverflow.com/questions/1909441/jquery-keyup-delay
var delay = (function(){
  var timer = 0;
  return function(callback, ms){
    clearTimeout (timer);
    timer = setTimeout(callback, ms);
  };
})();

$(document).ready(function () {
    'use strict';

    $("#passwordOutputContainer").hide();

    // https://github.com/ablanco/jquery.pwstrength.bootstrap
    $('#keyPassphraseInput').pwstrength({
        ui: {
            showVerdictsInsideProgressBar: true
        },
        common: {
            zxcvbn: true,
            zxcvbnTerms: ['secret', 'password'],
            userInputs: ['#usernameInput', '#domainInput', '#tokenInput']
        }
    });

    $('.form-control').on('keyup', function () {

        // delay execution for 500ms after keyups stop.
        delay(function(){
            // force password strength update
            $("#keyPassphraseInput").pwstrength("forceUpdate");

            var basePassphrase = $('#keyPassphraseInput').val();
            var username = $('#usernameInput').val();
            var siteUri = $('#domainInput').val();
            var extraSalt = $('#tokenInput').val();

            var passwordObj = computePassword(basePassphrase, username, siteUri, extraSalt);

            if (passwordObj && passwordObj.username && passwordObj.host && passwordObj.password) {
                $("#passwordOutput").text(passwordObj.password);
                $("#passwordEntropy").text(passwordObj.passwordEntropy);
                $("#sanitizedSaltInWords").text(computeSaltInWords(passwordObj.username, passwordObj.host, extraSalt));
                $("#passwordOutputContainer").slideDown();
            } else {
                $("#passwordOutput").text('');
                $("#sanitizedSaltInWords").text('');
                $("#passwordOutputContainer").slideUp();
            }
        }, 400 );

    });

});
