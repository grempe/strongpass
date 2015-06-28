function computePassword(basePassPhrase, usernameOrAppname, siteUri, version, extraSalt) {

  // trim leading and trailing whitespace from all fields
  basePassPhrase = $.trim(basePassPhrase);
  usernameOrAppname = $.trim(usernameOrAppname);
  siteUri = $.trim(siteUri);
  version = $.trim(version);
  extraSalt = $.trim(extraSalt);

  // normalize the non-secret params
  // some browsers, especially on mobile, will auto-capitalize
  // which will change the password results.
  usernameOrAppname = usernameOrAppname.toLowerCase();
  siteUri = siteUri.toLowerCase();
  version = parseInt(version);

  // Estimate base password entropy with ZXCVBN
  // https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/
  // https://dl.dropboxusercontent.com/u/209/zxcvbn/test/index.html
  var zxcvbnPassphrase = zxcvbn(basePassPhrase);

  var host = extractHostFromUri(siteUri);

  if (zxcvbnPassphrase.score >= 4 && usernameOrAppname.length >= 1 && host && version >= 1) {

      // Generate a master key w/ HMAC-SHA-256, from passphrase and username
      var passPhraseUint8 = nacl.util.decodeUTF8(basePassPhrase);                       // Byte Array
      var usernameOrAppnameUint8 = nacl.util.decodeUTF8(usernameOrAppname);             // Byte Array
      var usernameOrAppnameHashedUint8 = nacl.hash(usernameOrAppnameUint8);             // SHA-512, 64 Bytes
      var masterKeyUint8 = sha256.hmac(passPhraseUint8, usernameOrAppnameHashedUint8);  // SHA-256 HMAC, 32 Bytes

      // Construct a salt for PBKDF2 and pass it through SHA-512
      var paramsCombined = usernameOrAppname + '@' + host + ':v' + version + ':' + extraSalt; // String
      var paramsCombinedUint8 = nacl.util.decodeUTF8(paramsCombined);                         // Byte Array
      var pbkdf2SaltUint8 = nacl.hash(paramsCombinedUint8);                                   // SHA-512, 64 Bytes

      // Pass h(passphrase, usernameOrAppname) as masterKeyUint8
      // Pass h(usernameOrAppname | host | version | extraSalt) as pbkdf2SaltUint8
      // 25,000 rounds
      // Output 32 Bytes
      var pbkdf2Uint8 = sha256.pbkdf2(masterKeyUint8, pbkdf2SaltUint8, 25000, 32);  // PBKDF2, 32 Bytes

      // calculate a symbol from last byte
      var lastByte = pbkdf2Uint8[31];
      var symbols = ['!', '@', '#', '$', '%', '?', '&', '*', '+', '-'];
      var symbolIndexForByte = lastByte % 10;
      var chosenSymbol = symbols[symbolIndexForByte];

      // calculate a number from second to last byte
      var secondToLastByte = pbkdf2Uint8[30];
      var numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
      var numberIndexForByte = secondToLastByte % 10;
      var chosenNumber = numbers[numberIndexForByte];

      // Convert the PBKDF2 output to Base 64 (does not include extra number or symbol yet)
      var pbkdf2Base64 = nacl.util.encodeBase64(pbkdf2Uint8);                       // Base 64 String

      // Take only the first N bytes of the Base 64 encoded password as the final password.
      // Append a deterministically chosen symbol and number to ensure meeting most password requirements
      var password = pbkdf2Base64.substring(0, 18) + chosenSymbol + chosenNumber;  // Partial Base 64 String

      // Calc the estimated entropy of the final encoded password.
      var zxcvbnPassword = zxcvbn(password);

      return {usernameOrAppname: usernameOrAppname, host: host, password: password,
              passphraseEntropy: zxcvbnPassphrase.entropy,
              passwordEntropy: zxcvbnPassword.entropy};
  } else {
      return null;
  }
}

// http://www.example.com/foo/index.html => www.example.com
// http://127.0.0.1/foo/index.html => 127.0.0.1
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

function computeSaltInWords(usernameOrAppname, domain, version, extraSalt) {
  if (usernameOrAppname && domain && version >= 1 && extraSalt.length >= 1) {
    return usernameOrAppname + '@' + domain + ':v' + version + ':*****';
  } else if (usernameOrAppname && domain && version >= 1 && extraSalt === '') {
    return usernameOrAppname + '@' + domain + ':v' + version ;
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

function updatePasswordOutputContainer() {

    // delay execution for 500ms after keyups stop.
    delay(function(){
        // force password strength update
        $("#keyPassphraseInput").pwstrength("forceUpdate");

        var basePassphrase = $('#keyPassphraseInput').val();
        var usernameOrAppname = $('#usernameOrAppnameInput').val();
        var siteUri = $('#domainInput').val();
        var version = $('#versionInput').val();
        var extraSalt = $('#tokenInput').val();

        var passwordObj = computePassword(basePassphrase, usernameOrAppname, siteUri, version, extraSalt);

        if (passwordObj && passwordObj.usernameOrAppname && passwordObj.host && passwordObj.password) {
            $("#passwordOutput").text(passwordObj.password);
            $("#passwordEntropy").text(passwordObj.passwordEntropy);
            $("#sanitizedSaltInWords").text(computeSaltInWords(passwordObj.usernameOrAppname, passwordObj.host, version, extraSalt));
            $("#passwordOutputContainer").slideDown();
        } else {
            $("#passwordOutput").text('');
            $("#sanitizedSaltInWords").text('');
            $("#passwordOutputContainer").slideUp();
        }
    }, 400 );

}

$(document).ready(function () {
    'use strict';

    $("#passwordOutputContainer").hide();

    // Configure the password strength meter.
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

    // All form control elements keyup
    $('.form-control').on('keyup', function () {
        updatePasswordOutputContainer();
    });

    // Special handling for the HTML5 scroll arrows for a number field
    // https://stackoverflow.com/questions/5669207/html5-event-listener-for-number-input-scroll-chrome-only
    $('#versionInput').click(function(){
        updatePasswordOutputContainer();
    });

    $('#versionInput').change(function(){
        updatePasswordOutputContainer();
    });

    $('#versionInput').keypress(function(){
        updatePasswordOutputContainer();
    });

});
