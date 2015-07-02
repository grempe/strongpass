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
      var passPhraseUint8 = nacl.util.decodeUTF8(basePassPhrase);                          // Byte Array
      var usernameOrAppnameUint8 = nacl.util.decodeUTF8(usernameOrAppname);                // Byte Array
      var usernameOrAppnameHashedUint8 = nacl.hash(usernameOrAppnameUint8);                // SHA-512, 64 Bytes
      var masterKeyUint8 = nacl.auth.full(passPhraseUint8, usernameOrAppnameHashedUint8);  // HMAC-SHA-512, 64 Bytes

      // Construct a salt for key derivation and pass it through SHA-512
      var paramsCombined = usernameOrAppname + '@' + host + ':v' + version + ':' + extraSalt; // String
      var paramsCombinedUint8 = nacl.util.decodeUTF8(paramsCombined);                         // Byte Array
      var kdSaltUint8 = nacl.hash(paramsCombinedUint8);                                       // SHA-512, 64 Bytes

      // scrypt : https://www.tarsnap.com/scrypt.html
      //
      // On choosing optimal work factors:
      // https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
      //
      // masterKeyUint8 = h(passphrase, usernameOrAppname)
      // kdSaltUint8 = h(usernameOrAppname | host | version | extraSalt)
      // L bytes of derived key material from a password passwd and a salt salt
      // N, which must be a power of two, which will set the overall difficulty
      //   of the computation. The scrypt paper uses 2^14 = 16384 for interactive
      //   logins, and 2^20 = 1048576 for file encryption, but running in the
      //   browser is slow so Your Mileage Will Almost Certainly Vary.
      // r and p. r is a factor to control the blocksize for each mixing
      //   loop (memory usage). p is a factor to control the number of
      //   independent mixing loops (parallelism). Good values are
      //   r = 8 and p = 1. See the scrypt paper for details on these parameters.
      //   Choose wisely! Picking good values for N, r and p is important for
      //   making your keys sufficiently hard to brute-force.
      //
      var scrypt = scrypt_module_factory();
      var N = 16384; // 2^14 : 128×16384×8 = 16,777,216 bytes = 16 MB RAM, 16384 iterations.
      var r = 8;     //
      var p = 1;     //
      var L = 32;    // Output Bytes
      var kdBytesUint8 = scrypt.crypto_scrypt(masterKeyUint8, kdSaltUint8, N, r, p, L);

      // calculate a symbol from last byte to ensure every generated password
      // has at least one symbol since the Base64 output doesn't guarantee.
      var lastByte = kdBytesUint8[31];
      var symbols = ['!', '@', '#', '$', '%', '?', '&', '*', '+', '-'];
      var symbolIndexForByte = lastByte % 10;
      var chosenSymbol = symbols[symbolIndexForByte];

      // calculate a number from second to last byte to ensure every generated
      // password has at least one number since the Base64 output doesn't guarantee.
      var secondToLastByte = kdBytesUint8[30];
      var numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
      var numberIndexForByte = secondToLastByte % 10;
      var chosenNumber = numbers[numberIndexForByte];

      // Convert the key derivation function output to Base 64 (does not include
      // extra number or symbol yet)
      var kdBytesBase64 = nacl.util.encodeBase64(kdBytesUint8); // Base 64 String

      // Take only the first N bytes of the Base 64 encoded password as the final password.
      // Append a deterministically chosen symbol and number to ensure meeting most password requirements
      var password = kdBytesBase64.substring(0, 18) + chosenSymbol + chosenNumber; // Partial Base 64 String

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
