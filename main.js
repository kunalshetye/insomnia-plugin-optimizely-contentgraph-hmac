const CryptoJS = require('crypto-js');

function generateHMACKey(key, secretKey, body_str, method, target) {
    var secret = CryptoJS.enc.Base64.parse(secretKey);
    var timestamp = (new Date()).getTime();
    var nonce = Math.random().toString(36).substring(7);
    var body = "";
    body = body_str;
    //console.log("body: " + body);
    var bodybase64 = CryptoJS.MD5(body).toString(CryptoJS.enc.Base64);
    //console.log("body-hash: "+bodybase64);
    var message = key + method + target + timestamp + nonce + bodybase64;
    //console.log("message: "+message);
    var hmac = CryptoJS.HmacSHA256(message, secret);
    var base64hmac = CryptoJS.enc.Base64.stringify(hmac);
    var hmacKey = "epi-hmac " + key + ":" + timestamp +":" + nonce + ":" + base64hmac;
    return hmacKey;
}

// A request hook will be run before sending the request to API, but after everything else is finalized
module.exports.requestHooks = [
    (context) => {
      const req = context.request;
      const appKey = req.getEnvironmentVariable("AppKey");
      const appSecret = req.getEnvironmentVariable("Secret");
      const target = req.getUrl().replace(req.getEnvironmentVariable("GatewayAddress"),"");
      //console.log(`appKey: ${appKey}`);
      //console.log(`appSecret: ${appSecret}`);
      //console.log(`target: ${target}`);
      if(target.indexOf('auth=') == -1) { // only add hmac if auth parameter is missing
        const hmac = generateHMACKey(appKey,appSecret, req.getBody().text, req.getMethod(), target);
        //console.log("hmac " + hmac);
        req.setHeader("Authorization", hmac); 
      }
    }
  ];