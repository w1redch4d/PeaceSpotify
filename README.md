## Description 
This is an attempt to block ads from spotify via [DLL Proxying](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)

## How it works
The call to `cef_urlrequest_create` is replaced with a custom function that blocks urls which can lead to the playing of ads, and it redirects the other URLs to the original function.
the source code of the redirected functions resides [here](https://github.com/w1redch4d/PeaceSpotify/blob/main/PeaceSpotify/redir.h) , the custom function code resides [here](https://github.com/w1redch4d/PeaceSpotify/blob/ce8777259f7b15637d0219fa36549e71d8833b70/PeaceSpotify/peace.cpp#L42)
and the redirect generator code resides [here](https://github.com/w1redch4d/PeaceSpotify/blob/main/script/export.bat)

## Installation
1. Go to %APPDATA%\Spotify and rename the libcef.dll that resides there to libcef_orig.dll
2. Download the libcef.dll from releases in this github repository
3. copy the downloaded libcef.dll to %APPDATA%\Spotify
4. Launch Spotify

## References 
[CEF](https://cef-builds.spotifycdn.com/docs/105.3/index.html)
[Linux version](https://github.com/abba23/spotify-adblock)
