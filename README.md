[![GitHub version](https://badge.fury.io/gh/boennemann%2Fbadges.svg)](http://badge.fury.io/gh/boennemann%2Fbadges) [![GPL Licence](https://badges.frapsoft.com/os/gpl/gpl.svg?v=103)](https://opensource.org/licenses/GPL-2.0/) [![Open Source Love](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
# h2rs

Detects request smuggling via HTTP/2 downgrades.

# Requirements

* Python 3.x

## Python Modules

* base64
* sys
* socket
* ssl
* certifi
* h2.connection
* h2.events

# Install

```
$ pip3 install h2rs
```

# Usage

```
$ h2rs
 _   ___         
| |_|_  |___ ___ 
|   |  _|  _|_ -|
|_|_|___|_| |___|

version 0.0.1
Error: requires target parameter.
usage: h2rs [-h] [-t TARGET] [-p PORT] [-m TIMEOUT] [-u USER_AGENT]

Detects request smuggling via HTTP/2 downgrades.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target server hostname (eg. www.example.com).
  -p PORT, --port PORT  Server TCP port to connect over TLS (default 443).
  -m TIMEOUT, --timeout TIMEOUT
                        Set connection timeout for request smuggling test (default 5).
  -u USER_AGENT, --user_agent USER_AGENT
                        Set default User-Agent request header (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69
                        Safari/537.36").
```

# Example

```
$ h2rs -t ac971f5e1e77d74fc0555ed900ed00eb.web-security-academy.net
 _   ___         
| |_|_  |___ ___ 
|   |  _|  _|_ -|
|_|_|___|_| |___|

version 0.0.1
Making a GET HTTP2 request to ac971f5e1e77d74fc0555ed900ed00eb.web-security-academy.net:443 ...
Got response status code 200.
Detecting H2.CL request smuggling ...
Not potencial vulnerable to H2.CL request smuggling.
Detecting H2.CL (CRLF) request smuggling ...
Not potencial vulnerable to H2.CL (CRLF) request smuggling.
Detecting H2.TE request smuggling ...
Not potencial vulnerable to H2.TE request smuggling.
Detecting H2.TE (CRLF) request smuggling ...
[!] Potencial vulnerable to H2.TE (CRLF) request smuggling.
Detecting HTTP/2 request tunnelling ...
Not potencial vulnerable to HTTP/2 request tunnelling.
```

# Author

* [Ricardo Iramar dos Santos](mailto:ricardo.iramar@gmail.com)
