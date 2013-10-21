dns2udp
--------------------

Python/twisted script to proxy UDP traffic over DNS (TXT) queries.

Example usage:

```console
# Start *listening* netcat on UDP-1234
m1% ncat -luv 127.0.0.1 1234
Ncat: Version 6.25 ( http://nmap.org/ncat )
Ncat: Listening on 127.0.0.1:1234
(whatever typed here should be seen in last netcat)

# DNS (on default port 5353, see --help) to proxy packets to that netcat
m1% ./dns2udp.py --debug dns-server 127.0.0.1:1234

# (on a presumably remote machine) Proxy from 127.0.0.1:1235 to that DNS
m2% ./dns2udp.py --debug dns-client 127.0.0.1:1235 127.0.0.1:5353

# (on a presumably remote machine) Netcat to connect to first over DNS
m2% ncat -uv 127.0.0.1 1235
Ncat: Version 6.25 ( http://nmap.org/ncat )
Ncat: Connected to 127.0.0.1:1235.
(whatever typed here should be seen in first netcat)
```

Needs Python 2.7 and [Twisted](http://twistedmatrix.com/).
