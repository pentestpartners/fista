# FastInfoSet Translator and Attacker (fista)

This decodes fastinfoset encoded requests from client -> burp so they can be read/scanned/intruded etc, then encodes 
the requests again from burp -> server.

Similarly but in reverse for responses.

If the requests are gzip compressed, they will be decompressed first and re-compressed afterwards.

## Usage

The original encoded requests are visible in the proxy under the _Original request_ tab, but a new _Edited request_ tab 
shows the decoded content. This can then be sent to intruder/scanned etc which should then encode them on the fly but 
only show decoded requests/responses.

Similarly the _Original response_ tab is the decoded response, and the _Edited response_ tab the encoded response. 
These tab names are perhaps backwards but cannot be changed.

## Building

This project requires apache maven to build.

```
$ cd fista
$ mvn package
```

Open Burp Suite, switch to "Extender" tab, add the jar in the target folders as an extension.

Alternatively you can use the precompiled jar in this repository. 

## Contributing

Pull requests are welcome.