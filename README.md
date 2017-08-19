# csv-importer

csv-importer.py is a simple script to assist in importing objects via CSV files to StoredSafe.

Imports to StoredSafe can either be done thru the reference web UI implementation when creating new objects by pasting JSON structures according to a specified format or by utilizing StoredSafe's REST API which would require a connection and a valid API key to the affected StoredSafe server.

csv-importer.py can assist in both modes. By specifying the ```--no-rest``` option, csv-importer.py will operate in in off-line mode and translating input to the required JSON structures and store it in a file (```--json``` option), or output to stdout (which is the default option).

csv-importer.py can also utilize StoredSafe's REST API to directly import objects. If the ```--no-rest``` option is not specified, csv-importer.py will operate in REST API mode and will require either that pre-authentication has been performed by the StoredSafe authenticator CLI module (```storedsafe-authenticator.py```) and stored in an init file which location can be specified with the ```--rc``` option. Other authentication options includes specifying a valid token (```--token```) or perform an on-line one-shot authentication (```--user``` and ```--apikey```)

The script is written in Python v2 and has been tested on macOS Sierra and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

## Installation instructions

This script requires Python v2 and some libraries. 

It has been developed and tested using Python v2.7.10, on macOS Sierra 10.12.6.

Most of the required libraries are installed by default,  but others require manual installation. ("requests, requests_toolbelt, netaddr)

**requests:**
```
sudo -H pip install requests
```

**requests-toolbelt:**
```
sudo -H pip install requests-toolbelt
```

## Syntax

```
$ csv-importer.py --help
Usage: csv-importer.py [-vdsuat]
 --verbose (or -v)              (Boolean) Enable verbose output.
 --debug (or -d)                (Boolean) Enable debug output.
 --rc <rc file>                 Use this file to obtain a valid token and a server address.
 --storedsafe (or -s) <Server>  Use this StoredSafe server.
 --user (or -u) <user>          Authenticate as this user to the StoredSafe server.
 --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.
 --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.
 --csv <file>                   File in CSV format to import.
 --separator <char>             Use this character as CSV delimiter. (defaults to ,)
 --json <file>                  Store output (JSON) in this file.
 --fieldnames <fields>          Specify the mapping between columns and field names. Has to match exactly. Defaults to the Server template.
 --template <template>          Use this template name for import. Name has to match exactly. Defaults to the Server template.
 --templateid <template-ID>     Use this template-ID when importing.
 --vault <Vaultname>            Store imported objects in this vault. Name has to match exactly.
 --vaultid <Vault-ID>           Store imported objects in this Vault-ID.
 --objectname <field>           Use this field as objectname when storing objects. (Defaults to the host field from the Server template)
 --allow-duplicates             (Boolean) Allow duplicates when importing.
 --no-rest                      Operate in off-line mode, do not attempt to use the REST API.
 --skip-first-line              Skip first line of input. A CSV file usually has headers, use this to skip them.
 --remove-extra-columns         Remove any extra columns the if CSV file has more columns than the template.
 --list-vaults                  List all vaults accessible to the authenticated user.
 --list-templates               List all available templates.
 --list-fieldnames              List all fieldnames in the specified template. (--template or --templateid)

Using REST API and interactive login:
$ csv-importer.py --storedsafe safe.domain.cc --user bob --apikey myapikey --csv file.csv --vault "Public Web Servers" --verbose

Using REST API and pre-authenticated login:
$ csv-importer.py --rc ~/.storedsafe-client.rc --vault "Public Web Servers" --csv file.csv

Off-line mode:
$ csv-importer.py --no-rest --csv file.csv --json file.json --template Login --fieldnames host,username,password
```

```
--verbose
``` 
> Add verbose output

```
--debug
```
> Add debug output

```
--rc <RC file>
```
> Obtain credentials (roken) and server information from this file.

```
--storedsafe|-s <server>
```
> Upload certificates to this StoredSafe server

```
--user|-u <user>
```
> Authenticate as this StoredSafe user

```
--apikey|-a <apikey>
```
> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```
--token <token>
```
> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```
--csv <CSV file>
```
> Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.

```
--separator
```
> 

```
--json
```
> 

```
--fieldnames
```
> 

```
--template
```
> 

```
--templateid
```
> 

```
--vault|-v <Vaultname>
```
> Store any found certificates in this vault. Name has to match exactly.

```
--vaultid <Vault-ID>
```
> Store any found certificates in this Vault-ID.

```
--objectname
```
> 

```
--allow-duplicates
```
> Allow importing the same certificate to the same vault multiple times.

```
--no-rest
```
> 

```
--skip-first-line
```
> 

```
--remove-extra-columns
```
> 

```
--list-vaults
```
> 

```
--list-templates
```
> 

```
--list-fieldnames
```
> 

Usage
=====
Scan the networks 2001:db8:c016::202/128, 10.75.106.202/29 and 192.0.2.4/32 on port 443 for X.509 certificates. Store any certificates found in the "Public Web Servers" Vault on the StoredSafe server "safe.domain.cc" and arm an alarm that will fire 30 days prior to each certificates expiration date.

```
$ csv-importer.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -p 443 -s safe.domain.cc -u bob --apikey myapikey --vault "Public Web Servers" --verbose
Enter bob's passphrase:
Press bob's Yubikey:
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "myapikey"
Using the token "xyzzyxyzzy"
Will store found certificates in Vault "Public Web Servers" (Vault-ID 181)
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!!
Host "192.0.2.4:443" (PTR: inferno.example.org) X509 CommonName="inferno.example.org" (expires in 57 days)
Host "10.75.106.201:443" (PTR: webmail.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Host "10.75.106.204:443" (PTR: domain.cc) X509 CommonName="domain.cc" (expires in 460 days)
Host "10.75.106.207:443" (PTR: d1.domain.cc) X509 CommonName="d1.domain.cc" (expires in 576 days)
Host "2001:db8:c016::202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 824 days)
Imported 6 certificates.
```

Rescan the networks from the example above, csv-importer.py will detect that the certificates are already present in the vault "Public Web Servers" and will avoid storing duplicates by default (can be changed with --allow-duplicates).

```
$ csv-importer.py -c 2001:db8:c016::202 -c 10.75.106.202/29 -c 192.0.2.4 -s safe.domain.cc -u bob -a abcde12345 --vault "Public Web Servers" --verbose --timeout 1
Enter bob's passphrase:
Press bob's Yubikey:
Using StoredSafe Server "safe.domain.cc" (URL: "https://safe.domain.cc/api/1.0")
Logged in as "bob" with the API key "abcde12345"
Using the token "xyzzyxyzzy"
Will store found certificates in Vault "Public Web Servers" (Vault-ID 181)
Scanning network/s: 192.0.2.4/32, 10.75.106.202/29, 2001:db8:c016::202/128 on port/s: 443
[Legend: "." for no response, "!" for an open port]
!.!!.!..!.
Host "192.0.2.4:443" (PTR: inferno.example.org) X509 CommonName="inferno.example.org" (expires in 57 days)
Found existing certificate as Object-ID "587" in Vault-ID "181"
Host "10.75.106.201:443" (PTR: webmail.domain.cc) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.202:443" (PTR: freeloaders.domain.cc) X509 CommonName="*.domain.cc" (expires in 823 days)
Found existing certificate as Object-ID "588" in Vault-ID "181"
Host "10.75.106.204:443" (PTR: domain.cc) X509 CommonName="domain.cc" (expires in 459 days)
Found existing certificate as Object-ID "590" in Vault-ID "181"
Host "10.75.106.207:443" (PTR: d1.domain.cc) X509 CommonName="d1.domain.cc" (expires in 575 days)
Found existing certificate as Object-ID "591" in Vault-ID "181"
Found 5 duplicate certificate/s.
```

## Limitations / Known issues
```
--create-vault
```
> Is not yet implemented.

## License
GPL
