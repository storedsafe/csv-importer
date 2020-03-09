# csv-importer

csv-importer.py is a simple script to assist in importing objects via CSV files to StoredSafe.

Imports to StoredSafe can either be done thru the reference web UI implementation when creating new objects by pasting JSON structures according to a specified format or by utilizing StoredSafe's REST API which would require a connection and a valid API key to the affected StoredSafe server.

csv-importer.py can assist in both modes. By specifying the ```--no-rest``` option, csv-importer.py will operate in in off-line mode and translating input to the required JSON structures and store it in a file (```--json``` option), or output to stdout (which is the default option).

csv-importer.py can also utilize StoredSafe's REST API to directly import objects. If the ```--no-rest``` option is not specified, csv-importer.py will operate in REST API mode and will require either that pre-authentication has been performed by the StoredSafe token handler CLI module (```storedsafe-tokenhandler.py```) and stored in an init file which location can be specified with the ```--rc``` option. 

Other authentication options includes specifying a valid token (```--token```) or perform an on-line one-shot authentication (```--user``` and ```--apikey```)

The script is written in Python v2 and has been tested on macOS Sierra and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

## Installation instructions

This script requires Python v3 and some libraries. 

It has been developed and tested using Python v3.7.4, on macOS Sierra 10.15.3.

Most of the required libraries are installed by default, but others require manual installation. (requests)

**requests:**

```
sudo pip install -r requirements.txt 
```
or

```
sudo -H pip install requests
```

## Syntax

```
$ csv-importer.py --help
Usage: csv-importer.py [-vdsuat]
 --verbose                      (Boolean) Enable verbose output.
 --debug                        (Boolean) Enable debug output.
 --rc <rc file>                 Use this file to obtain a valid token and a server address.
 --storedsafe (or -s) <Server>  Use this StoredSafe server.
 --user (or -u) <user>          Authenticate as this user to the StoredSafe server.
 --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.
 --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.
 --basic-auth-user <user:pw>    Specify the user name and password to use for HTTP Basic Authentication
 --csv <file>                   File in CSV format to import.
 --separator <char>             Use this character as CSV delimiter. (defaults to ,)
 --json <file>                  Store output (JSON) in this file.
 --fieldnames <fields>          Specify the mapping between columns and field names. Has to match exactly. Defaults to the Server template.
 --objectname <field>           Use this field as objectname when storing objects. Defaults to the host field from the Server template
 --template <template>          Use this template name for import. Name has to match exactly. Defaults to the Server template.
 --templateid <template-ID>     Use this template-ID when importing.
 --vault <Vaultname>            Store imported objects in this vault. Name has to match exactly.
 --vaultid <Vault-ID>           Store imported objects in this Vault-ID.
 --create-vault                 (Boolean) Create missing vaults.
 --policy <policy-id>           Use this password policy for newly created vaults. (Default to 7)
 --description <text>           Use this as description for any newly created vault. (Default to "Created by csv-importer.")
 --allow-duplicates             (Boolean) Allow duplicates when importing.
 --no-rest                      Operate in off-line mode, do not attempt to use the REST API.
 --skip-first-line              Skip first line of input. A CSV file usually has headers, use this to skip them.
 --remove-extra-columns         Remove any extra columns the if CSV file has more columns than the template.
 --stuff-extra <field>          Add data from extranous columns to this field.
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
> Add verbose output.

```
--debug
```
> Add debug output.

```
--rc <RC file>
```
> Obtain credentials (token) and server information from this file. (Enabled by default to ```~/.storedsafe-client.rc```)

```
--storedsafe|-s <server>
```
> Upload certificates to this StoredSafe server.

```
--user|-u <user>
```
> Authenticate as this StoredSafe user.

```
--apikey|-a <apikey>
```
> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```
--token <token>
```
> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```
--basic-auth-user <user:pw>
```
> Specify the user name and password to use for HTTP Basic Authentication.

```
--csv <CSV file>
```
> Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.

```
--separator
```
> Use this character as CSV separator. (Single character)

```
--json
```
> Output resulting JSON to this file.

```
--fieldnames
```
> Use this comma separated list as input field names. See ```--list-fieldnames``` for valid field names per template.

```
--objectname
```
> Use this field as the primary name for the object. Defaults to the "host" field from the Server template.

```
--template
```
> Use this StoredSafe template for import. See ```--list-templates``` for a complete list of supported templates on the server. (Case sensitive and name has to match exactly)

```
--templateid
```
> Instead of using the template name (```--template```), you can specify the Template-ID which is unique per template.

```
--vault|-v <Vaultname>
```
> Store any found certificates in this vault. Name has to match exactly. See ```--list-vaults``` for a complete list of accessible vaults on the StoredSafe server.

```
--vaultid <Vault-ID>
```
> Store any found certificates in this Vault-ID.

```
 --create-vault
```
> Create missing vaults.

```
--policy <policy-id>
```
> Use this password policy for newly created vaults. (Default to 7)

```
--description <text>
```
> Use this as description for any newly created vault. (Default to "Created by csv-importer.")

```
--allow-duplicates
```
> Allow importing the same certificate to the same vault multiple times.

```
--no-rest
```
> Do not use the REST API, operate completely in off-line mode. Result displayed to screen (default) or can be saved in a file. (```--json```)

```
--skip-first-line
```
> Normally the first line in a CSV file has headers, use this option to skip these.

```
--remove-extra-columns
```
> If the input CSV file has more columns than matching fields in StoredSafe, remove them.

```
--stuff-extra <field>
```
> Add data from extranous columns to this field.

```
--list-vaults
```
> List all vaults accessible to the authenticated user on the StoredSafe server.

```
--list-templates
```
> List all templates accessible to the authenticated user on the StoredSafe server.

```
--list-fieldnames
```
> List all fields in the specified template. Obtained by querying the template on the StoredSafe server.

Usage
=====

Prepare a CSV file for importing objects to StoredSafe, this can be done manually or by exporting from an other password manager, or an excel spreadsheet.

```
$ cat file.csv
host,username,password,info,cryptedinfo
fw.safe.domain.cc,admin,j5nJ2QQnRhp7xYwG8fExygDvD,Firewall for Stockholm office.,iLO password is k3PUibwrWMCYCtxlYgsrOiKRZZnIxA
resolver.safe.domain.cc,root,Xf6PVBdlad40sS3C7u1H6mVsD,"unbound, recursive resolver for Stockholm office",
safe.domain.cc,rolf,BoDJCrHLF4VNOyeBOuKzZocqc,Rolf Rolfsson,cryptedinfo
safe.domain.cc,sven,lKuBdy1k6HMxbVh6vRB5yW7q6,Sven Hell,cryptedinfo
kdc.safe.domain.cc,root,uFwWyzrAjyU4RKVdnnClXMuJ5,KDC located in D4K3,Backup GPG passphrase is 3Bxq8Df2LrPpf99qT0mml8SI5Di9hY7QwDMioHvARxj1fmXRFy
```

Import objects into the StoredSafe appliance using the file "file.csv" as input (content as below), use a pre-authenticated session (```--rc```) and store imported objects in the "Stockholm Office" Vault on the StoredSafe server "safe.domain.cc".

```
$ csv-importer.py --rc ~/.storedsafe-client.rc --csv file.csv --vault "Stockholm Office" --skip-first-line --verbose
Importing "fw.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "resolver.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "kdc.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Imported 5 object/s
```

Re-running the import, csv-importer.py will detect that the objects are already present in the vault "Stockholm Office" and will avoid storing duplicates by default. (can be changed with --allow-duplicates)

```
$ csv-importer.py --rc ~/.storedsafe-client.rc --csv file.csv --vault "Stockholm Office" --skip-first-line --verbose
WARNING: Object "fw.safe.domain.cc" (Object-ID 696) (4 field/s matched "fw.safe.domain.cc") - duplicate.
WARNING: Found 1 possible duplicate object/s in "Stockholm Office" when trying to import "fw.safe.domain.cc". (Use "--allow-duplicates" to force import)
WARNING: Object "resolver.safe.domain.cc" (Object-ID 697) (4 field/s matched "resolver.safe.domain.cc") - duplicate.
WARNING: Found 1 possible duplicate object/s in "Stockholm Office" when trying to import "resolver.safe.domain.cc". (Use "--allow-duplicates" to force import)
WARNING: Object "safe.domain.cc" (Object-ID 698) (4 field/s matched "safe.domain.cc") - duplicate.
WARNING: Found 1 possible duplicate object/s in "Stockholm Office" when trying to import "safe.domain.cc". (Use "--allow-duplicates" to force import)
WARNING: Object "safe.domain.cc" (Object-ID 699) (4 field/s matched "safe.domain.cc") - duplicate.
WARNING: Found 1 possible duplicate object/s in "Stockholm Office" when trying to import "safe.domain.cc". (Use "--allow-duplicates" to force import)
WARNING: Object "kdc.safe.domain.cc" (Object-ID 700) (4 field/s matched "kdc.safe.domain.cc") - duplicate.
WARNING: Found 1 possible duplicate object/s in "Stockholm Office" when trying to import "kdc.safe.domain.cc". (Use "--allow-duplicates" to force import)
WARNING: Skipped 5 duplicate object/s.
```

List all available templates on the server.

```
$ csv-importer.py --rc ~/.storedsafe-client.rc --list-templates
Found Template "Credit Card" as Template-ID "11"
Found Template "Short login" as Template-ID "10"
Found Template "Server" as Template-ID "1"
Found Template "Folder" as Template-ID "2"
Found Template "Quicknote" as Template-ID "5"
Found Template "Login" as Template-ID "4"
Found Template "PIN code" as Template-ID "9"
Found Template "Note" as Template-ID "8"
Found Template "Server/IP" as Template-ID "1001"
```

List all field names in a selected template.

```
$ csv-importer.py --rc ~/.storedsafe-client.rc --list-fieldnames --templateid 1001
username,info,ip,host,password,cryptedinfo

```

List all vaults available to the current authenticated users.

```
$ csv-importer.py --rc ~/.storedsafe-client.rc --list-vaults
Vault "StoredSafe" (Vault-ID "1") with "Admin" permissions.
Vault "Testing grounds" (Vault-ID "19") with "Admin" permissions.
Vault "Stockholm Office" (Vault-ID "182") with "Admin" permissions.
Vault "Public Web Servers" (Vault-ID "181") with "Admin" permissions.
Vault "Firewalls in ZA" (Vault-ID "179") with "Admin" permissions.
```

Using the off-line mode, format the input CSV file according to the StoredSafe JSON specifications, which latter can be validated and imported thru the standard StoredSafe web UI. 

```
$ csv-importer.py --no-rest --csv file.csv --skip-first-line
{
    "Server": [
        {
            "username": "admin",
            "info": "Firewall for Stockholm office.",
            "host": "fw.safe.domain.cc",
            "password": "j5nJ2QQnRhp7xYwG8fExygDvD",
            "cryptedinfo": "iLO password is k3PUibwrWMCYCtxlYgsrOiKRZZnIxA"
        },
        {
            "username": "root",
            "info": "unbound, recursive resolver for Stockholm office",
            "host": "resolver.safe.domain.cc",
            "password": "Xf6PVBdlad40sS3C7u1H6mVsD",
            "cryptedinfo": ""
        },
        {
            "username": "rolf",
            "info": "Rolf Rolfsson",
            "host": "safe.domain.cc",
            "password": "BoDJCrHLF4VNOyeBOuKzZocqc",
            "cryptedinfo": "cryptedinfo"
        },
        {
            "username": "sven",
            "info": "Sven Hell",
            "host": "safe.domain.cc",
            "password": "lKuBdy1k6HMxbVh6vRB5yW7q6",
            "cryptedinfo": "cryptedinfo"
        },
        {
            "username": "root",
            "info": "KDC located in D4K3",
            "host": "kdc.safe.domain.cc",
            "password": "uFwWyzrAjyU4RKVdnnClXMuJ5",
            "cryptedinfo": "Backup GPG passphrase is 3Bxq8Df2LrPpf99qT0mml8SI5Di9hY7QwDMioHvARxj1fmXRFy"
        }
    ]
}
```
When importing CSV files with extra fields, you can either delete the extra fields:

```
$ csv-importer.py --no-rest --template 'Credit Card' --csv file.csv --json file.json --remove-extra-columns
```

Or concatenate them into an existing field:

```
$ csv-importer.py --no-rest --template Note --csv file.csv --json file.json --stuff-extra note
```

List all built in templates in off-line mode:

```
$ python3 csv-importer.py --no-rest --list-templates
Builtin templates: Server, Login, Short Login, PIN Code, Note, Credit Card
```

List fieldnames from built in templates, in off-line mode:

```
$ csv-importer.py --no-rest --list-fieldnames --template "Credit Card"
"Credit Card": service, cardno, expires, cvc, owner, pincode, note1, note2
```

## Limitations / Known issues
No known limitation.

## License
GPL
