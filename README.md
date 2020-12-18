# csv-importer

csv-importer.py is a simple script to assist in importing objects via CSV files to StoredSafe.

Imports to StoredSafe can either be done thru the reference web UI implementation when creating new objects by pasting JSON structures according to a specified format or by utilizing StoredSafe's REST API which would require a connection and a valid API key to the affected StoredSafe server.

csv-importer.py can assist in both modes. By specifying the ```--no-rest``` option, csv-importer.py will operate in in off-line mode and translating input to the required JSON structures and store it in a file (```--json``` option), or output to stdout (which is the default option).

csv-importer.py can also utilize StoredSafe's REST API to directly import objects. If the ```--no-rest``` option is not specified, csv-importer.py will operate in REST API mode and will require either that pre-authentication has been performed by the StoredSafe token handler CLI module (```storedsafe-tokenhandler.py```) and stored in an init file which location can be specified with the ```--rc``` option.

Other authentication options includes specifying a valid token (```--token```) or perform an on-line one-shot authentication (```--user``` and ```--apikey```)

The script is written in Python v3 and has been tested on macOS Catalina (10.15.5) and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

Support for previous versions of StoredSafe (pre v2.1.0) can be found in the legacy branch.

## Installation instructions

This script requires Python v3 and some libraries. It has been developed and tested using Python v3.7.7, on macOS Catalina 10.15.5.

Most of the required libraries are installed by default, but ```requests``` might require manual installation.

**requests:**

```bash
sudo pip install -r requirements.txt
```

or

```bash
sudo -H pip install requests
```

## Syntax

```bash
$ csv-importer.py --help
Usage: csv-importer.py [-vdsuat]
 --verbose                      (Boolean) Enable verbose output.
 --debug                        (Boolean) Enable debug output.
 --no-rest                      Operate in off-line mode, do not attempt to use the REST API.
 --rc <rc file>                 Use this file to obtain a valid token and a server address.
 --storedsafe (or -s) <Server>  Use this StoredSafe server.
 --user (or -u) <user>          Authenticate as this user to the StoredSafe server.
 --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.
 --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.
 --basic-auth-user <user:pw>    Specify the user name and password to use for HTTP Basic Authentication.
 --csv <file>                   File in CSV format to import.
 --separator <char>             Use this character as CSV delimiter. (defaults to ,)
 --escapechar <char>            Use this character to escape special characters. (defaults to None)
 --json <file>                  Store output (JSON) in this file.
 --fieldnames <fields>          Specify the mapping between columns and field names. Has to match exactly. Defaults to the Server template.
 --objectname <field>           Use this field as objectname when storing objects. Defaults to the host field from the Server template
 --template <template>          Use this template name for import. Name has to match exactly. Defaults to the Server template.
 --templateid <template-ID>     Use this template-ID when importing. (*)
 --vault <Vaultname>            Store imported objects in this vault. Name has to match exactly. (*)
 --vaultid <Vault-ID>           Store imported objects in this Vault-ID. (*)
 --create-vault                 (Boolean) Create missing vaults. (*)
 --policy <policy-id>           Use this password policy for newly created vaults. (Default to policy #7) (*)
 --description <text>           Use this as description for any newly created vault. (Default to "Created by csv-importer.") (*)
 --allow-duplicates             (Boolean) Allow duplicates when importing. (*)
 --skip-first-line              Skip first line of input. A CSV file usually has headers, use this to skip them.
 --remove-extra-columns         Remove any extra columns the if CSV file has more columns than the template.
 --stuff-extra <field>          Add data from extranous columns to this field.
 --not-empty <fielda,fieldb>    These fields must not be blank in imports. (Separate fields with ",")
 --fill-with <string>           For fields specified with --not-empty, use this string as filler. (Defaults to "n/a")
 --list-vaults                  List all vaults accessible to the authenticated user. (*)
 --list-templates               List all available templates.
 --list-fieldnames              List all fieldnames in the specified template. (--template or --templateid)

(*) REST mode only.

Using REST API and interactive login:
$ csv-importer.py --storedsafe safe.domain.cc --user bob --apikey myapikey --csv file.csv --vault "Public Web Servers" --verbose

Using REST API and pre-authenticated login:
$ csv-importer.py --rc ~/.storedsafe-client.rc --vault "Public Web Servers" --csv file.csv

Off-line mode:
$ csv-importer.py --no-rest --csv file.csv --json file.json --template Login --fieldnames host,username,password
```

```bash
--verbose
```

> Add verbose output.

```bash
--debug
```

> Add debug output.

```bash
--no-rest
```

> Do not use the REST API, operate completely in off-line mode. Result displayed to screen (default) or can be saved in a file. (```--json```)

```bash
--rc <RC file>
```

> Obtain credentials (token) and server information from this file. (Enabled by default to ```~/.storedsafe-client.rc```)

```bash
--storedsafe|-s <server>
```

> Upload certificates to this StoredSafe server.

```bash
--user|-u <user>
```

> Authenticate as this StoredSafe user.

```bash
--apikey|-a <apikey>
```

> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```bash
--token <token>
```

> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```bash
--basic-auth-user <user:pw>
```

> Specify the user name and password to use for HTTP Basic Authentication.

```bash
--csv <CSV file>
```

> Specify one or more IPv4 or IPv6 networks. Overlapping will be resolved.

```bash
--separator
```

> Use this character as CSV separator. (Single character)

```bash
--escapechar
```

> Use this character as CSV escape char. (Single character)

```bash
--json
```

> Output resulting JSON to this file.

```bash
--fieldnames
```

> Use this comma separated list as input field names. See ```--list-fieldnames``` for valid field names per template.

```bash
--objectname
```

> Use this field as the primary name for the object. Defaults to the "host" field from the Server template.

```bash
--template
```

> Use this StoredSafe template for import. See ```--list-templates``` for a complete list of supported templates on the server. (Case sensitive and name has to match exactly)

```bash
--templateid
```

> Instead of using the template name (```--template```), you can specify the Template-ID which is unique per template.

```bash
--vault|-v <Vaultname>
```

> Store any found certificates in this vault. Name has to match exactly. See ```--list-vaults``` for a complete list of accessible vaults on the StoredSafe server.

```bash
--vaultid <Vault-ID>
```

> Store any found certificates in this Vault-ID.

```bash
--create-vault
```

> Create missing vaults.

```bash
--policy <policy-id>
```

> Use this password policy for newly created vaults. (Default to 7)

```bash
--description <text>
```

> Use this as description for any newly created vault. (Default to "Created by csv-importer.")

```bash
--allow-duplicates
```

> Allow importing the same certificate to the same vault multiple times.

```bash
--skip-first-line
```

> Normally the first line in a CSV file has headers, use this option to skip these.

```bash
--remove-extra-columns
```

> If the input CSV file has more columns than matching fields in StoredSafe, remove them.

```bash
--stuff-extra <field>
```

> Add data from extranous columns to this field.

```bash
--not-empty <fielda,fieldb>
```

> Certain fields in templates can not be blank in imports. If import complains on empty fields, this option can be used to fill those fields with data. (Separate fields with ",")

```bash
--fill-with <string>
```

> For fields specified with --not-empty, use this string as filler. (Defaults to 'n/a')

```bash
--list-vaults
```

> List all vaults accessible to the authenticated user on the StoredSafe server.

```bash
--list-templates
```

> List all templates accessible to the authenticated user on the StoredSafe server.

```bash
--list-fieldnames
```

> List all fields in the specified template. Obtained by querying the template on the StoredSafe server.

## Usage

Prepare a CSV file for importing objects to StoredSafe, this can be done manually or by exporting from an other password manager, or an excel spreadsheet.

```bash
$ cat file.csv
host,username,password,info,cryptedinfo
fw.safe.domain.cc,admin,j5nJ2QQnRhp7xYwG8fExygDvD,Firewall for Stockholm office.,iLO password is k3PUibwrWMCYCtxlYgsrOiKRZZnIxA
resolver.safe.domain.cc,root,Xf6PVBdlad40sS3C7u1H6mVsD,"unbound, recursive resolver for Stockholm office",
safe.domain.cc,rolf,BoDJCrHLF4VNOyeBOuKzZocqc,Rolf Rolfsson,cryptedinfo
safe.domain.cc,sven,lKuBdy1k6HMxbVh6vRB5yW7q6,Sven Hell,cryptedinfo
kdc.safe.domain.cc,root,uFwWyzrAjyU4RKVdnnClXMuJ5,KDC located in D4K3,Backup GPG passphrase is 3Bxq8Df2LrPpf99qT0mml8SI5Di9hY7QwDMioHvARxj1fmXRFy
```

Import objects into the StoredSafe appliance using the file "file.csv" as input (content as below), use a pre-authenticated session (```--rc```) and store imported objects in the "Stockholm Office" Vault on the StoredSafe server "safe.domain.cc".

```bash
$ csv-importer.py --rc ~/.storedsafe-client.rc --csv file.csv --vault "Stockholm Office" --skip-first-line --verbose
Importing "fw.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "resolver.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Importing "kdc.safe.domain.cc" into the Vault "Stockholm Office" (Vault-ID 182).
Imported 5 object/s
```

Re-running the import, csv-importer.py will detect that the objects are already present in the vault "Stockholm Office" and will avoid storing duplicates by default. (can be changed with --allow-duplicates)

```bash
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

```bash
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

```bash
$ csv-importer.py --rc ~/.storedsafe-client.rc --list-fieldnames --templateid 1001
username,info,ip,host,password,cryptedinfo

```

List all vaults available to the current authenticated users.

```bash
$ csv-importer.py --rc ~/.storedsafe-client.rc --list-vaults
Vault "StoredSafe" (Vault-ID "1") with "Admin" permissions.
Vault "Testing grounds" (Vault-ID "19") with "Admin" permissions.
Vault "Stockholm Office" (Vault-ID "182") with "Admin" permissions.
Vault "Public Web Servers" (Vault-ID "181") with "Admin" permissions.
Vault "Firewalls in ZA" (Vault-ID "179") with "Admin" permissions.
```

Using the off-line mode, format the input CSV file according to the StoredSafe JSON specifications, which latter can be validated and imported thru the standard StoredSafe web UI.

```bash
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

When importing CSV files with extra fields, you will receive a warning.

```bash
WARNING: Extra, unmatched columns detected. Import will most likely fail due to this.
WARNING: Consider using "--remove-extra-columns" or "--stuff-extra".
```

To remediate, you can either delete the extra fields:

```bash
$ csv-importer.py --no-rest --template 'Credit Card' --csv file.csv --json file.json --remove-extra-columns
```

Or concatenate them into an existing field:

```bash
$ csv-importer.py --no-rest --template Note --csv file.csv --json file.json --stuff-extra note
```

List all built in templates in off-line mode:

```bash
$ python3 csv-importer.py --no-rest --list-templates
Builtin templates: Server, Login, Short Login, PIN Code, Note, Credit Card
```

List fieldnames from built in templates, in off-line mode:

```bash
$ csv-importer.py --no-rest --list-fieldnames --template "Credit Card"
service,cardno,expires,cvc,owner,pincode,note1,note2
```

Since certain fields in different templates requires a value, it is possible to specify fields that can not be empty, and also supply an appropriate string as a filler.

```bash
$ cat file.csv
exocet,,5b9VcuPpwQG1R0MBCk8TEMtT7w7hd0j1i3iRERqm,https://exocet.domain.tld/login,Serialno: u54898945
,root,UiA7NrjVcOMWcd1aUZaW1lFUuDzXFJkGzZ7aSjmU,,same password for the admin user in the webui
$ csv-importer.py --no-rest --csv file.csv --not-empty host,username --fill-with "blank"
{
    "Server": [
        {
            "host": "exocet",
            "username": "blank",
            "password": "5b9VcuPpwQG1R0MBCk8TEMtT7w7hd0j1i3iRERqm",
            "info": "https://exocet.domain.tld/login",
            "cryptedinfo": "Serialno: u54898945"
        },
        {
            "host": "blank",
            "username": "root",
            "password": "UiA7NrjVcOMWcd1aUZaW1lFUuDzXFJkGzZ7aSjmU",
            "info": "",
            "cryptedinfo": "same password for the admin user in the webui"
        }
    ]
}
```

## Limitations / Known issues

No known limitation.

## License

GPL
