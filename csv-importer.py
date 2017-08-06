#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
csv-importer.py: Assist in parsing CSV files and output either a properly formatted JSON file suitable
  for import into StoredSafe or utilize the REST API to do a direct import to StoredSafe.
"""
 
import sys
import ssl
import OpenSSL
import csv
import json
import getopt
import getpass
import os.path
import re
import pprint
#import requests
#from requests_toolbelt.multipart.encoder import MultipartEncoder
 
__author__     = "Fredrik Soderblom"
__copyright__  = "Copyright 2017, AB StoredSafe"
__license__    = "GPL"
__version__    = "1.0.1"
__maintainer__ = "Fredrik Soderblom"
__email__      = "fredrik@storedsafe.com"
__status__     = "Production"

# Globals

url              = False
token            = False
verbose          = False
debug            = False
create_vault     = False
allow_duplicates = False
no_rest          = False
skip_first       = False
delete_extra     = False

def main():
  user = apikey = vaultid = vaultname = supplied_token = rc_file = template = templateid = False
  infile = outfile = fieldnames = separator = False
  global token, url, verbose, debug, create_vault, allow_duplicates, no_rest, skip_first, delete_extra

  try:
   opts, args = getopt.getopt(sys.argv[1:], "s:u:a:v:t:",\
    [ "verbose", "debug", "storedsafe=", "token=", "user=", "apikey=", "vault=", "vaultid=",\
     "template=", "templateid=", "rc=", "csv=", "json=", "create-vault", "allow-duplicates", "no-rest",\
     "fieldnames=", "separator=", "skip-first-line", "remove-extra-columns" ])
  except getopt.GetoptError as err:
    print("%s" % str(err))
    usage()
    sys.exit()

  if opts:
    pass
  else:
    usage()
    sys.exit()

  for opt, arg in opts:
    if opt in ("--verbose"):
      verbose = True
    elif opt in ("--debug"):
      debug = True
    elif opt in ("-s", "--storedsafe"):
      storedsafe = arg
    elif opt in ("-u", "--user"):
      user = arg
    elif opt in ("-a", "--apikey"):
      if len(str(arg)) == 10:
        apikey = arg
      else:
        print("Invalid API key.")
        sys.exit()
    elif opt in ("-t", "--token"):
      if len(str(arg)) == 42:
        supplied_token = arg
      else:
        print("Invalid token.")
        sys.exit()
    elif opt in ("--rc"):
      rc_file = arg
    elif opt in ("-v", "--vault"):
      vaultname = arg
    elif opt in ("--vaultid"):
      vaultid = arg
    elif opt in ("--template"):
      template = arg
    elif opt in ("--templateid"):
      templateid = arg
    elif opt in ("--csv"):
      infile = arg
    elif opt in ("--separator"):
      separator = arg
    elif opt in ("--json"):
      outfile = arg
    elif opt in ("--fieldnames"):
      fieldnames = arg.split(',')
    elif opt in ("--create-vault"):
      create_vault = True
    elif opt in ("--allow-duplicates"):
      allow_duplicates = True
    elif opt in ("--no-rest"):
      no_rest = True
    elif opt in ("--skip-first-line"):
      skip_first = True
    elif opt in ("--remove-extra-columns"):
      delete_extra = True
    elif opt in ("-?", "--help"):
      usage()
      sys.exit()
    else:
      assert False, "Unrecognized option"

  if outfile:
     output = open(outfile, 'w')

  if no_rest:
    if not template:
      template = "Server"
    if not fieldnames:
      fieldnames = [ 'host', 'username', 'password', 'info', 'cryptedinfo' ]

    lines = CSVRead(infile, template, fieldnames)
    data = {}
    data[template] = lines

    if outfile:
      output.write(json.dumps(data, indent=4, ensure_ascii=False, encoding="utf-8"))
      output.close()
    else:
      print(json.dumps(data, indent=4, ensure_ascii=False, encoding="utf-8"))

    sys.exit(0)

  # REST continues

  if supplied_token:
    token = supplied_token
  if rc_file:
    (storedsafe, token) = readrc(rc_file)
  
  if not token:
    if user and apikey:
      pp = passphrase(user)
      otp = OTP(user)
      token = login(user, pp + apikey + otp)
    else:
      print("ERROR: StoredSafe User (--user) and a StoredSafe API key (--apikey) or a valid StoredSafe Token (--token) is mandatory arguments.")
      sys.exit()

  # Check if Vaultname exists
  if vaultname:
    vaultid = findVaultID(vaultname)

  # Check if Vault-ID exists
  if vaultid:
    vaultname = findVaultName(vaultid)
  else:
    if not create_vault:
      print("ERROR: One of \"--vault\", \"--vaultid\" or \"--create-vault\" is mandatory.")
      sys.exit()

  # Check if Template exists
  if template:
    templateid = findTemplateID(template)

  # Check if Template-ID exists
  if templateid:
    template = findTemplateName(templateid)

  data = CSVRead(infile, template, fieldnames)
  (imported, duplicates) = insertObjects(data, vaultid)

  if imported:
    print("Imported %d object/s." % imported)
  if duplicates:
    print("Found %d duplicate object/s. " % duplicates)

  sys.exit(0)

def usage():
  print("Usage: %s [-vdsuat]" % sys.argv[0])
  print(" --verbose (or -v)              (Boolean) Enable verbose output.")
  print(" --debug (or -d)                (Boolean) Enable debug output.")
  print(" --csv <file>                   File in CSV format to import.")
  print(" --separator <char>             Use this character as CSV delimiter (defaults to ,)")
  print(" --json <file>                  Store output (JSON) in this file.")
  print(" --fieldnames <fields>          Specify the mapping between columns and field names. Has to match exactly. Defaults to the Server template.")
  print(" --rc <rc file>                 Use this file to obtain a valid token and a server address.")
  print(" --storedsafe (or -s) <Server>  Use this StoredSafe server.")
  print(" --user (or -u) <user>          Authenticate as this user to the StoredSafe server.")
  print(" --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.")
  print(" --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.")
  print(" --template <template>          Use this template name for import. Name has to match exactly. Defaults to the Server template.")
  print(" --templateid <template-ID>     Use this template-ID when importing.")
  print(" --vault <Vaultname>            Store any found certificates in this vault. Name has to match exactly.")
  print(" --vaultid <Vault-ID>           Store any found certificates in this Vault-ID.")
# print(" --create-vault                 (Boolean) Create missing vaults.") # NOTIMPL
  print(" --allow-duplicates             (Boolean) Allow duplicates when importing.")
  print(" --no-rest                      Operate in off-line mode, do not attempt to use the REST API")
  print(" --skip-first-line              Skip first line of input. A CSV file usually has headers, use this to skip them.")
  print(" --remove-extra-columns         Remove any extra columns the if CSV file has more columns than the template.")
# print(" --stuff-extra-in <field>       Add data from extranous columns to this field.") # NOTIMPL
  print("\nExample using interactive login:")
  print("$ %s --storedsafe safe.domain.cc --user bob --apikey myapikey --csv file.csv --vault \"Public Web Servers\" --verbose" % sys.argv[0])
  print("\nExample using pre-authenticated login:")
  print("$ %s --rc ~/.storedsafe.rc --vault \"Public Web Servers\" --csv file.csv" % sys.argv[0])
  print("\nExample in off-line mode:")
  print("$ %s --no-rest --csv file.csv --json file.json --template Login --fieldnames host,username,password" % sys.argv[0])

def readrc(rc_file):
  if os.path.isfile(rc_file):
    f = open(rc_file, 'rU')
    for line in f:
      if "token" in line:
        token = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
        if token == 'none':
          print("ERROR: No valid token found in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
      if "mysite" in line:
        server = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
        if server == 'none':
          print("ERROR: No valid server specified in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
    f.close()
    if not token:
      print("ERROR: Could not find a valid token in \"%s\"" % rc_file)
      sys.exit()
    if not server:
      print("ERROR: Could not find a valid server in \"%s\"" % rc_file)
      sys.exit()
    return (server, token)
  else:
    print("ERROR: Can not open \"%s\"." % rc_file)

def passphrase(user):
  p = getpass.getpass('Enter ' + user + '\'s passphrase: ')
  return(p)

def OTP(user):
  otp = getpass.getpass('Press ' + user + '\'s Yubikey: ')
  return(otp)

def login(user, key):
  global url
  payload = { 'username': user, 'keys': key }
  try:
    r = requests.post(url + '/auth', data=json.dumps(payload))
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if r.ok:
    return data["CALLINFO"]["token"]
  else:
    print("ERROR: %s" % data["ERRORS"][0])
    sys.exit()

def findVaultID(vaultname):
  global token, url, verbose, debug
  vaultid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any vaults.")
    sys.exit()

  for v in data["GROUP"].iteritems():
    if vaultname == data["GROUP"][v[0]]["groupname"]:
      vaultid = v[0]
      if debug: print("Found Vault \"%s\" via Vaultname as Vault-ID \"%s\"" % (vaultname, vaultid))

  if not vaultid:
    if create_vault:
      print("ERROR: Can not find Vaultname \"%s\", will try to create a new vault." % vaultname)
      vaultid = False
    else:
      print("ERROR: Can not find Vaultname \"%s\" and \"--create-vault\" not specified." % vaultname)   
      sys.exit()

  return(vaultid)

def findVaultName(vaultid):
  global token, url, create_vault, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/vault/' + vaultid, params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    if create_vault:
      print("WARNING: Can not find Vault-ID \"%s\", will try to create a new vault." % vaultid)
      vaultname = False
    else:
      print("ERROR: Can not find Vault-ID \"%s\" and \"--create-vault\" not specified." % vaultid)
      sys.exit()

  if data["CALLINFO"]["status"] == "SUCCESS":
    vaultname = data["GROUP"][vaultid]["groupname"]
    if debug: print("Found Vault \"%s\" via Vault-ID \"%s\"" % (vaultname, vaultid))
  else:
    print("ERROR: Can not retreive Vaultname for Vault-ID %s." % vaultid)
    sys.exit()

  return(vaultname)

def findTemplateID(template):
  global token, url, verbose, debug
  templateid = False

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template', params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find any templates.")
    sys.exit()

  for v in data["TEMPLATE"].iteritems():
    if template == data["TEMPLATE"][v[0]]["name"]:
      templateid = v[0]
      if debug: print("Found Template \"%s\" as Template-ID \"%s\"" % (template, templateid))

  if not templateid:
    print("ERROR: Can not find Template \"%s\"." % template)   
    sys.exit()

  return(templateid)

def findTemplateName(templateid):
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.get(url + '/template/' + templateid, params=payload)
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()
  data = json.loads(r.content)
  if not r.ok:
    print("ERROR: Can not find Template-ID \"%s\"." % templateid)
    sys.exit()

  if data["CALLINFO"]["status"] == "SUCCESS":
    template = data["TEMPLATE"][templateid]["name"]
    if debug: print("Found Template \"%s\" via Template-ID \"%s\"" % (template, templateid))
  else:
    print("ERROR: Can not retreive Template for Template-ID %s." % templateid)
    sys.exit()

  return(template)

def CSVRead(infile, template, fieldnames):
    global skip_first, delete_extra
    reader = csv.DictReader(open(infile, 'rb'), fieldnames=fieldnames, restkey="unspecified-columns")

    if skip_first:
    	reader.next()

    lines = []
    for line in reader:
      if delete_extra:
      	if 'unspecified-columns' in line:
      		del line['unspecified-columns']
      lines.append(line)

    return lines

def insertObjects(data, vaultid):
  # FIXME
  return(imported, duplicates)

if __name__ == '__main__':
  main()