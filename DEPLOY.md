# SPARK Meeting — BTP CF Deploy Guide

## Pre-requisites

- `cf` CLI installed and authenticated (`cf login`)
- Target org/space set: `cf target -o <ORG> -s <SPACE>`
- Python buildpack available in your CF environment

## Step 1 — Export the users database as env var

Run this once on your Mac to generate the `cf set-env` command:

```bash
python3 -c "
import json, pathlib
f = pathlib.Path.home() / '.config/sap-portal/users.json'
print('cf set-env spark-meeting USERS_JSON \'' + json.dumps(json.loads(f.read_text())) + '\'')
"
```

Copy the output and run it.

## Step 2 — Deploy

```bash
cd ~/Library/CloudStorage/OneDrive-SAPSE/projects/spark-meeting-app
cf push
```

## Step 3 — Apply the env var and restage

```bash
# Paste here the output from Step 1
cf set-env spark-meeting USERS_JSON '<json output from step 1>'

cf restage spark-meeting
```

## Step 4 — Verify

```bash
cf app spark-meeting
```

The app will be available at:
`https://spark-meeting.cfapps.br10.hana.ondemand.com`

---

## Updating the route

If your CF target is not `br10`, edit `manifest.yml` and change:

```yaml
routes:
  - route: spark-meeting.cfapps.<REGION>.hana.ondemand.com
```

---

## Adding or updating users

Users are stored in the `USERS_JSON` environment variable.
To add a new user with a bcrypt-hashed password:

```bash
python3 -c "
import bcrypt, json
email = input('Email: ')
name = input('Name: ')
password = input('Password: ')
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
print(json.dumps({'password_hash': hashed, 'name': name, 'email': email}, indent=2))
"
```

Add the output to the USERS_JSON object, then:

```bash
cf set-env spark-meeting USERS_JSON '<updated json>'
cf restage spark-meeting
```

---

## Local dev (unchanged)

```bash
./start.sh
```

Reads users from `~/.config/sap-portal/users.json` as before.
