# Setup on a new host

## Configure .env and userlist.txt

Copy the `.env.template` and `pgbouncer/userlist.txt.template` files to their untemplated paths:

``` shellsession
$ cp deploy/production/.env.template deploy/production/.env 
$ cp deploy/production/pgbouncer/userlist.txt.template  deploy/production/pgbouncer/userlist.txt 
```

First, you need to generate three passwords for `.env`:

* `NOM_SECRET_KEY`
* `NOM_DB_PASSWORD`
* `CELERY_FLOWER_PASSWORD`

Next, you need to add the `NOM_DB_PASSWORD` to `userlist.txt` with an md5 prefix:

``` shellsession
echo $NOM_DB_PASSWORD | md5sum
```

Put it in like this:

``` 
"nomnom_staging" "md5<the hash>"
```

## Initial setup

... tbd
