===================
Pulse Specification
===================

Tracking
========

- frequency -- jobs occur as expected
  - continuous (multiple times per hour)
  - intermittent (multiple times per day)
  - daily
  - weekly
  - monthly
  - quarterly
  - yearly
  - urgent

- device
  - 11.16
  - 11.111

- job
  - sync
  - backup

and eventually

- status
  - pass/fail
  - percentage
  - text
  - tripline
- etc.


Communication
=============

Network
-------

A web server[^1] will run on `11.16` at port `3500`, and will accept `GET`
requests as a form of heart beat.  Those requests are logged, processed, and a
`204`[^2] code returned.

`GET` requests take the form of:

    $ curl -s http://192.168.11.16:3500/192.168.8.8/weekly/full_backup
              \  the pulse server     /\ reporting |   \      \ the pulse name
                                        \  machine |    \
                                                         \  daily, weekly, etc.

`POST` requests are also accepted, although at this point they are only useful
for `urgent` frequency messages.  For example:

    # set status to FIX and send messages
    $ curl http://127.0.0.1:8000/192.168.11.16/urgent/backup -d action=alert

    # set status to FIX
    $ curl http://127.0.0.1:8000/192.168.11.16/urgent/backup -d action=trip

    # remove PULSE from clues, set status to GOOD if no other warnings exist
    $ curl http://127.0.0.1:8000/192.168.11.16/urgent/backup -d action=clear

If the `action` parameter is left off, the default action is `trip` (no messages
sent, just change the status).


Web Server
----------

Besides the log file[^3] (which can be parsed by other tools), the web server
will write message files[^4].  When running in production mode, these files
must be written to the openerp server at:

    /home/openerp/sandbox/openerp/var/pulse

These files will be named using the first and third pieces of the request -- so
typically the reporting machine's IP address and job name.  The contents of these
files will repeat the IP address and job name, and will additionally have the
frequency; if `POST` is used, the fields in the `POST` request will also be in
the message file.

Continuing the first example:

    # file name: IP-192.168.8.8-full_backup.txt
    {
    "ip_address": "192.168.8.8",
    "job_name": "full_backup",
    "frequency": "weekly",
    }


OpenERP Server
--------------

An OpenERP cron job will monitor the above directory and update the appropriate
tables with the information found in the message files.  Another OpenERP cron
job will check for missing entries, and change the status of the IP device to
`FIX` if sufficient time has passed:

  - continuous jobs have grace periods of 30 minutes
  - intermittent jobs have grace periods that end at noon and midnight (status
    changes if the job has not run in the previous 12 hours)
  - daily jobs have a grace period of two physical days
  - weekly and monthly jobs have a grace period of two business days
  - quarterly and yearly jobs have a grace period of five business days

Besides the standard frequencies, there is a one-time frequency:  `urgent`.
The default action for `urgent` is called `trip` and it immediately sets the
associated device's status to `FIX`; the `alert` action will also cause text
messages and email to be sent, while the `clear` action will remove that
particular `pulse` from `clues`, possibly changing the status to `Good`.


---

[^1]: The web server is a custom server called `pulse`.  It is based on the
      `SimpleHTTPServer`, but simpler -- the `SimpleHTTPServer` is designed to
      serve files, while the `pulse` server just returns the `204`[^2] code,
      logs the request, and writes a message file.

[^2]: `204` is the `No Content` status code, but indicates success.

[^3]: By default, logging is sent to stderr; a command line parameter is available
      to set the name and location of the file, which will rotate at midnight.

[^4]: By default, message files are written in the server's startup directory;
      a command line parameter is available to set the location (and should be
      used for production).
