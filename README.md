# maillog-crusher

It's a script that reads `maillog` and produces some statistics from Postfix, Dovecot and Amavis-new log registers.

## How it works

The script reads `maillog` in chunks of 50MB, spawning parallel processes depending on the number of CPUs the system has.

Each line is matched against several regular expressions and counted depending on the information registered.

In the end, 4 CSV files are produced concerning amavis, smtp policies, lmtp and smtp in general.

## How to run

E.g. For the October month, use:

    ./main.py -m 10
