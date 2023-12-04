# Zero-DB Gateway
Allows to protect backend Zero-DB for Hub uploads with protection. Supports itsyou.online and threefold connect.

# Summary
Expose a small RESP (redis) protocol server supporting small amount of commands, used to provide
public access to another backend behind (tested with [0-db](https://github.com/threefoldtech/0-db)).

# Commands
Small amount of commands are available.

## AUTH
Authenticate yourself with a JWT as argument. Your JWT needs to be a valid ItsYou.Online JWT token or a token generated via the hub for threefold connect.

## EXISTS
Forward to the backend, EXISTS command, only if the user is authenticated.

## SET
Forward SET to the backend, only if the user is authenticated and if the payload
matches the key format used by the backend storage (flist backend).

This avoid anyone to push unexpected data or overwrite data with fake data.

## INFO
Returns legacy answer to determine it's a gateway.

## SELECT
Wrapper used to avoid command error, this does nothing

# Repository Owner
- [Maxime Daniel](https://github.com/maxux), Telegram: [@maxux](http://t.me/maxux)
