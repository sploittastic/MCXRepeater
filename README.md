# MCXRepeater

A MeshCore repeater in Python for a Raspberry Pi with one or two radios running the MeshCore
**KISS modem** firmware (`examples/kiss_modem`). Each radio can repeat on its own frequency, onto
the other radio (cross frequency), or both. A web UI shows live stats and has an admin panel for
every setting.

## Install

```sh
git clone https://github.com/sploittastic/MCXRepeater.git
cd MCXRepeater
./installdependencies.sh                # apt packages, dialout group, creates config.json
nano config.json                        # serial ports, frequencies, web_password (gitignored: git pull never touches it)
python3 mcxrepeater.py --config config.json
```

Use the stable `/dev/serial/by-id/...` names for the serial ports (`ls -l /dev/serial/by-id/`):
`/dev/ttyACM0` and `/dev/ttyACM1` can swap or change when a modem resets. Only one program may have a
port open; on desktop Debian/Ubuntu, `sudo systemctl disable --now ModemManager` stops it probing the modems.

Open `http://<pi>:8090/` and log in with `web_password`. On first start the password is replaced
by a hash in `config.json`, and a repeater key is generated if `private_key` is empty.

To run it as a service: edit the paths and user in `mcxrepeater.service`, then

```sh
sudo cp mcxrepeater.service /etc/systemd/system/
sudo systemctl enable --now mcxrepeater
```

Updating: `git pull && sudo systemctl restart mcxrepeater`.

## How it works

- **Threads.** One reader per radio (KISS serial), one evaluator, one transmitter per radio, and the
  web server. The evaluator owns all routing state (duplicates, neighbours, filters, stats), so it
  needs no locks. Transmitters own their modem: they push the radio settings (again whenever they
  change in the UI or the modem reboots), wait out each relay's random delay, send, and wait for TxDone.
  Listen-before-talk is the modem's own KISS CSMA (`kiss_persistence`, `kiss_slottime`).
- **One identity.** Both radios share the repeater key set in the admin panel; the modems' keys
  aren't used. It's appended to flood paths and matched in direct paths and traces.
- **Duplicates.** One table of packet hashes (type + payload, as the firmware) for both radios,
  so a packet is relayed at most once per radio whichever band it arrives on. Copies of a flood
  arriving via other repeaters are dropped; a sender's retry is a new packet and goes through.
- **Floods** follow the firmware: id appended at the packet's own id size, hop limits (8 for
  adverts), loop detection, advert signatures checked, random delay of 0-5 x half the airtime
  (closer sources first).
- **Direct packets** go out on the radio their next hop was last heard on (a neighbour table built
  from zero-hop adverts and the last hop of floods). Unknown next hop: every radio the repeat
  settings allow.
- **Regions** filter scoped floods ("only these" or "all except"); unscoped floods have their own
  checkbox. Private `$` regions aren't supported.
- **Blacklist** by source key prefix (`5b*`, `5b98*`): adverts and logins carry the full key; DMs,
  requests and responses carry only one byte, so only 1-byte prefixes block those. Names can be
  blocked in the Public channel and #hashtag channels.
- **Stats** are kept in memory and saved to `data/stats.json` every minute.

## Tests

```sh
python3 -m unittest discover -s tests
```

The packet, KISS modem and relay code comes from
[pyMeshRoom](https://github.com/sploittastic/pyMeshRoom)'s virtual repeater.
