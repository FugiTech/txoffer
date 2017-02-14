This is the current version running on CS|Kuma or Cona among a few other bots on Rizon.
Supports outputting a packs.txt to integrate with other services.
See [nginx.example](nginx.example) or [apache.example](apache.example) for example ddl setup.

To install:

`pip install -r requirements.txt`

Other Dependancies:

`pyopenssl`

You may or may not need to install this. I know it comes with Ubuntu but isn't included in other distros.

To run:

`twistd -y txoffer.py`

To stop:

`kill $(cat twistd.pid)`

You need to configure txoffer.yaml first before using.

