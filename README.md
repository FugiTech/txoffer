This is the current version running on CS|Tori and Vivid|Hii among a few other bots on Rizon.
Supports outputting a packs.txt to integrate with other services.
See [nginx.example](nginx.example) for example ddl setup.

To install:

`pip install -r requirements.txt`

Other Dependancies:

`pyopenssl`

You may or may not need to install this. I know it comes with Ubuntu but isn't included in other distros.

To run:

`twistd -y txoffer.py`

To stop:

`kill $(cat twistd.pid)`

You need to configure txoffer.yaml first before using. I'll explain the most vague one in the readme. 

watch_directory 
The path where txoffer will check for packlist. Example :

watch_directory: /your/directory

For more information about the rest config, please refer to txoffer.yaml file.
