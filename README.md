IllicoTuner========

A small flask app to proxy requests between Illicoweb any other IPTV software (Tvheadend, VLC, ...).

#### illicoTuner configuration
1. Create a virtual enviroment: ```$ virtualenv venv```
2. Activate the virtual enviroment: ```$ . venv/bin/activate```
3. Install the requirements: ```$ pip install -r requirements.txt```
4. Finally run the app with: ```$ python illicoTuner.py```

#### systemd service configuration
A startup script for Ubuntu can be found in illicoTuner.service (change paths in illicoTuner.service to your setup), install with:

    $ sudo cp illicoTuner.service /etc/systemd/system/illicoTuner.service
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable illicoTuner.service
    $ sudo systemctl start illicoTuner.service

#### IPTV soft

Go to your browser and 

- 127.0.0.1:5024/credentials (login info )

- 127.0.0.1:5024/M3u.get (create m3u file )

