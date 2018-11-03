[Unit]
Description=A simple proxy for Plex and IllicoWeb

[Service]
Environment=
WorkingDirectory=/home/jmg/illicoPlexTuner-1.0/
ExecStart=/home/jmg/venv_for_illicoPlexTuner/bin/python /home/jmg/illicoPlexTuner-1.0/illicoPlexTuner.py
Restart=always

[Install]
WantedBy=multi-user.target
