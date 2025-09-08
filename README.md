## Introduction

YouTube allows a channel to stream 24 hours a day but will not necessarily archive any stream that goes past 12 hours. For channels with 24/7 use cases, most have chosen to maintain continuous streams at the expense of making the content available to rewatch later on. However, the option to archive continuous streaming didn't really exist, since stopping and starting a stream every 12 hours, day after day is not really feasible for most – and even for those who can do it, it's something that's been difficult to do consistently, for lack of an automated solution up until this point.

The Automated Relay SYStem (ARSYS) represents a solution to that end. Created primarily using Anthropic's Claude AI, is a relatively lightweight script that ends and starts a new YouTube livestream every 12 hours and has been successfully tested and implemented on the [NEET INTEL YouTube channel](https://www.youtube.com/@neetintel/streams) _(beginning with the 250901A stream)_.

### Requirements
* YouTube channel with YouTube Data API v3 enabled
* OBS (ver 27.2.4 or higher) with [obs-websocket](https://github.com/obsproject/obs-websocket) extension installed
  * _(websocket is now included by default starting with OBS 28.0.0)_

### Configuration
* __Mandatory:__ a `/passwords/` folder with;
  * `client_secrets.json` downloaded via Google Cloud Console
  * `passwords.txt` updated by the user to include details of YouTube refresh token, OBS-websocket port number, and OBS-websocket password
* __Optional:__ a `/script_files/` folder with;
  * `stopstarter_description.txt`
* __Optional:__ a `/thumbnails/` folder with;
  * `thumbnail.jpg` 


__NOTE:__ I do not really 'get' GitHub and so I may be doing some of this 'the wrong way'. I hope the script can still be of value despite that. Feedback and suggestions are welcome.
