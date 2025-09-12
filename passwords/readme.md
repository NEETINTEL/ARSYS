## Mandatory folder

- `client_secrets.json` must obtained by creating an OAuth client ID via [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
  - As of 250907, stopstarter.py does not have internal error handling in the case this file is not present
- `passwords.txt` must be created with the necessary information in the following format:

```yaml
# Remove the placeholder text in square brackets with real values
YOUTUBE_REFRESH_TOKEN: [OAuth refresh token]
OBS_WEBSOCKET_PORT: [e.g. 4455]
OBS_WEBSOCKET_PASSWORD: [...]
```
