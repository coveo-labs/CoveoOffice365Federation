# This information is obtained upon registration of a new Outlook Application
client_id = '---client-id---'
client_secret = '---client-secret---'

# OAuth endpoints given in Outlook API documentation
authorization_base_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
scope = ['Group.Read.All','Calendars.Read','Contacts.Read','email','Files.Read','Mail.Read','Notes.Read','openid','People.Read','profile','Sites.Read.All','Tasks.Read','User.Read']
redirect_uri = 'https://localhost/'     # Should match Site URL

from requests_oauthlib import OAuth2Session
outlook = OAuth2Session(client_id,scope=scope,redirect_uri=redirect_uri)

# Redirect  the user owner to the OAuth provider (i.e. Outlook) using an URL with a few key OAuth parameters.
authorization_url, state = outlook.authorization_url(authorization_base_url)
print ('Please go here and authorize,', authorization_url)

# Get the authorization verifier code from the callback url
redirect_response = input('Paste the full redirect URL here:')

# Fetch the access token
token = outlook.fetch_token(token_url,client_secret=client_secret,authorization_response=redirect_response)

print (token)
# Fetch a protected resource, i.e. calendar information
o = outlook.get('https://outlook.office.com/api/v1.0/me/calendars')
print (o.content)
