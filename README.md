# auth
THis is a sample Django app to authenticate with GitHub as a third-party OAuth2 provider.

## Deployment
This app is deployed on AWS running SSL [here](https://aws/djangodemo.com/auth).

## Dependencies
This app uses the following Python packages
+ [python-dotenv](https://pypi.org/project/python-dotenv/), to store sensitive information
+ [requests-oauthlib](https://requests-oauthlib.readthedocs.io), to integrate with third-party OAuth2 providers, such as GitHub

Other requirements include:
+ A [GitHub](http://github.com) account to login and a GitHub developer [OAuth](https://github.com/settings/developers) credentials. 
+ An SSL connection to implement a callback URL endpoint to communicate with GitHub's OAuth2 workflow.

# Why I wrote this app?
+ I wanted to understand and learn how to integrate with a third-party OAuth2 provider by writing some code myself, instead of plugging in a third-party Django app
+ With _requests-oauthlib_, I am able to write a client service that completes the [OAuth2 flow](https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow) between the client and provider, which requires these steps: 
  - request authorization from GitHub at an [authorized GitHub URL](https://github.com/login/oauth/authorize) with `client_id` and `state` information and expecting a `code` back
  - receive a `code` back from GitHub with the prior `state` information at the client's [callback URL](http://example.com/callback).
  - fetch a token from GitHub's [token URL](https://github.com/login/oauth/access_token) passing `client_secret` and `code` as arguments
  - retrieve the authorized user profile data from GitHub as `JSON` data
  - create a Django `User` account or reuse an existing authorized `User` account
  - proceed with Django app logic based on the `User` privileges
+ 
