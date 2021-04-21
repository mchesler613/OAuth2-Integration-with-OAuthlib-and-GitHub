# auth
This is a sample Django app to authenticate with [GitHub](http://github.com) as a third-party OAuth2 provider.

## Deployment
This app is deployed on AWS running SSL [here](https://aws/djangodemo.com/auth). This app contains a secret page whose secret content can only be viewed after authenticating with GitHub.

Before authentication:

![Before Authentication](https://i.postimg.cc/T3Lx89gD/2021-04-21-14-13-13.jpg "Before Authentication")

After authentication:

![After Authentication](https://i.postimg.cc/GhSRSN8R/2021-04-21-14-12-03.jpg "After Authentication")

## Dependencies
This app uses the following Python packages
+ [python-dotenv](https://pypi.org/project/python-dotenv/), to store sensitive information
+ [requests-oauthlib](https://requests-oauthlib.readthedocs.io), to integrate with third-party OAuth2 providers, such as GitHub

Other requirements include:
+ a GitHub account to login
+ a GitHub [OAuth](https://github.com/settings/developers) developer account to generic credentials such as `client id` and `client secret`. 
+ an SSL connection to implement a client callback with a URL endpoint that receives communication back from GitHub's OAuth service.

# Why I wrote this app?
+ I wanted to understand and learn how to integrate with a third-party OAuth2 provider by writing some code myself, instead of plugging in a third-party Django app
+ With _requests-oauthlib_, I am able to write a client service that completes the [OAuth2 flow](https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#web-application-flow) between the client and provider, which requires these steps: 
  - request authorization from GitHub at an [authorized GitHub URL](https://github.com/login/oauth/authorize) with `client id` and `state` information and expecting a `code` back
  - receive a `code` back from GitHub with the prior `state` information at the client's [callback URL](http://example.com/callback)
  - fetch a token from GitHub's [token URL](https://github.com/login/oauth/access_token) passing `client secret` and `code` as arguments
  - retrieve the authorized user profile data from GitHub as `JSON` data
  - create a Django `User` account or reuse an existing authorized `User` account
  - proceed with Django app logic based on `User` privileges

