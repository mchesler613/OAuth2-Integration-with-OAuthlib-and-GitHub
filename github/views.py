"""
-------------------------------------------------------------
Author: Merilyn Chesler
Date: 4/20/2021
File: views.py
Description: This file contains the views to login to GitHub
and authenticate and return to the origin site using the Django
requests-oauthlib extension and other pages to test the
validity of the authentication.
https://requests-oauthlib.readthedocs.io/en/latest/examples/github.html
-------------------------------------------------------------
"""
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.urls import reverse
import requests, json
from pprint import *
from django.contrib.auth.models import User
from django.views.generic.base import TemplateView
from django.contrib.auth import login, logout
from django.contrib import messages
import secrets
from requests.models import PreparedRequest
from auth import settings
from oauthlib.oauth2 import WebApplicationClient

# Contact GitHub to authenticate
def github_login(request):

    # Setup a Web Application Client from oauthlib
    client_id = settings.GITHUB_OAUTH_CLIENT_ID    
    client = WebApplicationClient(client_id)

    # GitHub Authorize URL
    authorization_url = 'https://github.com/login/oauth/authorize'

    # Store state info in session
    request.session['state'] = secrets.token_urlsafe(16)

    """
    Generate a complete authorization url with parameters
    https://github.com/login/oauth/authorize?response_type=code&client_id=<client_id>&redirect_uri=https://example.com/callback&scope=read%3Auser&state=<state>&allow_signup=false'
    """

    url = client.prepare_request_uri(
      authorization_url, 
      redirect_uri = settings.GITHUB_OAUTH_CALLBACK_URL,
      scope = ['read:user'],
      state = request.session['state'],
      allow_signup = 'false'
    )

    print('authorization_url', url)

    # Redirect to the complete authorization url
    return HttpResponseRedirect(url)


# Client Callback from GitHub
class CallbackView(TemplateView):

  def get(self, request, *args, **kwargs):

    # Retrieve these data from the URL 
    data = self.request.GET
    code = data['code']
    state = data['state']
    print("code=%s, state=%s" %(code, state))

    # For security purposes, verify that the
    # state information is the same as was passed
    # to github_login()
    if self.request.session['state'] != state:
      messages.add_message(
        self.request,
        messages.ERROR,
        "State information mismatch!"
      )
      return HttpResponseRedirect(reverse('github:welcome'))
    else:
      del self.request.session['state']


    # fetch the access token from GitHub's API at token_url
    token_url = 'https://github.com/login/oauth/access_token'
    client_id = settings.GITHUB_OAUTH_CLIENT_ID    
    client_secret = settings.GITHUB_OAUTH_SECRET

    # Create a Web Applicantion Client from oauthlib
    client = WebApplicationClient(client_id)

    # Prepare body for request
    data = client.prepare_request_body(
      code = code,
      redirect_uri = settings.GITHUB_OAUTH_CALLBACK_URL,
      client_id = client_id,
      client_secret = client_secret
    )

    # Post a request at GitHub's token_url
    # Returns requests.Response object
    response = requests.post(token_url, data=data)

    """
    Parse the unicode content of the response object
    Returns a dictionary stored in client.token
    {
      'access_token': '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',
      'scope': ['read:user'],
      'token_type': 'bearer'
    }
    """
    client.parse_request_body_response(response.text)
    
    # Prepare an Authorization header for GET request using the 'access_token' value
    # using GitHub's official API format
    header = {'Authorization': 'token {}'.format(client.token['access_token'])}
    
    # Retrieve GitHub profile data
    # Send a GET request
    # Returns requests.Response object
    response = requests.get('https://api.github.com/user', headers=header)

    # Store profile data in JSON
    json_dict  = response.json()

    '''
    Fields that are of interest:
      'login' => json_dict['login'],
      'name' => json_dict['name'],
      'bio' => json_dict['bio'],
      'blog' => json_dict['blog'],
      'email' => json_dict['email'],    # not public data
      'avatar_url' => json_dict['avatar_url'],
    '''

    # save the user profile in a session
    self.request.session['profile'] = json_dict

    # retrieve or create a Django User for this profile
    try:
      user = User.objects.get(username=json_dict['login'])

      messages.add_message(self.request, messages.DEBUG, "User %s already exists, Authenticated? %s" %(user.username, user.is_authenticated))

      print("User %s already exists, Authenticated %s" %(user.username, user.is_authenticated))

      # remember to log the user into the system
      login(self.request,user)

    except:
      # create a Django User for this login
      user = User.objects.create_user(json_dict['login'], json_dict['email'])

      messages.add_message(self.request, messages.DEBUG, "User %s is created, Authenticated %s?" %(user.username, user.is_authenticated))

      print("User %s is created, Authenticated %s" %(user.username, user.is_authenticated))

      # remember to log the user into the system
      login(self.request,user)

    # Redirect response to hide the callback url in browser
    return HttpResponseRedirect(reverse('github:welcome'))


class WelcomeView(TemplateView):
  template_name = 'welcome.html'

class PageView(TemplateView):
  template_name = 'page.html'

class HomeView(TemplateView):
  template_name = 'home.html'

def logout_request(request):
    logout(request)
    messages.add_message(request, messages.SUCCESS, "You are successfully logged out")
    return render(request, 'home.html')
