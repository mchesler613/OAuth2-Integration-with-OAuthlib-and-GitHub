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
from requests_oauthlib import OAuth2Session
from django.views.generic.base import TemplateView
from django.contrib.auth import login, logout
from django.contrib import messages
import secrets
from requests.models import PreparedRequest
from auth import settings

# Contact GitHub to authenticate
def github_login(request):
    client_id = settings.GITHUB_OAUTH_CLIENT_ID    

    # GitHub Authorize URL with Params
    # https://github.com/login/oauth/authorize?response_type=code&client_id=<client_id>&state=<state>

    # Store state info in session
    request.session['state'] = secrets.token_urlsafe(16)

    params = {
      'response_type': 'code',
      'client_id': client_id,
      'state': request.session['state']
    }

    authorization_base_url = 'https://github.com/login/oauth/authorize'
    req = PreparedRequest()
    req.prepare_url(authorization_base_url, params)

    print('authorization_url', req.url)

    return HttpResponseRedirect(req.url)


# Client Callback from GitHub
class CallbackView(TemplateView):

  def get(self, request, *args, **kwargs):

    # Retrieve these data from the URL keyword arguments
    data = self.request.GET
    code = data['code']
    state = data['state']

    # For security purposes, verify that the
    # state information is the same as was passed
    # to github_login()
    print(state, self.request.session['state'])
    if state != self.request.session['state']:
      messages.add_message(
        self.request,
        messages.ERROR,
        "State information mismatch!"
      )
      return HttpResponseRedirect(reverse('github:welcome'))
    else:
      del self.request.session['state']

    # GitHub invokes a URL that calls us,
    # Build the URL that calls this function
    # e.g. https://aws.djangodemo.com/auth/callback/?code=<code>&state=<state>
    response = self.request.build_absolute_uri()

    print("response = %s, code=%s, state=%s" %(response, code, state))

    # fetch the access token from GitHub's API at token_url
    token_url = 'https://github.com/login/oauth/access_token'
    client_id = settings.GITHUB_OAUTH_CLIENT_ID    
    client_secret = settings.GITHUB_OAUTH_SECRET
    github = OAuth2Session(client_id)
    """
    This will work either way, pass the 'response' or just the 'code'
    github.fetch_token(token_url, client_secret=client_secret,authorization_response=response)
    or
    github.fetch_token(token_url, code=code, client_secret=client_secret)
    """
    github.fetch_token(token_url, code=code, client_secret=client_secret)

    # Retrieve GitHub profile data
    get_result = github.get('https://api.github.com/user')

    # Store profile data in JSON
    json_dict  = get_result.json()

    '''
    Fields that are of interest:
      'login' => json_dict['login'],
      'name' => json_dict['name'],
      'bio' => json_dict['bio'],
      'blog' => json_dict['blog'],
      'email' => json_dict['email'],
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
