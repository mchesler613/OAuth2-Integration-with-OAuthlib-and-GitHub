"""
-------------------------------------------------------------
Author: Merilyn Chesler
Date: 4/20/2021
File: views.py
Description: This file contains the views to login to GitHub
and authenticate and return to the origin site using the Django
Requests-OAuthlib extension and other pages to test the validity
of the authentication.
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
client_id = settings.GITHUB_OAUTH_CLIENT_ID    
client_secret = settings.GITHUB_OAUTH_SECRET
github = OAuth2Session(client_id)
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'
state = ''
redirect_uri = settings.GITHUB_OAUTH_CALLBACK_URL


# Create your views here.
def github_login(request):

    #authorization_url, state = github.authorization_url(authorization_base_url)
    # https://github.com/login/oauth/authorize?response_type=code&client_id=<client_id>&state=<state>
    params = {
      'response_type': 'code',
      'client_id': client_id,
      'state': secrets.token_urlsafe(16),
    }
    req = PreparedRequest()
    req.prepare_url(authorization_base_url, params)
    print('authorization_url', req.url)
    return HttpResponseRedirect(req.url)


class CallbackView(TemplateView):
  template_name = 'welcome.html'

  def get_context_data(self, **kwargs):
    data = self.request.GET
    code = data['code']
    state = data['state']

    # returns the URL that calls this function, e.g. https://aws.djangodemo.com/auth/callback/?code=<code>&state=<state>
    response = self.request.build_absolute_uri()
    print("response = %s, code=%s, state=%s" %(response, code, state))

    # fetch the token from GitHub's API at token_url
    github.fetch_token(token_url, client_secret=client_secret,authorization_response=response)

    # returns a 'requests.get(url)' object
    get_result = github.get('https://api.github.com/user')

    json_dict  = get_result.json()

    dict = {
      'login': json_dict['login'],
      'name': json_dict['name'],
      'bio': json_dict['bio'],
      'blog': json_dict['blog'],
      'email': json_dict['email'],
      'avatar_url': json_dict['avatar_url'],
    }

    context = {'profile': json_dict}

    # create a User for this profile
    try:
      user = User.objects.get(username=json_dict['login'])
      messages.add_message(self.request, messages.DEBUG, "User %s already exists, Authenticated? %s" %(user.username, user.is_authenticated))
      print("User %s already exists, Authenticated %s" %(user.username, user.is_authenticated))
      context['user'] = user

      # remember to log the user into the system
      login(self.request,user)

    except:
      # create a Django User for this login
      user = User.objects.create_user(json_dict['login'], json_dict['email'])
      messages.add_message(self.request, messages.DEBUG, "User %s is created, Authenticated %s? %s" %(user.username, user.is_authenticated))
      print("User %s is created, Authenticated %s" %(user.username, user.is_authenticated))
      context['user'] = user

      # remember to log the user into the system
      login(self.request,user)

    return context #render(request, 'welcome.html', context)


# Class View
class WelcomeView(TemplateView):
  template_name = 'welcome.html'

  def get_context_data(self, **kwargs):
      context = super().get_context_data(**kwargs)

      # deserialize JSON
      profile = json.loads(self.kwargs['profile'])
      context['profile'] = profile
      user = json.loads(self.kwargs['user'])
      context['user'] = user

      #assert False
      return context


class PageView(TemplateView):
  template_name = 'page.html'

  def get_context_data(self, **kwargs):
      context = super().get_context_data(**kwargs)
      context['user'] = self.request.user

      #assert False
      return context


class HomeView(TemplateView):
  template_name = 'home.html'


def logout_request(request):
    logout(request)
    user = request.user
    authenticated = user.is_authenticated
    #print("logout_request: User %s Authenticated? %s", %(user.username, authenticated))
    messages.add_message(request, messages.SUCCESS, "You are successfully logged out")
    return render(request, 'home.html')
