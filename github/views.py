from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.urls import reverse
import requests, json
from pprint import *
from django.contrib.auth.models import User
from requests_oauthlib import OAuth2Session
from django.views.generic.base import TemplateView
from django.contrib.auth import logout
from django.contrib import messages
import secrets
from requests.models import PreparedRequest



client_id = '114b2fd1c5f0e2d39848'
client_secret = '195a3f154f8986eae3661f9c3186909f44efa683'
github = OAuth2Session(client_id)
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = 'https://github.com/login/oauth/access_token'
state = ''
redirect_uri = 'https://aws.djangodemo.com/auth/callback'

# Create your views here.
def ping(request):
    '''
    x = requests.get(url,
    params = {
      "client_id": client_id,
      "state": client_state,   # randomized string
      "redirect_uri": 'http://aws.djangodemo.com/auth/callback/', 
      "scope": 'user',
      "login": 'mchesler613',
      "allow_signup": 'false',
    })

    context = {'x': x, 'headers':x.headers, 'content': x.content}
    return HttpResponse(x.content)
'''
    #authorization_url, state = github.authorization_url(authorization_base_url)
    #assert False
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


def callback(request):
  '''
  data = request.GET
  code = data['code']
  state = data['state']
  '''
  
  # returns the URL that calls this function, e.g. https://aws.djangodemo.com/auth/callback/?code=<code>&state=<state>
  response = request.build_absolute_uri()
  #print("response = %s, code=%s, state=%s" %(response, code, state))

  # fetch the token from GitHub's API at token_url
  github.fetch_token(token_url, client_secret=client_secret,authorization_response=response)
  '''
  x = requests.post(token_url,
    data = {
      "client_id": client_id,
      "client_secret": client_secret,
      "code": code,   
      "redirect_uri": response,
      "state": state,   # randomized string
    })

  print('Callback x.status_code', x.status_code)
  print('Callback x.reason', x.reason)
  print('Callback x.headers', x.headers['Content-Type'])
  print('Callback x.text', x.text)
  #print('Callback x.json()', x.json())
  '''

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
  #assert False
  #return HttpResponse("<pre>%s</pre>" %pformat(dict))
  #return HttpResponseRedirect(reverse('github:welcome', kwargs={'profile': json_string}))

  # create a User for this profile
  try:
      user = User.objects.get(username=json_dict['login'])
      messages.add_message(request, messages.SUCCESS, "User %s already exists, Authenticated? %s" %(user.username, user.is_authenticated))
      print("User %s already exists, Authenticated %s" %(user.username, user.is_authenticated))
      context['user'] = user
  except:
      user = User.objects.create_user(json_dict['login'], json_dict['email'])
      messages.add_message(request, messages.SUCCESS, "User %s is created, Authenticated %s? %s" %(user.username, user.is_authenticated))
      print("User %s is created, Authenticated %s" %(user.username, user.is_authenticated))
      context['user'] = user

  return render(request, 'welcome.html', context)

# Class View
class WelcomeView(TemplateView):
  template_name = 'welcome.html'

  def get_context_data(self, **kwargs):
      context = super().get_context_data(**kwargs)

      # deserialize JSON
      profile = json.loads(self.kwargs['profile'])
      context['profile'] = profile


      assert False
      return context

def login_request(request):
  # Check if user exists
  # Otherwise create a new user
  return render(request, 'login.html')

def logout_request(request):
    logout(request)
    messages.add_message(request, messages.SUCCESS, "You are successfully logged out")
    return render(request, 'login.html')
