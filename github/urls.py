from django.urls import path
from . import views
#from django_github_oauth_views.views import GithubOAuthLoginView
from github.views import WelcomeView

app_name = 'github'

#path('callback/', GithubOAuthCallbackView.as_view())
#path('login', GithubOAuthLoginView.as_view()),
urlpatterns = [
    path('welcome/', WelcomeView.as_view(), name='welcome'),
    path('callback/', views.callback, name='callback'),
    path('ping/', views.ping, name='ping'),
    path('login/', views.login_request, name='login'),
    path('logout/', views.logout_request, name='logout'),
]
