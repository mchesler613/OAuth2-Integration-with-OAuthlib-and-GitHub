from django.urls import path
from . import views
from github.views import PageView, HomeView, CallbackView

app_name = 'github'

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('callback/', CallbackView.as_view(), name='callback'),
    path('login/', views.github_login, name='login'),
    path('logout/', views.logout_request, name='logout'),
    path('page/', PageView.as_view(), name='page'),
]
