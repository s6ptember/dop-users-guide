from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('profile/', views.profile_views, name='profile'),
    path('account-details/', views.account_details, name='account_details'),
    path('edit-account-details/', views.edit_account_details, name='edit_account_details'),
    path('update-account-details/', views.update_account_details, name='update_account_details'),
    path('logout/', views.logout_view, name='logout'),
    path('password-reset/', views.password_reset_request,
          name='password_reset_request'),
    path('password-reset/<uidb64>/<token>/', views.password_reset_confirm, 
         name='password_reset_confirm'),
]