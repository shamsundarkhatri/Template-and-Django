from django.urls import path

from . import views

urlpatterns = [
    path('register/', views.user_register, name='user_register'),
    path('login/', views.login_view, name="login"),
    path('', views.login_view, name="login_home"),
    path('list/', views.book_list, name='book_list'),
    path('view/<int:pk>', views.book_view, name='book_view'),
    path('new', views.book_create, name='book_new'),
    path('edit/<int:pk>', views.book_update, name='book_edit'),
    path('delete/<int:pk>', views.book_delete, name='book_delete'),
    path("logout/", views.LogoutView.as_view(), name="logout")

]