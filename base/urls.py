from django.urls import path
from . import views
from .views import register
from rest_framework_simplejwt.views import TokenObtainPairView
from base.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static
from .views import get_photo_data
from .views import TopicViewSet, TopicCreateView, TopicListView, TopicDetailView

# from .views import  OrderCreateView
from .views import (
    ProductList,
    ProductCreate,
    ProductDetail,
    ProductUpdate,
    ProductDelete,
)
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import views as auth_views

from .views import (
    CustomPasswordResetView,
    CustomPasswordResetConfirmView,
    CustomPasswordResetDoneView,
    
)
from .views import LogoutView

from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TopicViewSet
router = DefaultRouter()
router.register(r'topics', TopicViewSet)


urlpatterns = [
    path('', include(router.urls)),

    path('api/register/', register, name='register'),
    path('login/', views.MyTokenObtainPairView.as_view()),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('reset_password/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('reset_password/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password/done/', CustomPasswordResetDoneView.as_view(), name='password_reset_done'),


    path('api/photos/', get_photo_data, name='get_photo_data'),
    
    path('products/', ProductList.as_view(), name='product-list'),
    path('products/create/', ProductCreate.as_view(), name='product-create'),
    path('products/<int:pk>/', ProductDetail.as_view(), name='product-detail'),
    path('products/<int:pk>/update/', ProductUpdate.as_view(), name='product-update'),
    path('products/<int:pk>/delete/', ProductDelete.as_view(), name='product-delete'),
    
    path('topics/add/', TopicCreateView.as_view(), name='create-topic'),
    path('topics/list/', TopicListView.as_view(), name='list-topics'),
    path('topics/detail/<int:pk>/', TopicDetailView.as_view(), name='detail-topic'),



] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

