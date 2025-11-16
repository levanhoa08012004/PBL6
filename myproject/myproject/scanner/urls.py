from django.urls import path
from . import views
app_name = 'scanner'
urlpatterns = [
    path('', views.index, name='index'),
    path('stream/', views.index, name='stream'),
    path('dump/tables/', views.dump_tables, name='dump_tables'),
    path('dump/columns/', views.dump_columns, name='dump_columns'),
    path('dump/data/', views.dump_data, name='dump_data'),
]
from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.index, name='index'),
    path('stream/', views.index, name='stream'),
    path('dump/tables/', views.dump_tables, name='dump_tables'),
    path('dump/columns/', views.dump_columns, name='dump_columns'),
    path('dump/data/', views.dump_data, name='dump_data'),
]
