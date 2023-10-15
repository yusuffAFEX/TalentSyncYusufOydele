from django.shortcuts import render
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import CreateAPIView, ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView

from blog.models import Post
from blog.serializers import CreateUserSerializer, CTokenObtainPairSerializer, CreateUpdatePostSerializer


# Create your views here.

class CreateUserAPIView(CreateAPIView):
    serializer_class = CreateUserSerializer


class LoginAPIView(TokenObtainPairView):
    serializer_class = CTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.user or request.user
            print(user)

            request.user = user
            response_data = {"id": user.id, "username": user.username,
                             'access_token': serializer.validated_data.get('access')}

            return Response(data=response_data, status=status.HTTP_200_OK)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ListCreateBlogAPIView(ListCreateAPIView):
    queryset = Post.post_objects.all().order_by('-date_created')
    serializer_class = CreateUpdatePostSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    pagination_class = PageNumberPagination

    # pagination_class.page_size = 10  # Set the number of items per page

    def get(self, request, *args, **kwargs):
        page_size = request.query_params.get('page_size')

        # Check if custom page size and page number are provided in the query parameters
        if page_size:
            self.pagination_class.page_size = page_size

        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RetrieveUpdateDestroyBlogAPIView(RetrieveUpdateDestroyAPIView):
    serializer_class = CreateUpdatePostSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    lookup_field = 'slug'

    def get_queryset(self):
        if self.request.method == 'DELETE':
            return Post.objects.all()
        return Post.post_objects.all()

    def get_object(self):
        obj = super().get_object()
        if self.request.method == 'GET':
            return obj
        elif self.request.method == 'DELETE':
            if self.request.user != obj.author:
                raise PermissionDenied("You do not have permission to perform this action.")
            obj = Post.objects.filter(slug=self.kwargs.get("slug")).first()
            print(obj)
            return obj
        else:
            if self.request.user != obj.author:
                raise PermissionDenied("You do not have permission to perform this action.")
            return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        print(instance)
        instance.is_deleted = not instance.is_deleted
        instance.save()
        if instance.is_deleted:
            return Response(data="Deleted Successfully!", status=status.HTTP_204_NO_CONTENT)
        return Response(data="Retrieved Successfully!", status=status.HTTP_200_OK)
