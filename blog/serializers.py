from django.contrib.auth import authenticate
from django.contrib.auth.models import User, update_last_login
from django.utils.text import slugify
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from blog.models import Post
from blog.utils import generate_slug


class CreateUserSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    username = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'username', 'email', 'image', 'password', 'confirm_password')
        extra_kwargs = {
            "date_joined": {"read_only": True},
            "id": {"read_only": True},
        }

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        username = attrs.get('username')

        if password != confirm_password:
            raise serializers.ValidationError('Password does not matched!')

        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('User with username already exist!')

        return attrs

    def create(self, validated_data):
        # Remove confirm_password from the validated data before creating the User instance
        validated_data.pop('confirm_password', None)
        password = validated_data.pop('password', None)
        image = validated_data.pop('image', None)
        user = User.objects.create_user(**validated_data)
        user.set_password(password)  # set password for the user and hash it
        user.save()
        user.profile.image = image  # user object to profile is OnetoOne relationShip
        user.profile.save(update_fields=['image'])  # save the image field
        return user


class CTokenObtainPairSerializer(TokenObtainSerializer):
    username = serializers.CharField()
    password = serializers.CharField()
    token_class = RefreshToken

    def validate(self, attrs):

        authenticate_kwargs = {'username': attrs['username'], "password": attrs["password"], }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        try:
            print(authenticate_kwargs)
            self.user = authenticate(**authenticate_kwargs)
        except User.MultipleObjectsReturned:
            raise serializers.ValidationError("Access denied due to mistaken identity", "no_user_found")
        except Exception as e:
            raise serializers.ValidationError(f"Login error: {str(e)}", "no_user_found")

        if self.user is None:
            print(self.user)
            raise serializers.ValidationError("Access denied due to invalid credentials", "no_user_found")

        if not self.user.is_active:
            raise serializers.ValidationError("User is not active", "in_active")

        data = {}

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        update_last_login(None, self.user)

        return data


class CreateUpdatePostSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField(required=False)

    class Meta:
        model = Post
        fields = ("id", "title", "content", "image", "author", "slug", "date_created")
        extra_kwargs = {
            "date_created": {"read_only": True},
            "id": {"read_only": True},
            "author": {"read_only": True},
            "slug": {"read_only": True},
        }

    def get_author(self, obj):
        return {"first_name": obj.author.first_name, "last_name": obj.author.last_name, "email": obj.author.email,
                "username": obj.author.username}

    def create(self, validated_data):
        title = validated_data.get("title")
        slug = generate_slug(title)
        while Post.objects.filter(slug=slug).exists():
            slug = generate_slug(title, more=True)
        author = self.context["request"].user
        validated_data['slug'] = slug
        validated_data['author'] = author
        return super(CreateUpdatePostSerializer, self).create(validated_data)

    def update(self, instance, validated_data):
        title = validated_data.get("title")
        if title:
            slug = generate_slug(title)
            while Post.objects.filter(slug=slug).exclude(slug=instance.slug).exists():
                slug = generate_slug(title, more=True)
            validated_data['slug'] = slug
        author = self.context["request"].user
        validated_data['author'] = author
        return super(CreateUpdatePostSerializer, self).update(instance, validated_data)
